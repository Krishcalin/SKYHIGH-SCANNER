"""
Network discovery, port scanning, and service fingerprinting.

Discovers live hosts on a network, identifies open ports, and classifies
targets by OS type and running services for dispatching to the appropriate
scanner module.
"""

from __future__ import annotations

import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Dict

from .ip_utils import expand_ip_range, reverse_dns


# ── Port → service mapping ──────────────────────────────────────────
SERVICE_PORTS: Dict[int, str] = {
    # Windows
    135:   "msrpc",
    139:   "netbios-ssn",
    445:   "microsoft-ds",
    3389:  "ms-wbt-server",
    5985:  "wsman",
    5986:  "wsmans",
    # Linux / SSH
    22:    "ssh",
    # Cisco
    23:    "telnet",
    # SNMP (UDP — we do TCP probe fallback)
    161:   "snmp",
    # Web servers
    80:    "http",
    443:   "https",
    8080:  "http-proxy",
    8443:  "https-alt",
    # Tomcat
    8009:  "ajp13",
    # WebLogic
    7001:  "weblogic",
    7002:  "weblogic-ssl",
    # WebSphere
    9043:  "websphere-admin-ssl",
    9060:  "websphere-admin",
    9080:  "websphere-http",
    9443:  "websphere-https",
    # JBoss / WildFly
    9990:  "jboss-mgmt",
    # GlassFish
    4848:  "glassfish-admin",
    # Node.js / Express
    3000:  "nodejs",
    5000:  "dotnet-kestrel",
    5001:  "dotnet-kestrel-ssl",
    # Databases
    1521:  "oracle-tns",
    1158:  "oracle-oem",
    5500:  "oracle-oem-express",
    3306:  "mysql",
    27017: "mongodb",
    # Redis / Postgres (bonus)
    6379:  "redis",
    5432:  "postgresql",
}

# Default scan port list (sorted)
DEFAULT_SCAN_PORTS = sorted(SERVICE_PORTS.keys())


@dataclass
class ServiceInfo:
    """Information about a discovered service on a port."""
    port: int
    service: str = ""
    banner: str = ""
    version: str = ""
    state: str = "open"


@dataclass
class HostInfo:
    """Information about a discovered host."""
    ip: str
    hostname: str = ""
    os_guess: str = ""
    target_type: str = ""       # windows | linux | cisco | webserver | middleware | database
    services: List[ServiceInfo] = field(default_factory=list)
    reachable: bool = True
    scan_types: List[str] = field(default_factory=list)  # recommended scanner types

    def has_port(self, port: int) -> bool:
        return any(s.port == port for s in self.services)

    def get_service(self, port: int) -> Optional[ServiceInfo]:
        for s in self.services:
            if s.port == port:
                return s
        return None


class NetworkDiscovery:
    """Discover live hosts, scan ports, fingerprint services, classify targets."""

    def __init__(self, ip_range: str, ports: List[int] = None,
                 max_hosts: int = 256, timeout: int = 3,
                 workers: int = 50, verbose: bool = False):
        self.ip_range = ip_range
        self.ports = ports or DEFAULT_SCAN_PORTS
        self.max_hosts = max_hosts
        self.timeout = timeout
        self.workers = workers
        self.verbose = verbose

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"\033[2m[discovery] {msg}\033[0m", file=sys.stderr)

    # ── Phase 1: Host discovery ──────────────────────────────────────
    def _probe_host(self, ip: str) -> bool:
        """Quick TCP connect probe on common ports to check if host is up."""
        quick_ports = [445, 22, 80, 443, 3389]
        for port in quick_ports:
            try:
                with socket.create_connection((ip, port), timeout=2):
                    return True
            except (OSError, socket.timeout):
                continue
        return False

    def discover_hosts(self) -> List[str]:
        """Return list of reachable IPs."""
        all_ips = expand_ip_range(self.ip_range)
        if len(all_ips) > self.max_hosts:
            print(f"\033[33m[!] Range contains {len(all_ips)} hosts, "
                  f"capped at --max-hosts {self.max_hosts}\033[0m",
                  file=sys.stderr)
            all_ips = all_ips[:self.max_hosts]

        self._log(f"Probing {len(all_ips)} addresses...")
        reachable = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._probe_host, ip): ip for ip in all_ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        reachable.append(ip)
                        self._log(f"  {ip} — UP")
                except Exception:
                    pass

        self._log(f"Found {len(reachable)} live hosts")
        return sorted(reachable, key=lambda x: socket.inet_aton(x))

    # ── Phase 2: Port scanning ───────────────────────────────────────
    def _scan_port(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """TCP connect scan on a single port."""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                service = SERVICE_PORTS.get(port, "unknown")
                banner = ""
                # Grab banner for certain services
                if port in (22, 23, 21, 25, 110, 143, 3306, 27017, 1521):
                    try:
                        sock.settimeout(3)
                        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                    except Exception:
                        pass
                return ServiceInfo(port=port, service=service, banner=banner)
        except (OSError, socket.timeout):
            return None

    def scan_ports(self, ip: str) -> List[ServiceInfo]:
        """Scan all configured ports on a single host."""
        services = []
        with ThreadPoolExecutor(max_workers=min(self.workers, len(self.ports))) as pool:
            futures = {pool.submit(self._scan_port, ip, p): p for p in self.ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    services.append(result)
        return sorted(services, key=lambda s: s.port)

    # ── Phase 3: Banner grabbing & enrichment ────────────────────────
    def _grab_http_banner(self, ip: str, port: int, use_ssl: bool = False) -> str:
        """Grab HTTP Server header."""
        try:
            scheme = "https" if use_ssl else "http"
            sock = socket.create_connection((ip, port), timeout=self.timeout)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
            sock.sendall(request.encode())
            response = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            return ""
        except Exception:
            return ""

    def enrich_services(self, host: HostInfo) -> None:
        """Add banner/version details to discovered services."""
        for svc in host.services:
            # HTTP banner grabbing
            if svc.port in (80, 8080, 9060, 9080, 3000, 5000, 7001, 4848, 9990):
                banner = self._grab_http_banner(host.ip, svc.port, use_ssl=False)
                if banner:
                    svc.banner = banner
            elif svc.port in (443, 8443, 9043, 9443, 5001, 7002):
                banner = self._grab_http_banner(host.ip, svc.port, use_ssl=True)
                if banner:
                    svc.banner = banner

            # Extract version from SSH banner
            if svc.port == 22 and svc.banner:
                m = re.search(r"SSH-[\d.]+-(.+)", svc.banner)
                if m:
                    svc.version = m.group(1).strip()

            # MySQL banner version
            if svc.port == 3306 and svc.banner:
                m = re.search(r"(\d+\.\d+\.\d+)", svc.banner)
                if m:
                    svc.version = m.group(1)

        # Hostname resolution
        if not host.hostname:
            host.hostname = reverse_dns(host.ip)

    # ── Phase 4: OS / target classification ──────────────────────────
    def classify_host(self, host: HostInfo) -> None:
        """Determine OS type and recommended scanner modules."""
        scan_types = set()

        # Windows indicators
        if host.has_port(445) or host.has_port(135) or host.has_port(5985):
            host.os_guess = "Windows"
            scan_types.add("windows")

        # Cisco indicators
        ssh_svc = host.get_service(22)
        if ssh_svc and ssh_svc.banner:
            banner_lower = ssh_svc.banner.lower()
            if "cisco" in banner_lower:
                host.os_guess = "Cisco IOS"
                scan_types.add("cisco")

        # Linux indicators (SSH but not Cisco, not Windows)
        if host.has_port(22) and "cisco" not in scan_types and "windows" not in scan_types:
            host.os_guess = host.os_guess or "Linux"
            scan_types.add("linux")

        # Web server detection
        web_ports = [80, 443, 8080, 8443, 7001, 7002, 9043, 9060, 9080, 9443, 4848, 9990]
        for port in web_ports:
            svc = host.get_service(port)
            if svc:
                scan_types.add("webserver")
                banner = svc.banner.lower()
                if "apache" in banner and "tomcat" not in banner:
                    svc.service = "apache-httpd"
                elif "nginx" in banner:
                    svc.service = "nginx"
                elif "iis" in banner or "microsoft" in banner:
                    svc.service = "iis"
                elif "weblogic" in banner or port in (7001, 7002):
                    svc.service = "weblogic"
                elif "websphere" in banner or port in (9043, 9060, 9080):
                    svc.service = "websphere"
                elif port in (4848,):
                    svc.service = "glassfish"
                elif port in (9990,):
                    svc.service = "jboss"

        # Middleware detection
        middleware_ports = {3000: "nodejs", 5000: "dotnet", 5001: "dotnet",
                           8080: "java", 8443: "java", 4848: "java", 9990: "java"}
        for port, mw_type in middleware_ports.items():
            if host.has_port(port):
                scan_types.add("middleware")
                break

        # Database detection
        db_ports = {1521: "oracle", 3306: "mysql", 27017: "mongodb",
                    5432: "postgresql", 6379: "redis"}
        for port, db_type in db_ports.items():
            if host.has_port(port):
                scan_types.add("database")
                break

        # SNMP
        if host.has_port(161):
            scan_types.add("cisco")  # SNMP typically on network devices

        host.target_type = host.os_guess.lower().split()[0] if host.os_guess else "unknown"
        host.scan_types = sorted(scan_types)

    # ── Full discovery pipeline ──────────────────────────────────────
    def discover(self) -> List[HostInfo]:
        """Run the complete discovery pipeline.

        Returns:
            List of HostInfo objects with services and classifications.
        """
        start = time.time()

        # Phase 1: Find live hosts
        live_ips = self.discover_hosts()
        if not live_ips:
            self._log("No live hosts found.")
            return []

        # Phase 2 & 3: Port scan + enrich each host
        hosts: List[HostInfo] = []
        for ip in live_ips:
            self._log(f"Scanning ports on {ip}...")
            services = self.scan_ports(ip)
            if not services:
                continue
            host = HostInfo(ip=ip, services=services)
            self.enrich_services(host)
            self.classify_host(host)
            hosts.append(host)
            self._log(f"  {ip}: {len(services)} ports open, type={host.scan_types}")

        elapsed = round(time.time() - start, 1)
        self._log(f"Discovery complete: {len(hosts)} targets in {elapsed}s")
        return hosts
