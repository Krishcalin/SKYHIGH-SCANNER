"""
Network discovery, port scanning, and service fingerprinting.

Discovers live hosts on a network, identifies open ports, and classifies
targets by OS type and running services for dispatching to the appropriate
scanner module.

Fingerprinting techniques:
  - TTL-based OS guessing (Windows=128, Linux=64, Cisco=255)
  - SSH banner analysis (OpenSSH → Linux, Cisco SSH → Cisco IOS)
  - HTTP Server header parsing (Apache, nginx, IIS, Tomcat, etc.)
  - Telnet banner for Cisco detection
  - Port-based heuristics (445 → Windows, 22 → Linux, etc.)
"""

from __future__ import annotations

import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .ip_utils import expand_ip_range, reverse_dns

# ── Port → service mapping ──────────────────────────────────────────
SERVICE_PORTS: dict[int, str] = {
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
    services: list[ServiceInfo] = field(default_factory=list)
    reachable: bool = True
    scan_types: list[str] = field(default_factory=list)  # recommended scanner types
    ttl: int = 0                # TTL from TCP probe (0 = unknown)
    os_confidence: str = "low"  # low | medium | high

    def has_port(self, port: int) -> bool:
        return any(s.port == port for s in self.services)

    def get_service(self, port: int) -> ServiceInfo | None:
        for s in self.services:
            if s.port == port:
                return s
        return None


def guess_os_from_ttl(ttl: int) -> str:
    """Guess OS family from TCP TTL value.

    Common defaults:
      - Linux/Unix: 64
      - Windows: 128
      - Cisco IOS / network devices: 255
    """
    if ttl <= 0:
        return ""
    if ttl <= 64:
        return "Linux"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Network Device"
    return ""


def _resolve_os(signals: list[str]) -> str:
    """Pick the best OS guess from multiple signals using majority vote."""
    if not signals:
        return ""
    # Normalise signals
    normalised = []
    for s in signals:
        s_lower = s.lower()
        if "cisco" in s_lower:
            normalised.append("Cisco IOS")
        elif "windows" in s_lower:
            normalised.append("Windows")
        elif "linux" in s_lower or "ubuntu" in s_lower or "debian" in s_lower:
            normalised.append("Linux")
        elif "network" in s_lower:
            normalised.append("Network Device")
        else:
            normalised.append(s)
    # Majority vote
    from collections import Counter
    counts = Counter(normalised)
    return counts.most_common(1)[0][0]


def _os_confidence(signals: list[str]) -> str:
    """Determine confidence level based on number of corroborating signals."""
    if not signals:
        return "low"
    unique = len(set(signals))
    if unique == 1 and len(signals) >= 2:
        return "high"
    if len(signals) >= 3:
        return "high"
    if len(signals) >= 2:
        return "medium"
    return "low"


class NetworkDiscovery:
    """Discover live hosts, scan ports, fingerprint services, classify targets."""

    def __init__(self, ip_range: str, ports: list[int] = None,
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

    def discover_hosts(self) -> list[str]:
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

    # ── TTL probing ────────────────────────────────────────────────────
    def _grab_ttl(self, ip: str) -> int:
        """Grab TTL from a TCP connection to estimate OS family.

        Connects to the first open port and reads the socket TTL option.
        Returns 0 if TTL cannot be determined.
        """
        quick_ports = [80, 443, 22, 445, 3389]
        for port in quick_ports:
            try:
                sock = socket.create_connection((ip, port), timeout=2)
                try:
                    ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                except (OSError, AttributeError):
                    ttl = 0
                sock.close()
                if ttl > 0:
                    return ttl
            except (OSError, socket.timeout):
                continue
        return 0

    # ── Phase 2: Port scanning ───────────────────────────────────────
    def _scan_port(self, ip: str, port: int) -> ServiceInfo | None:
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

    def scan_ports(self, ip: str) -> list[ServiceInfo]:
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
        """Determine OS type and recommended scanner modules.

        Uses multiple signals for classification:
          1. Port-based heuristics (445 → Windows, etc.)
          2. SSH banner analysis (Cisco SSH, OpenSSH version)
          3. Telnet banner (Cisco IOS prompt)
          4. HTTP Server header (IIS → Windows, Apache → Linux)
          5. TTL-based OS fingerprinting (128 → Windows, 64 → Linux)
        """
        scan_types: set = set()
        os_signals: list[str] = []  # collect OS hints for confidence

        # ── 1. Port-based OS detection ───────────────────────────────
        # Windows indicators
        win_ports = {445, 135, 139, 3389, 5985, 5986}
        win_port_hits = sum(1 for p in win_ports if host.has_port(p))
        if win_port_hits:
            os_signals.append("Windows")
            scan_types.add("windows")

        # ── 2. SSH banner analysis ───────────────────────────────────
        ssh_svc = host.get_service(22)
        if ssh_svc and ssh_svc.banner:
            banner_lower = ssh_svc.banner.lower()
            if "cisco" in banner_lower:
                os_signals.append("Cisco IOS")
                scan_types.add("cisco")
            elif "ubuntu" in banner_lower or "debian" in banner_lower:
                os_signals.append("Linux (Ubuntu/Debian)")
            elif "openssh" in banner_lower and "windows" not in scan_types:
                os_signals.append("Linux")
            elif "fortigate" in banner_lower or "fortios" in banner_lower:
                os_signals.append("Network Device")

        # ── 3. Telnet banner (Cisco IOS prompt) ──────────────────────
        telnet_svc = host.get_service(23)
        if telnet_svc and telnet_svc.banner:
            banner_lower = telnet_svc.banner.lower()
            if "cisco" in banner_lower or "ios" in banner_lower or "user access verification" in banner_lower:
                os_signals.append("Cisco IOS")
                scan_types.add("cisco")

        # ── 4. HTTP Server header analysis ───────────────────────────
        web_ports = [80, 443, 8080, 8443, 7001, 7002,
                     9043, 9060, 9080, 9443, 4848, 9990]
        for port in web_ports:
            svc = host.get_service(port)
            if svc:
                scan_types.add("webserver")
                banner = svc.banner.lower()
                if "apache" in banner and "tomcat" not in banner:
                    svc.service = "apache-httpd"
                    if "windows" not in scan_types:
                        os_signals.append("Linux")
                elif "nginx" in banner:
                    svc.service = "nginx"
                    if "windows" not in scan_types:
                        os_signals.append("Linux")
                elif "iis" in banner or "microsoft-httpapi" in banner:
                    svc.service = "iis"
                    os_signals.append("Windows")
                    scan_types.add("windows")
                elif "tomcat" in banner:
                    svc.service = "tomcat"
                elif "weblogic" in banner or port in (7001, 7002):
                    svc.service = "weblogic"
                elif "websphere" in banner or port in (9043, 9060, 9080):
                    svc.service = "websphere"
                elif "lighttpd" in banner or "litespeed" in banner:
                    svc.service = banner.split("/")[0].strip() if "/" in banner else banner.strip()
                elif port in (4848,):
                    svc.service = "glassfish"
                elif port in (9990,):
                    svc.service = "jboss"

        # ── 5. TTL-based OS fingerprinting ───────────────────────────
        if host.ttl > 0:
            ttl_guess = guess_os_from_ttl(host.ttl)
            if ttl_guess:
                os_signals.append(ttl_guess)

        # ── Linux fallback (SSH present, not Cisco/Windows) ──────────
        if host.has_port(22) and "cisco" not in scan_types and "windows" not in scan_types:
            os_signals.append("Linux")
            scan_types.add("linux")

        # ── Middleware detection ─────────────────────────────────────
        middleware_ports = {3000: "nodejs", 5000: "dotnet", 5001: "dotnet",
                           8080: "java", 8443: "java", 4848: "java", 9990: "java"}
        for port in middleware_ports:
            if host.has_port(port):
                scan_types.add("middleware")
                break

        # ── Database detection ───────────────────────────────────────
        db_ports = {1521: "oracle", 3306: "mysql", 27017: "mongodb",
                    5432: "postgresql", 6379: "redis"}
        for port in db_ports:
            if host.has_port(port):
                scan_types.add("database")
                break

        # ── SNMP → likely network device ─────────────────────────────
        if host.has_port(161):
            scan_types.add("cisco")

        # ── Resolve OS guess with confidence ─────────────────────────
        host.os_guess = _resolve_os(os_signals)
        host.os_confidence = _os_confidence(os_signals)
        host.target_type = host.os_guess.lower().split()[0] if host.os_guess else "unknown"
        host.scan_types = sorted(scan_types)

    # ── Full discovery pipeline ──────────────────────────────────────
    def discover(self) -> list[HostInfo]:
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

        # Phase 2 & 3: Port scan + TTL probe + enrich each host
        hosts: list[HostInfo] = []
        for ip in live_ips:
            self._log(f"Scanning ports on {ip}...")
            services = self.scan_ports(ip)
            if not services:
                continue
            ttl = self._grab_ttl(ip)
            host = HostInfo(ip=ip, services=services, ttl=ttl)
            self.enrich_services(host)
            self.classify_host(host)
            hosts.append(host)
            self._log(f"  {ip}: {len(services)} ports open, "
                      f"TTL={ttl}, OS={host.os_guess} ({host.os_confidence}), "
                      f"types={host.scan_types}")

        elapsed = round(time.time() - start, 1)
        self._log(f"Discovery complete: {len(hosts)} targets in {elapsed}s")
        return hosts
