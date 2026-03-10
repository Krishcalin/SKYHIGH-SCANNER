"""
Transport abstractions for connecting to remote targets.

Each transport wraps an optional third-party library with graceful
degradation when the library is not installed.

Supported transports:
  - SSHTransport   — paramiko / netmiko (Linux, Cisco, web server configs)
  - WinRMTransport — pywinrm           (Windows)
  - SMBTransport   — impacket          (Windows, file shares)
  - SNMPTransport  — pysnmp-lextudio   (Cisco SNMP)
  - HTTPTransport  — requests          (web servers, APIs)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Optional

# ── Optional dependency flags ────────────────────────────────────────
HAS_PARAMIKO = False
HAS_NETMIKO = False
HAS_WINRM = False
HAS_IMPACKET = False
HAS_PYSNMP = False
HAS_REQUESTS = False

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    pass

try:
    from netmiko import ConnectHandler
    HAS_NETMIKO = True
except ImportError:
    pass

try:
    import winrm
    HAS_WINRM = True
except ImportError:
    pass

try:
    from impacket.smbconnection import SMBConnection
    HAS_IMPACKET = True
except ImportError:
    pass

try:
    from pysnmp.hlapi import (
        getCmd, nextCmd, bulkCmd, SnmpEngine, CommunityData,
        UsmUserData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity,
    )
    HAS_PYSNMP = True
except ImportError:
    pass

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    pass


def check_dependency(name: str, flag: bool, package: str) -> None:
    """Raise ImportError with install hint if a dependency is missing."""
    if not flag:
        raise ImportError(
            f"{name} requires '{package}'. Install with: pip install {package}"
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SSH Transport (paramiko)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class SSHTransport:
    """SSH connection via paramiko for command execution and file reads."""

    def __init__(self, host: str, username: str, password: str = None,
                 key_file: str = None, port: int = 22,
                 timeout: int = 30):
        check_dependency("SSHTransport", HAS_PARAMIKO, "paramiko")
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self) -> None:
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, Any] = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.key_file:
            kwargs["key_filename"] = self.key_file
        elif self.password:
            kwargs["password"] = self.password
        self._client.connect(**kwargs)

    def execute(self, command: str, timeout: int = 60) -> str:
        """Execute a command and return stdout."""
        if not self._client:
            raise RuntimeError("Not connected. Call connect() first.")
        _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        return output

    def get_file(self, remote_path: str) -> str:
        """Read a remote file and return its contents."""
        return self.execute(f"cat {remote_path}")

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.disconnect()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Netmiko Transport (for Cisco devices)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class NetmikoTransport:
    """SSH connection via netmiko for Cisco IOS/IOS-XE/NX-OS devices."""

    def __init__(self, host: str, username: str, password: str,
                 device_type: str = "cisco_ios", enable_password: str = None,
                 port: int = 22, timeout: int = 30):
        check_dependency("NetmikoTransport", HAS_NETMIKO, "netmiko")
        self.host = host
        self.username = username
        self.password = password
        self.device_type = device_type
        self.enable_password = enable_password
        self.port = port
        self.timeout = timeout
        self._conn = None

    def connect(self) -> None:
        params = {
            "device_type": self.device_type,
            "host": self.host,
            "username": self.username,
            "password": self.password,
            "port": self.port,
            "timeout": self.timeout,
        }
        if self.enable_password:
            params["secret"] = self.enable_password
        self._conn = ConnectHandler(**params)
        if self.enable_password:
            self._conn.enable()

    def execute(self, command: str) -> str:
        if not self._conn:
            raise RuntimeError("Not connected.")
        return self._conn.send_command(command)

    def get_config(self) -> str:
        return self.execute("show running-config")

    def get_version(self) -> str:
        return self.execute("show version")

    def disconnect(self) -> None:
        if self._conn:
            self._conn.disconnect()
            self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.disconnect()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# WinRM Transport
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class WinRMTransport:
    """WinRM connection for Windows targets."""

    def __init__(self, host: str, username: str, password: str,
                 domain: str = None, port: int = 5985,
                 use_ssl: bool = False, timeout: int = 60):
        check_dependency("WinRMTransport", HAS_WINRM, "pywinrm")
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self._session = None

    def connect(self) -> None:
        scheme = "https" if self.use_ssl else "http"
        endpoint = f"{scheme}://{self.host}:{self.port}/wsman"
        user = f"{self.domain}\\{self.username}" if self.domain else self.username
        self._session = winrm.Session(
            endpoint,
            auth=(user, self.password),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=self.timeout,
            operation_timeout_sec=self.timeout,
        )

    def run_ps(self, script: str) -> str:
        """Execute a PowerShell script and return stdout."""
        if not self._session:
            raise RuntimeError("Not connected.")
        result = self._session.run_ps(script)
        if result.status_code != 0:
            stderr = result.std_err.decode("utf-8", errors="replace")
            if stderr.strip():
                raise RuntimeError(f"PowerShell error: {stderr}")
        return result.std_out.decode("utf-8", errors="replace")

    def run_cmd(self, command: str) -> str:
        """Execute a cmd.exe command and return stdout."""
        if not self._session:
            raise RuntimeError("Not connected.")
        result = self._session.run_cmd(command)
        return result.std_out.decode("utf-8", errors="replace")

    def disconnect(self) -> None:
        self._session = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.disconnect()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SMB Transport (impacket)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class SMBTransport:
    """SMB connection for Windows file shares and remote registry."""

    def __init__(self, host: str, username: str, password: str,
                 domain: str = "", port: int = 445, timeout: int = 30):
        check_dependency("SMBTransport", HAS_IMPACKET, "impacket")
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.timeout = timeout
        self._conn: Optional[SMBConnection] = None

    def connect(self) -> None:
        self._conn = SMBConnection(self.host, self.host, sess_port=self.port,
                                   timeout=self.timeout)
        self._conn.login(self.username, self.password, self.domain)

    def list_shares(self) -> list[str]:
        if not self._conn:
            raise RuntimeError("Not connected.")
        return [s["shi1_netname"].rstrip("\x00") for s in self._conn.listShares()]

    def get_file(self, share: str, remote_path: str) -> bytes:
        """Download a file from an SMB share."""
        if not self._conn:
            raise RuntimeError("Not connected.")
        from io import BytesIO
        buf = BytesIO()
        self._conn.getFile(share, remote_path, buf.write)
        return buf.getvalue()

    def disconnect(self) -> None:
        if self._conn:
            self._conn.logoff()
            self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.disconnect()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SNMP Transport
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class SNMPTransport:
    """SNMP v2c/v3 transport for network devices."""

    def __init__(self, host: str, community: str = "public",
                 v3_user: str = None, v3_auth_key: str = None,
                 v3_priv_key: str = None, port: int = 161, timeout: int = 10):
        check_dependency("SNMPTransport", HAS_PYSNMP, "pysnmp-lextudio")
        self.host = host
        self.community = community
        self.v3_user = v3_user
        self.v3_auth_key = v3_auth_key
        self.v3_priv_key = v3_priv_key
        self.port = port
        self.timeout = timeout

    def _get_auth(self):
        """Return CommunityData (v2c) or UsmUserData (v3)."""
        if self.v3_user:
            return UsmUserData(self.v3_user, self.v3_auth_key, self.v3_priv_key)
        return CommunityData(self.community)

    def _get_target(self):
        return UdpTransportTarget((self.host, self.port), timeout=self.timeout)

    def get(self, *oids: str) -> dict[str, str]:
        """SNMP GET for one or more OIDs. Returns {oid: value}."""
        obj_types = [ObjectType(ObjectIdentity(o)) for o in oids]
        error_indication, error_status, _, var_binds = next(
            getCmd(SnmpEngine(), self._get_auth(), self._get_target(),
                   ContextData(), *obj_types)
        )
        if error_indication or error_status:
            return {}
        return {str(oid): str(val) for oid, val in var_binds}

    def walk(self, oid: str) -> list[tuple[str, str]]:
        """SNMP WALK (GETNEXT) on an OID subtree."""
        results = []
        for error_indication, error_status, _, var_binds in nextCmd(
            SnmpEngine(), self._get_auth(), self._get_target(),
            ContextData(), ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if error_indication or error_status:
                break
            for oid_val, val in var_binds:
                results.append((str(oid_val), str(val)))
        return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HTTP Transport
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class HTTPTransport:
    """HTTP/HTTPS transport for web server probing and REST APIs."""

    def __init__(self, base_url: str, username: str = None,
                 password: str = None, api_key: str = None,
                 verify_ssl: bool = False, timeout: int = 30):
        check_dependency("HTTPTransport", HAS_REQUESTS, "requests")
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_ssl
        if username and password:
            self._session.auth = (username, password)
        if api_key:
            self._session.headers["Authorization"] = f"Bearer {api_key}"
        # Suppress SSL warnings when verify=False
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get(self, path: str = "", **kwargs) -> requests.Response:
        url = f"{self.base_url}/{path.lstrip('/')}" if path else self.base_url
        return self._session.get(url, timeout=self.timeout, **kwargs)

    def head(self, path: str = "", **kwargs) -> requests.Response:
        url = f"{self.base_url}/{path.lstrip('/')}" if path else self.base_url
        return self._session.head(url, timeout=self.timeout, **kwargs)

    def get_headers(self, path: str = "") -> dict[str, str]:
        """Get HTTP response headers."""
        try:
            resp = self.head(path)
            return dict(resp.headers)
        except Exception:
            return {}

    def get_server_banner(self) -> str:
        """Extract the Server header value."""
        headers = self.get_headers()
        return headers.get("Server", "")

    def probe_path(self, path: str) -> tuple[int, str]:
        """Probe a URL path. Returns (status_code, body_snippet)."""
        try:
            resp = self.get(path)
            return resp.status_code, resp.text[:2000]
        except Exception:
            return 0, ""

    def get_ssl_info(self) -> dict:
        """Get SSL/TLS certificate and protocol info."""
        import ssl
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(self.base_url)
        host = parsed.hostname
        port = parsed.port or 443

        info = {"host": host, "port": port}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        info["subject"] = dict(x[0] for x in cert.get("subject", ()))
                        info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                        info["not_before"] = cert.get("notBefore", "")
                        info["not_after"] = cert.get("notAfter", "")
                        info["serial"] = cert.get("serialNumber", "")
                    info["protocol"] = ssock.version()
                    info["cipher"] = ssock.cipher()
        except Exception as e:
            info["error"] = str(e)
        return info

    def disconnect(self) -> None:
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.disconnect()
