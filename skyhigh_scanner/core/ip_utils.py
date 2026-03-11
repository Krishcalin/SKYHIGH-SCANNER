"""
IP address and range utilities.

Supports multiple input formats:
  - CIDR:       192.168.1.0/24
  - Range:      192.168.1.1-192.168.1.50
  - Single:     10.0.0.5
  - Comma-sep:  10.0.0.1,10.0.0.2,10.0.0.3
  - Mixed:      192.168.1.0/24,10.0.0.5,172.16.0.1-172.16.0.10
  - Hostname:   server1.example.com
"""

from __future__ import annotations

import ipaddress
import socket


def expand_ip_range(spec: str) -> list[str]:
    """Expand an IP range specification into a list of individual IP strings.

    Supports CIDR, start-end ranges, single IPs, hostnames, and
    comma-separated combinations of all the above.

    Args:
        spec: IP range specification string.

    Returns:
        Deduplicated, sorted list of IP address strings.
    """
    results: set[str] = set()

    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue

        # CIDR notation (e.g. 192.168.1.0/24)
        if "/" in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                for addr in network.hosts():
                    results.add(str(addr))
            except ValueError:
                pass  # skip invalid
            continue

        # Range notation (e.g. 192.168.1.1-192.168.1.50  or  192.168.1.1-50)
        if "-" in part:
            try:
                left, right = part.split("-", 1)
                left = left.strip()
                right = right.strip()

                start_ip = ipaddress.ip_address(left)

                # Short form: 192.168.1.1-50
                if "." not in right and right.isdigit():
                    prefix = ".".join(left.split(".")[:-1])
                    end_ip = ipaddress.ip_address(f"{prefix}.{right}")
                else:
                    end_ip = ipaddress.ip_address(right)

                if int(start_ip) > int(end_ip):
                    start_ip, end_ip = end_ip, start_ip

                current = int(start_ip)
                while current <= int(end_ip):
                    results.add(str(ipaddress.ip_address(current)))
                    current += 1
            except ValueError:
                pass
            continue

        # Single IP
        try:
            ipaddress.ip_address(part)
            results.add(part)
            continue
        except ValueError:
            pass

        # Hostname — resolve to IP
        try:
            resolved = socket.gethostbyname(part)
            results.add(resolved)
        except socket.gaierror:
            pass  # unresolvable hostname

    return sorted(results, key=lambda ip: ipaddress.ip_address(ip))


def is_private(ip: str) -> bool:
    """Check if an IP address is in a private/RFC1918 range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def reverse_dns(ip: str) -> str:
    """Attempt reverse DNS lookup. Returns hostname or empty string."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""
