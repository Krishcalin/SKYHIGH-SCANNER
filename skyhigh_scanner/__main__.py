"""
SkyHigh Scanner — CLI entry point.

Usage:
    python -m skyhigh_scanner auto    -r 192.168.1.0/24 [options]
    python -m skyhigh_scanner windows -r 192.168.1.0/24 [options]
    python -m skyhigh_scanner linux   -r 10.0.0.0/24    [options]
    python -m skyhigh_scanner cisco   -r 10.1.1.0/24    [options]
    python -m skyhigh_scanner webserver --target https://app.example.com [options]
    python -m skyhigh_scanner middleware -r 10.0.0.0/24  [options]
    python -m skyhigh_scanner database   -r 10.0.0.0/24  [options]
    python -m skyhigh_scanner cve-sync   [--api-key KEY] [--since 2010]
    python -m skyhigh_scanner cve-import [--seed-dir DIR]
    python -m skyhigh_scanner cve-stats
    python -m skyhigh_scanner epss-sync  [-v]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import VERSION


def _build_parser(
    plugin_dirs: list = None,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skyhigh-scanner",
        description="SkyHigh Scanner — Comprehensive Active Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Target types:
  auto        Auto-discover and scan all detected targets
  windows     Scan Windows systems (WinRM/SMB)
  linux       Scan Linux systems (SSH)
  cisco       Scan Cisco IOS/IOS-XE/NX-OS devices (SSH/SNMP)
  webserver   Scan web servers (IIS, Apache, Nginx, Tomcat, WebLogic, WebSphere)
  middleware  Scan middleware (Java, .NET, PHP, Node.js, Laravel)
  database    Scan databases (Oracle, MySQL/MariaDB, MongoDB)

CVE management:
  cve-sync    Sync CVE database from NVD API
  cve-import  Import seed CVE data for offline use
  cve-stats   Show CVE database statistics
  epss-sync   Fetch/update EPSS scores from FIRST.org API

Plugins:
  Use --plugin-dir to load custom scanner plugins from a directory.
  Place plugins in skyhigh_scanner/plugins/ for auto-discovery.
        """,
    )
    parser.add_argument("--version", action="version", version=f"SkyHigh Scanner v{VERSION}")
    parser.add_argument("--plugin-dir", action="append", default=[],
                        help="Load plugins from directory (repeatable)")

    sub = parser.add_subparsers(dest="command", help="Scanner target type")

    # ── Scan sub-commands ────────────────────────────────────────────
    scan_types = ["auto", "windows", "linux", "cisco", "webserver", "middleware", "database"]
    for scan_type in scan_types:
        sp = sub.add_parser(scan_type, help=f"Scan {scan_type} targets")
        _add_target_args(sp)
        _add_credential_args(sp)
        _add_output_args(sp)
        _add_scan_args(sp)

    # ── Plugin sub-commands ──────────────────────────────────────────
    from .core.plugin_registry import discover_plugins
    plugins = discover_plugins(extra_dirs=plugin_dirs)
    for cmd, info in sorted(plugins.items()):
        sp = sub.add_parser(cmd, help=info.help or f"Plugin: {info.name}")
        _add_target_args(sp)
        _add_credential_args(sp)
        _add_output_args(sp)
        _add_scan_args(sp)

    # ── CVE sub-commands ─────────────────────────────────────────────
    cve_sync = sub.add_parser("cve-sync", help="Sync CVE database from NVD API")
    cve_sync.add_argument("--api-key", help="NVD API key (get from nvd.nist.gov)")
    cve_sync.add_argument("--since", type=int, default=2010,
                          help="Sync CVEs published since year (default: 2010)")
    cve_sync.add_argument("--incremental", action="store_true",
                          help="Only sync CVEs modified since last sync")
    cve_sync.add_argument("--platform", nargs="+", metavar="KEY",
                          help="Only sync specific platforms (e.g. --platform apache_httpd nginx)")
    cve_sync.add_argument("-v", "--verbose", action="store_true")

    cve_import = sub.add_parser("cve-import", help="Import seed CVE data")
    cve_import.add_argument("--seed-dir", help="Path to seed JSON directory")
    cve_import.add_argument("-v", "--verbose", action="store_true")

    cve_stats = sub.add_parser("cve-stats", help="Show CVE database statistics")

    epss_sync = sub.add_parser("epss-sync", help="Fetch/update EPSS scores from FIRST.org API")
    epss_sync.add_argument("-v", "--verbose", action="store_true")

    return parser


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Target")
    group.add_argument("-r", "--range", dest="ip_range",
                       help="IP range (CIDR, start-end, comma-separated, hostname)")
    group.add_argument("-t", "--target",
                       help="Single target (IP, hostname, or URL)")
    group.add_argument("--max-hosts", type=int, default=256,
                       help="Maximum hosts to scan (default: 256)")


def _add_credential_args(parser: argparse.ArgumentParser) -> None:
    ssh = parser.add_argument_group("SSH Credentials (Linux, Cisco)")
    ssh.add_argument("--ssh-user", help="SSH username")
    ssh.add_argument("--ssh-password", help="SSH password")
    ssh.add_argument("--ssh-key", help="SSH private key file")
    ssh.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")

    win = parser.add_argument_group("Windows Credentials (WinRM)")
    win.add_argument("--win-user", help="Windows username")
    win.add_argument("--win-password", help="Windows password")
    win.add_argument("--win-domain", help="Windows domain")
    win.add_argument("--win-port", type=int, default=5985, help="WinRM port (default: 5985)")
    win.add_argument("--win-ssl", action="store_true", help="Use HTTPS for WinRM")

    snmp = parser.add_argument_group("SNMP Credentials (Cisco)")
    snmp.add_argument("--snmp-community", default="public", help="SNMP community string")
    snmp.add_argument("--snmp-v3-user", help="SNMPv3 username")
    snmp.add_argument("--snmp-v3-auth", help="SNMPv3 auth key")
    snmp.add_argument("--snmp-v3-priv", help="SNMPv3 privacy key")

    cisco = parser.add_argument_group("Cisco Credentials")
    cisco.add_argument("--enable-password", help="Cisco enable password")

    web = parser.add_argument_group("Web Credentials")
    web.add_argument("--web-user", help="Web application username")
    web.add_argument("--web-password", help="Web application password")
    web.add_argument("--web-api-key", help="Web API key")

    db = parser.add_argument_group("Database Credentials")
    db.add_argument("--db-user", help="Database username")
    db.add_argument("--db-password", help="Database password")
    db.add_argument("--db-port", type=int, help="Database port")
    db.add_argument("--db-sid", help="Oracle SID/service name")
    db.add_argument("--db-name", help="Database name")

    parser.add_argument("--credentials-file",
                        help="JSON file with credentials (see docs)")


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    out = parser.add_argument_group("Output")
    out.add_argument("--json", dest="json_file", help="Save JSON report to file")
    out.add_argument("--html", dest="html_file", help="Save HTML report to file")
    out.add_argument("--csv", dest="csv_file", help="Save CSV report to file")
    out.add_argument("--pdf", dest="pdf_file",
                     help="Save PDF report to file (requires: pip install weasyprint)")
    out.add_argument("--sarif", dest="sarif_file",
                     help="Save SARIF v2.1.0 report (GitHub Code Scanning, VS Code)")
    out.add_argument("--baseline", dest="baseline_file",
                     help="Compare against a previous JSON scan (show new/fixed findings)")


def _add_scan_args(parser: argparse.ArgumentParser) -> None:
    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("--config", dest="config_file",
                      help="Config file path (YAML/TOML) for default settings")
    scan.add_argument("--profile", default="standard",
                      choices=["quick", "standard", "full", "compliance", "cve-only"],
                      help="Scan profile (default: standard)")
    scan.add_argument("--severity", default="LOW",
                      choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                      help="Minimum severity to report (default: LOW)")
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan.add_argument("--timeout", type=int, default=30,
                      help="Connection timeout in seconds (default: 30)")
    scan.add_argument("--threads", type=int, default=10,
                      help="Max parallel connections (default: 10)")
    scan.add_argument("--no-discovery", action="store_true",
                      help="Skip host discovery (assume all hosts are up)")
    scan.add_argument("--compliance", action="store_true",
                      help="Map findings to compliance frameworks (NIST, ISO, PCI DSS, CIS)")


# ── Credential setup helper ──────────────────────────────────────────
def _setup_credentials(args) -> "CredentialManager":
    from .core.credential_manager import CredentialManager

    cm = CredentialManager()

    # CLI args take priority
    if getattr(args, "ssh_user", None):
        cm.set_ssh(args.ssh_user, args.ssh_password,
                   getattr(args, "ssh_key", None),
                   getattr(args, "ssh_port", 22))

    if getattr(args, "win_user", None):
        cm.set_winrm(args.win_user, args.win_password,
                     getattr(args, "win_domain", None),
                     getattr(args, "win_port", 5985),
                     getattr(args, "win_ssl", False))

    if getattr(args, "snmp_community", None):
        cm.set_snmp(args.snmp_community,
                    getattr(args, "snmp_v3_user", None),
                    getattr(args, "snmp_v3_auth", None),
                    getattr(args, "snmp_v3_priv", None))

    if getattr(args, "enable_password", None):
        cm.set_enable(args.enable_password)

    if getattr(args, "web_user", None) or getattr(args, "web_api_key", None):
        cm.set_web(getattr(args, "web_user", None),
                   getattr(args, "web_password", None),
                   getattr(args, "web_api_key", None))

    if getattr(args, "db_user", None):
        cm.set_db(args.db_user,
                  getattr(args, "db_password", ""),
                  getattr(args, "db_port", 0) or 0,
                  getattr(args, "db_sid", None),
                  getattr(args, "db_name", None))

    # Credential file
    cred_file = getattr(args, "credentials_file", None)
    if cred_file:
        cm.load_from_file(cred_file)

    # Environment variable fallback
    cm.load_from_env()

    return cm


# ── Scanner dispatch ─────────────────────────────────────────────────
def _run_scan(args) -> int:
    """Dispatch to the appropriate scanner module."""
    from .core.credential_manager import CredentialManager
    from .core.reporting import generate_html_report, generate_pdf_report
    from .core.scan_profiles import get_profile
    from .core.config import find_config, load_config, merge_config_into_args

    # Load config file (CLI args override config values)
    config_path = find_config(getattr(args, "config_file", None))
    if config_path:
        try:
            config = load_config(config_path)
            merge_config_into_args(config, args)
            print(f"[*] Config loaded from {config_path}", file=sys.stderr)
        except (ValueError, ImportError) as e:
            print(f"[!] Config error: {e}", file=sys.stderr)
            return 2

    if not args.ip_range and not args.target:
        print("[!] Error: Specify --range or --target", file=sys.stderr)
        return 2

    creds = _setup_credentials(args)
    target_spec = args.ip_range or args.target
    profile = get_profile(getattr(args, "profile", "standard"))

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  SkyHigh Scanner v{VERSION}", file=sys.stderr)
    print(f"  Target: {target_spec}", file=sys.stderr)
    print(f"  Mode: {args.command}", file=sys.stderr)
    print(f"  Profile: {profile.name} — {profile.description}", file=sys.stderr)
    print(f"  Credentials: {creds.summary()}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    # Import scanner modules based on command
    scanner = None
    command = args.command

    if command == "auto":
        from .scanners.auto_scanner import AutoScanner
        scanner = AutoScanner(
            target=target_spec, credentials=creds,
            max_hosts=args.max_hosts, timeout=args.timeout,
            threads=args.threads, verbose=args.verbose,
            no_discovery=args.no_discovery, profile=profile,
        )
    elif command == "windows":
        from .scanners.windows_scanner import WindowsScanner
        scanner = WindowsScanner(
            target=target_spec, credentials=creds,
            max_hosts=args.max_hosts, timeout=args.timeout,
            verbose=args.verbose, profile=profile,
        )
    elif command == "linux":
        from .scanners.linux_scanner import LinuxScanner
        scanner = LinuxScanner(
            target=target_spec, credentials=creds,
            max_hosts=args.max_hosts, timeout=args.timeout,
            verbose=args.verbose, profile=profile,
        )
    elif command == "cisco":
        from .scanners.cisco_scanner import CiscoScanner
        scanner = CiscoScanner(
            target=target_spec, credentials=creds,
            max_hosts=args.max_hosts, timeout=args.timeout,
            verbose=args.verbose, profile=profile,
        )
    elif command == "webserver":
        from .scanners.webserver_scanner import WebServerScanner
        scanner = WebServerScanner(
            target=target_spec, credentials=creds,
            timeout=args.timeout, verbose=args.verbose,
            profile=profile,
        )
    elif command == "middleware":
        from .scanners.middleware_scanner import MiddlewareScanner
        scanner = MiddlewareScanner(
            target=target_spec, credentials=creds,
            max_hosts=args.max_hosts, timeout=args.timeout,
            verbose=args.verbose, profile=profile,
        )
    elif command == "database":
        from .scanners.database_scanner import DatabaseScanner
        scanner = DatabaseScanner(
            target=target_spec, credentials=creds,
            max_hosts=args.max_hosts, timeout=args.timeout,
            verbose=args.verbose, profile=profile,
        )

    # ── Plugin dispatch ───────────────────────────────────────────
    if scanner is None:
        from .core.plugin_registry import get_plugin
        plugin = get_plugin(command)
        if plugin:
            scanner = plugin.scanner_class(
                target=target_spec, credentials=creds,
                max_hosts=getattr(args, "max_hosts", 256),
                timeout=args.timeout, verbose=args.verbose,
                profile=profile,
            )

    if scanner is None:
        print(f"[!] Unknown command: {command}", file=sys.stderr)
        return 2

    # Execute scan
    scanner.scan()

    # Apply severity filter (profile floor overrides CLI if stricter)
    severity = args.severity
    if profile.severity_floor:
        from .core.scanner_base import ScannerBase
        sev_order = ScannerBase.SEVERITY_ORDER
        if sev_order.get(profile.severity_floor, 5) < sev_order.get(severity, 5):
            severity = profile.severity_floor
    scanner.filter_severity(severity)

    # Compliance enrichment
    if getattr(args, "compliance", False):
        mapped = scanner.enrich_compliance()
        if mapped:
            print(f"[*] Compliance: {mapped} findings mapped to NIST/ISO/PCI/CIS controls",
                  file=sys.stderr)

    # Console report
    scanner.print_report()

    # File exports
    if args.json_file:
        scanner.save_json(args.json_file)
    if args.csv_file:
        scanner.save_csv(args.csv_file)
    if args.html_file:
        report_html = generate_html_report(
            scanner_name=scanner.SCANNER_NAME,
            version=scanner.SCANNER_VERSION,
            target_type=scanner.TARGET_TYPE,
            findings=scanner.findings,
            summary=scanner.summary(),
            targets_scanned=scanner.targets_scanned,
            targets_failed=scanner.targets_failed,
        )
        with open(args.html_file, "w", encoding="utf-8") as fh:
            fh.write(report_html)
        scanner._info(f"HTML report saved to {args.html_file}")
    if args.sarif_file:
        scanner.save_sarif(args.sarif_file)
    if args.pdf_file:
        try:
            pdf_bytes = generate_pdf_report(
                scanner_name=scanner.SCANNER_NAME,
                version=scanner.SCANNER_VERSION,
                target_type=scanner.TARGET_TYPE,
                findings=scanner.findings,
                summary=scanner.summary(),
                targets_scanned=scanner.targets_scanned,
                targets_failed=scanner.targets_failed,
            )
            with open(args.pdf_file, "wb") as fh:
                fh.write(pdf_bytes)
            scanner._info(f"PDF report saved to {args.pdf_file}")
        except RuntimeError as exc:
            scanner._error(str(exc))

    # Baseline comparison
    baseline_file = getattr(args, "baseline_file", None)
    if baseline_file:
        from .core.baseline import load_baseline, compute_diff, print_diff_report
        try:
            baseline = load_baseline(baseline_file)
            diff = compute_diff(scanner.findings, baseline)
            print_diff_report(diff)
        except (FileNotFoundError, ValueError) as e:
            print(f"[!] Baseline error: {e}", file=sys.stderr)

    return scanner.exit_code()


# ── CVE sub-commands ─────────────────────────────────────────────────
def _run_cve_sync(args) -> int:
    from .core.cve_database import CVEDatabase
    from .core.cve_sync import CVESync

    platforms = getattr(args, "platform", None)

    with CVEDatabase() as db:
        sync = CVESync(db, api_key=args.api_key, verbose=args.verbose)
        if args.incremental:
            last = sync.get_last_sync()
            if last:
                print(f"[*] Incremental sync — fetching changes since {last[:19]}", file=sys.stderr)
            results = sync.sync_incremental(platforms=platforms)
        else:
            results = sync.sync_all(since_year=args.since, platforms=platforms)

    if not results:
        return 1

    total = sum(v for k, v in results.items() if not k.startswith("_"))
    internal_keys = sum(1 for k in results if k.startswith("_"))
    mode = "Incremental sync" if args.incremental else "Sync"
    print(f"\n[*] {mode} complete: {total} CVEs across {len(results) - internal_keys} platforms")
    kev = results.get("_cisa_kev_flagged", 0)
    if kev:
        print(f"[*] CISA KEV: {kev} actively exploited CVEs flagged")
    epss = results.get("_epss_enriched", 0)
    if epss:
        print(f"[*] EPSS: {epss} CVEs enriched with exploit probability scores")
    return 0


def _run_cve_import(args) -> int:
    from .core.cve_database import CVEDatabase

    with CVEDatabase() as db:
        count = db.import_seed(args.seed_dir)

    print(f"[*] Imported {count} CVEs from seed files")
    return 0


def _run_epss_sync(args) -> int:
    from .core.cve_database import CVEDatabase
    from .core.cve_sync import CVESync

    with CVEDatabase() as db:
        sync = CVESync(db, verbose=args.verbose)
        count = sync.sync_epss()

    print(f"\n[*] EPSS sync complete: {count} CVEs enriched with exploit probability scores")
    return 0


def _run_cve_stats(_args) -> int:
    from .core.cve_database import CVEDatabase

    db = CVEDatabase()
    try:
        db.open()
        stats = db.stats()
    except Exception as e:
        print(f"[!] No CVE database found. Run 'cve-sync' or 'cve-import' first.\n    {e}",
              file=sys.stderr)
        return 1
    finally:
        db.close()

    print(f"\n{'='*50}")
    print(f"  SkyHigh Scanner - CVE Database Statistics")
    print(f"{'='*50}")
    print(f"  Total CVEs      : {stats.get('total', 0)}")
    print(f"  CISA KEV        : {stats.get('kev', 0)}")
    print(f"  EPSS Populated  : {stats.get('epss_populated', 0)}")
    print(f"  EPSS Avg Score  : {stats.get('epss_avg', 0.0):.2%}")
    print(f"  EPSS High Risk  : {stats.get('epss_high_risk', 0)} (score >= 50%)")

    # Sync metadata
    sync_meta = stats.get("sync_metadata", {})
    last_full = sync_meta.get("last_full_sync")
    last_epss = sync_meta.get("last_epss_sync")
    if last_full or last_epss:
        print(f"{'-'*50}")
        if last_full:
            print(f"  Last CVE Sync   : {last_full[:19]}")
        if last_epss:
            print(f"  Last EPSS Sync  : {last_epss[:19]}")

    print(f"{'-'*50}")
    for platform, count in sorted(stats.get("platforms", {}).items()):
        print(f"  {platform:30s}: {count}")
    print(f"{'='*50}\n")
    return 0


# ── Main ─────────────────────────────────────────────────────────────
def main() -> int:
    # Pre-parse --plugin-dir before full parse so plugins can register
    # their subcommands in the parser.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--plugin-dir", action="append", default=[])
    pre_args, _ = pre.parse_known_args()

    parser = _build_parser(plugin_dirs=pre_args.plugin_dir)
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "cve-sync":
        return _run_cve_sync(args)
    elif args.command == "cve-import":
        return _run_cve_import(args)
    elif args.command == "cve-stats":
        return _run_cve_stats(args)
    elif args.command == "epss-sync":
        return _run_epss_sync(args)
    else:
        return _run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
