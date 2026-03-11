# SkyHigh Scanner — Project Context for Claude

## Project Overview
**SkyHigh Scanner** is an enterprise-grade active vulnerability scanner built in Python.
It connects to live hosts (SSH, WinRM, SNMP, HTTP, SMB) to perform authenticated security assessments,
CIS benchmark checks, and CVE detection across 23+ platforms.

- **Repository**: `c:\KRISHNENDU\PROJECTS\SkyHigh-Scanner\SKYHIGH-SCANNER`
- **Branch**: `main`
- **Version**: 1.0.0
- **License**: MIT
- **Python**: 3.9+

## Architecture

### Package Structure
```
skyhigh_scanner/
├── __init__.py          # VERSION = "1.0.0"
├── __main__.py          # CLI entry point (argparse)
├── core/                # Shared infrastructure
│   ├── credential_manager.py   # Multi-protocol credential store
│   ├── cve_database.py         # SQLite CVE DB + seed import
│   ├── cve_sync.py             # NVD API 2.0 + CISA KEV sync
│   ├── discovery.py            # IP range scanning + service fingerprinting
│   ├── finding.py              # Finding dataclass
│   ├── ip_utils.py             # CIDR/range parsing
│   ├── reporting.py            # HTML/JSON report generation
│   ├── scanner_base.py         # Base scanner class
│   ├── transport.py            # SSH/WinRM/HTTP/SNMP transports
│   └── version_utils.py        # parse_ver(), version_in_range()
├── scanners/            # Platform scanner orchestrators
│   ├── auto_scanner.py         # Auto-discovery + dispatch
│   ├── cisco_scanner.py        # Cisco IOS/IOS-XE/NX-OS (SSH/SNMP)
│   ├── database_scanner.py     # Oracle DB, MySQL, MongoDB dispatcher
│   ├── linux_scanner.py        # Linux (SSH)
│   ├── middleware_scanner.py   # Java, .NET, PHP, Node.js dispatcher
│   ├── webserver_scanner.py    # Web server dispatcher (HTTP probing)
│   └── windows_scanner.py      # Windows (WinRM/SMB)
├── webservers/          # Web server check modules
│   ├── apache_checks.py        # APACHE_CVES (12), ServerTokens, dir listing
│   ├── iis_checks.py           # IIS_CVE_VERSIONS (8), headers, WebDAV
│   ├── nginx_checks.py         # NGINX_CVES (10), server_tokens, stub_status
│   ├── tomcat_checks.py        # TOMCAT_CVES (12), default creds, AJP
│   ├── weblogic_checks.py      # WEBLOGIC_CVES (15), T3/IIOP, console
│   └── websphere_checks.py     # WEBSPHERE_CVES (8), admin console, SOAP
├── middleware/          # Middleware/runtime check modules
│   ├── dotnet_checks.py        # DOTNET_EOL (7 entries), web.config
│   ├── java_checks.py          # JAVA_EOL (16 entries), Log4j, Actuator
│   ├── laravel_checks.py       # Laravel debug mode, .env exposure
│   ├── nodejs_checks.py        # NODE_EOL (10 entries), npm audit
│   ├── oracle_checks.py        # ORACLE_CVES (10), listener, audit
│   └── php_checks.py           # PHP version, php.ini checks
├── databases/           # Database check modules
│   ├── mongodb_checks.py       # Auth, bindIP, TLS, EOL (6 entries)
│   ├── mysql_checks.py         # MYSQL_EOL + MARIADB_EOL, auth, TLS
│   └── oracle_db_checks.py     # TNS, audit, password policy
├── benchmarks/          # CIS benchmark check scripts
├── cve_data/
│   ├── cpe_mappings.json       # 49 CPE strings for NVD sync
│   └── seed/                   # 21 seed JSON files (451 CVEs)
└── templates/           # HTML report templates

tests/                   # 166 pytest tests
├── conftest.py                # Shared fixtures
├── test_version_utils.py      # 20 tests
├── test_ip_utils.py           # 16 tests
├── test_finding.py            # 10 tests
├── test_credential_manager.py # 18 tests
├── test_scanner_base.py       # 17 tests
├── test_cve_database.py       # 14 tests
├── test_reporting.py          # 11 tests
├── test_seed_validation.py    # 12 tests
└── test_cli.py                # 25 tests
```

### CLI Commands
```bash
python -m skyhigh_scanner auto       -r 192.168.1.0/24    # Auto-discover + scan
python -m skyhigh_scanner windows    -r 192.168.1.0/24    # Windows hosts
python -m skyhigh_scanner linux      -r 10.0.0.0/24       # Linux hosts
python -m skyhigh_scanner cisco      -r 10.1.1.0/24       # Cisco devices
python -m skyhigh_scanner webserver  --target https://...  # Web servers
python -m skyhigh_scanner middleware -r 10.0.0.0/24        # Middleware
python -m skyhigh_scanner database   -r 10.0.0.0/24        # Databases
python -m skyhigh_scanner cve-sync   --api-key KEY         # Sync NVD API
python -m skyhigh_scanner cve-import                        # Import seed CVEs
python -m skyhigh_scanner cve-stats                         # Show CVE stats
```

### Key Patterns
- **Finding dataclass**: `rule_id, name, category, severity, file_path, line_num, line_content, description, recommendation, cwe, cve, target_type`
- **Version matching**: `version_in_range(ver, ">=2.4.0,<2.4.52")` handles comma-separated conditions
- **Embedded CVE lists**: Scanner modules have hardcoded CVE dicts for fast offline matching
- **Seed JSON schema**: `{"cve_id", "platform", "severity", "cvss_v3", "cwe", "published", "name", "description", "recommendation", "cisa_kev", "epss_score", "affected"}`
- **Seed file formats**: Importer accepts both `[...]` arrays and `{"cves": [...]}` wrappers
- **CPE_QUERIES**: Dict in `cve_sync.py` mapping platform keys to CPE 2.3 strings (49 entries)
- **Rule ID formats**: `WEB-APACHE-001`, `CISCO-AUTH-001`, `DB-MONGO-NET-001`, `MW-JAVA-VER-001`

## CVE Database
- **451 curated CVEs** across 21 seed files, 35 platforms (deduplicated in Phase 3)
- **146 CISA KEV** flagged entries
- **SQLite** backend at `skyhigh_scanner/cve_data/skyhigh_scanner.db`
- **NVD API 2.0** sync with rate limiting (6s without key, 0.6s with key)
- **Vendor feeds**: MSRC, Cisco PSIRT, Ubuntu USN, Red Hat RHSA (stubs)

### Seed Files (21 files, 451 unique CVEs)
| File | CVEs | Platforms |
|------|------|-----------|
| windows_os_cves_seed.json | 39 | windows, exchange_server |
| windows_apps_cves_seed.json | 38 | windows, exchange_server |
| linux_kernel_cves_seed.json | 27 | linux_kernel |
| linux_packages_cves_seed.json | 23 | bash, sudo, polkit, glibc, systemd, curl |
| cisco_cves_seed.json | 39 | cisco_ios, cisco_asa, cisco_ftd |
| apache_httpd_cves_seed.json | 25 | apache_httpd |
| nginx_cves_seed.json | 15 | nginx |
| iis_cves_seed.json | 15 | iis |
| tomcat_cves_seed.json | 25 | tomcat |
| weblogic_cves_seed.json | 25 | weblogic |
| websphere_cves_seed.json | 15 | websphere |
| java_ecosystem_cves_seed.json | 24 | log4j, spring_framework, spring_boot, struts, jboss_eap |
| openssl_cves_seed.json | 18 | openssl |
| openssh_cves_seed.json | 14 | openssh |
| nodejs_cves_seed.json | 20 | nodejs, expressjs |
| mongodb_cves_seed.json | 15 | mongodb |
| dotnet_cves_seed.json | 20 | dotnet, dotnet_framework, aspnet_core |
| php_cves_seed.json | 20 | php |
| mysql_cves_seed.json | 20 | mysql, mariadb |
| oracle_db_cves_seed.json | 20 | oracle_db |
| laravel_cves_seed.json | 10 | laravel |

## Development History

### v1.0.0 — Initial Release (commit `514f3ed`)
- Full scanner framework with 7 scanner types
- 10 core modules, 6 web server checks, 6 middleware checks, 3 database checks
- ~800 security rules across 21 check modules
- CVE database with NVD API 2.0 sync + CISA KEV overlay
- 62 seed CVEs across 11 JSON files
- HTML/JSON reporting with severity filtering
- Auto-discovery with service fingerprinting

### Phase 2 — CVE Coverage Expansion (commit `9844b44`)
- Expanded seed CVEs from 62 to 457 (7.4x increase)
- Restructured 11 seed files into 21 per-platform files
- Expanded embedded CVE lists in 8 scanner modules
- Updated 5 EOL dictionaries with latest version data
- Added 9 CPE mappings (49 total) for NVD sync
- Fixed importer to handle both array and dict-wrapped JSON formats
- 35 platforms covered, 146 CISA KEV entries

### Phase 3 — Tests & CI Pipeline
- **166 pytest tests** across 9 test files, all passing
- **GitHub Actions CI**: test matrix (Python 3.9-3.12), ruff lint, seed validation
- **Coverage**: finding.py 100%, reporting.py 100%, credential_manager.py 98%, ip_utils.py 97%, version_utils.py 94%, scanner_base.py 93%, cve_database.py 85%
- **Seed data fixes**: removed 6 duplicate CVEs (1 cisco, 1 linux_kernel, 4 linux_packages)
- **New files**: `requirements-dev.txt`, `pyproject.toml`, `.github/workflows/ci.yml`, 9 test files + conftest
- **Known limitation**: `parse_ver()` strips non-numeric suffixes (e.g. OpenSSL `1.0.1f` → `(1,0,1)`), so letter-based version ranges don't work — seed data should use numeric ranges

## Testing
```bash
pip install -r requirements-dev.txt    # pytest, pytest-cov, ruff, mypy
pytest                                  # Run all 166 tests
pytest --cov=skyhigh_scanner.core       # With coverage
pytest tests/test_seed_validation.py    # Seed integrity only
ruff check skyhigh_scanner/ tests/      # Lint
```

### Test Files
| File | Tests | Module |
|------|-------|--------|
| `tests/test_version_utils.py` | 20 | `parse_ver`, `version_in_range`, `compare_versions`, `is_eol` |
| `tests/test_ip_utils.py` | 16 | `expand_ip_range`, `is_private`, `reverse_dns` |
| `tests/test_finding.py` | 10 | Finding dataclass, serialisation, display |
| `tests/test_credential_manager.py` | 18 | Setters, has_*, summary, file/env loading |
| `tests/test_scanner_base.py` | 17 | `_add`, filter, summary, timing, exit code, JSON/CSV export |
| `tests/test_cve_database.py` | 14 | SQLite schema, seed import, version lookup, KEV, stats |
| `tests/test_reporting.py` | 11 | HTML generation, themes, XSS escaping |
| `tests/test_seed_validation.py` | 12 | JSON schema, CVE format, CVSS/EPSS ranges, dedup |
| `tests/test_cli.py` | 25 | All argparse subcommands, flags, defaults |

### CI Pipeline (`.github/workflows/ci.yml`)
- **test**: Matrix Python 3.9, 3.10, 3.11, 3.12 — `pytest --cov`
- **lint**: `ruff check` + `ruff format --check`
- **seed-validation**: Dedicated seed file integrity job
- Triggers: push/PR to `main`

## Conventions
- **No duplicate CVE IDs** per platform across seed files (cross-platform dupes are allowed, e.g. CVE-2023-44487)
- **Version ranges must be accurate** — they drive actual scan results
- **CISA KEV priority**: KEV > CVSS >= 9.0 > CVSS >= 7.0 > widely exploited
- **Platform keys** must match across seed files, CPE_QUERIES, cpe_mappings.json, and scanner queries
- **Commit messages**: Descriptive, multi-line, with Co-Authored-By for Claude contributions

## Dependencies
- **Required**: Python 3.9+ (stdlib only for core)
- **Optional**: `requests` (CVE sync, HTTP probing), `paramiko` (SSH), `pysnmp-lextudio` (SNMP), `pywinrm` (WinRM), `impacket` (SMB)
- **Dev/Test**: `pytest`, `pytest-cov`, `ruff`, `mypy` (see `requirements-dev.txt`)
