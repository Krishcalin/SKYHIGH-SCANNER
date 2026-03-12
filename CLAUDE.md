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
│   ├── reporting.py            # HTML/PDF report generation + Chart.js dashboard
│   ├── scanner_base.py         # Base scanner class
│   ├── transport.py            # SSH/WinRM/HTTP/SNMP transports
│   ├── version_utils.py        # parse_ver(), version_in_range()
│   ├── compliance.py           # CWE/category → NIST/ISO/PCI/CIS mapping
│   ├── config.py               # YAML/TOML config file loader
│   ├── baseline.py             # Diff scanning (NEW/FIXED/UNCHANGED)
│   ├── scan_profiles.py        # quick/standard/full/compliance/cve-only profiles
│   └── plugin_registry.py      # @scanner_plugin decorator + auto-discovery
├── scanners/            # Platform scanner orchestrators
│   ├── auto_scanner.py         # Auto-discovery + parallel dispatch (v1.2.0)
│   ├── cisco_scanner.py        # Cisco IOS/IOS-XE/NX-OS (SSH/SNMP)
│   ├── database_scanner.py     # Oracle DB, MySQL, MongoDB dispatcher
│   ├── linux_scanner.py        # Linux (SSH)
│   ├── middleware_scanner.py   # Java, .NET, PHP, Node.js dispatcher
│   ├── webserver_scanner.py    # Web server dispatcher (HTTP probing)
│   ├── dast_scanner.py         # DAST orchestrator (crawl → check dispatch)
│   └── windows_scanner.py      # Windows (WinRM/SMB)
├── dast/               # DAST engine
│   ├── __init__.py             # Package exports (DastConfig, ScopePolicy)
│   ├── config.py               # ScopePolicy, RateLimiter, RequestCounter, CircuitBreaker, DastConfig
│   ├── http_client.py          # DastHTTPClient (scope + rate + retries + circuit breaker + evidence)
│   ├── crawler.py              # WebCrawler, SiteMap, _LinkFormParser, JS extraction
│   ├── discovery.py            # URL discovery (robots.txt, sitemap.xml, common paths)
│   ├── waf_detect.py           # WAF fingerprinting utility (8 WAFs)
│   └── checks/                 # Check modules (82 DAST rules across 11 categories)
│       ├── __init__.py         # Check module interface
│       ├── injection.py        # SQL/cmd/SSTI/CRLF/host/NoSQL/XPath/blind/LDAP/HPP (12 rules)
│       ├── xss.py              # Reflected/DOM/header/error/stored XSS (7 rules)
│       ├── auth_session.py     # Auth & session checks
│       ├── access_control.py   # Access control checks
│       ├── api_security.py     # API security + GraphQL DoS (11 rules)
│       ├── file_inclusion.py   # LFI/RFI checks
│       ├── info_disclosure.py  # Info disclosure checks
│       ├── config_misconfig.py # Configuration checks
│       ├── ssrf.py             # SSRF detection (4 rules)
│       ├── xxe.py              # XXE injection (4 rules)
│       └── jwt_security.py     # JWT token analysis (5 rules)
├── webservers/          # Web server check modules
│   ├── apache_checks.py        # APACHE_CVES (13), ServerTokens, dir listing
│   ├── iis_checks.py           # IIS_CVE_VERSIONS (10), headers, WebDAV
│   ├── nginx_checks.py         # NGINX_CVES (10), server_tokens, stub_status
│   ├── tomcat_checks.py        # TOMCAT_CVES (13), default creds, AJP
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
│   ├── cpe_mappings.json       # 47 CPE strings for NVD sync
│   └── seed/                   # 21 seed JSON files (510 CVEs, 159 CISA KEV)
├── plugins/             # Auto-discovered plugin directory
│   └── example_scanner.py      # Example plugin template
└── templates/           # HTML report templates

tests/                   # 999 pytest tests (all passing, 0 skipped)
├── conftest.py                # Shared fixtures
├── test_version_utils.py      # 20 tests
├── test_ip_utils.py           # 16 tests
├── test_finding.py            # 10 tests
├── test_credential_manager.py # 18 tests
├── test_scanner_base.py       # 17 tests
├── test_cve_database.py       # 14 tests
├── test_reporting.py          # 49 tests (HTML/PDF, charts, XSS escaping)
├── test_seed_validation.py    # 12 tests
├── test_epss.py               # 27 tests (EPSS integration)
├── test_cli.py                # 25 tests
├── test_incremental_sync.py   # 23 tests (incremental CVE sync)
├── test_compliance.py         # 53 tests (compliance framework mapping)
├── test_sarif.py              # 30 tests (SARIF v2.1.0 export)
├── test_plugins.py            # 26 tests (plugin architecture)
├── test_scan_profiles.py      # 36 tests (scan profiles & category gating)
├── test_auto_scanner.py       # 67 tests (auto scanner & parallel dispatch)
├── test_config.py             # 30 tests (config file loading)
├── test_baseline.py           # 20 tests (baseline diff scanning)
├── test_dast_config.py        # 41 tests (DAST config, scope, rate limiter, circuit breaker)
├── test_dast_http_client.py   # 22 tests (HTTP client, auth, evidence)
├── test_dast_crawler.py       # 52 tests (crawler, HTML parser, JS extraction, advanced crawling)
├── test_dast_discovery.py     # 26 tests (URL discovery, robots.txt, sitemap.xml)
├── test_dast_evidence.py      # 43 tests (evidence capture in check modules)
├── test_dast_perf_safety.py   # 39 tests (circuit breaker, retry, adaptive rate limiter)
├── test_dast_scanner.py       # 22 tests (DAST scanner orchestrator, concurrent dispatch, CLI)
├── test_dast_injection.py     # 21 tests (SQL, cmd, SSTI, CRLF, LDAP, HPP injection checks)
├── test_dast_xss.py           # 20 tests (reflected, DOM, header, error, stored XSS)
├── test_dast_api_security.py  # 18 tests (API security + GraphQL DoS)
├── test_dast_jwt_security.py  # 10 tests (JWT alg confusion, sig strip, expired, tampering, weak secret)
├── test_dast_waf_detect.py    # 6 tests (WAF fingerprinting)
├── test_dast_ssrf.py          # SSRF detection tests
├── test_dast_xxe.py           # XXE injection tests
├── test_dast_injection_blind.py  # Blind SQL/command injection tests
└── test_dast_report_sections.py  # DAST report section tests
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
python -m skyhigh_scanner dast       --target https://...  # DAST web app scanning
python -m skyhigh_scanner cve-sync   --api-key KEY         # Full sync NVD API + EPSS + KEV
python -m skyhigh_scanner cve-sync   --incremental          # Delta sync (changes since last sync)
python -m skyhigh_scanner cve-sync   --platform nginx tomcat # Sync specific platforms only
python -m skyhigh_scanner cve-import                        # Import seed CVEs
python -m skyhigh_scanner cve-stats                         # Show CVE + EPSS + sync stats
python -m skyhigh_scanner epss-sync                         # Update EPSS scores from FIRST.org
```

### Key Patterns
- **Finding dataclass**: `rule_id, name, category, severity, file_path, line_num, line_content, description, recommendation, cwe, cve, target_type, cvss, cisa_kev, epss, compliance`
- **Version matching**: `version_in_range(ver, ">=2.4.0,<2.4.52")` handles comma-separated conditions
- **Embedded CVE lists**: Scanner modules have hardcoded CVE dicts for fast offline matching
- **Seed JSON schema**: `{"cve_id", "platform", "severity", "cvss_v3", "cwe", "published", "name", "description", "recommendation", "cisa_kev", "epss_score", "affected"}`
- **Seed file formats**: Importer accepts both `[...]` arrays and `{"cves": [...]}` wrappers
- **CPE_QUERIES**: Dict in `cve_sync.py` mapping platform keys to CPE 2.3 strings (49 entries)
- **Rule ID formats**: `WEB-APACHE-001`, `CISCO-AUTH-001`, `DB-MONGO-NET-001`, `MW-JAVA-VER-001`, `DAST-INJ-001`
- **DAST safety controls**: ScopePolicy (mandatory host allowlist), RateLimiter (adaptive token bucket), RequestCounter (hard cap), CircuitBreaker (threshold/reset), warning banner
- **DAST check dispatch**: 11 categories via ThreadPoolExecutor(4 workers) — injection, xss, auth_session, access_control, api_security, file_inclusion, info_disclosure, config_misconfig, ssrf, xxe, jwt
- **DAST rule count**: 82 rules across 11 check modules (DAST-INJ-001–012, DAST-XSS-001–007, DAST-API-001–011, DAST-SSRF-001–004, DAST-XXE-001–004, DAST-JWT-001–005, plus auth/access/file/info/config checks)
- **DAST WAF detection**: Pre-scan fingerprinting for 8 WAFs (Cloudflare, AWS WAF, Imperva, Akamai, ModSecurity, F5, Sucuri, Barracuda) via header/cookie/block-probe analysis
- **DAST auth modes**: none, bearer, cookie, basic, form — configured via DastConfig
- **DAST passive mode**: Skips injection, xss, file_inclusion, access_control, jwt checks
- **DAST retries**: Exponential backoff on 5xx/ConnectionError/Timeout, configurable max_retries
- **DAST evidence**: RequestEvidence dataclass with method/url/status/headers/body/response_time, attached to findings
- **DAST perf metrics**: avg_response_time_ms and p95_response_time_ms tracked and included in summary
- **Compliance mapping**: `compliance.py` maps CWE IDs + categories to NIST 800-53, ISO 27001, PCI DSS 4.0, CIS Controls v8
- **`--compliance` flag**: Enriches findings with framework controls; shown in console, HTML, JSON, CSV
- **SARIF v2.1.0 export**: `--sarif FILE` — GitHub Code Scanning / VS Code compatible
- **Plugin architecture**: `@scanner_plugin` decorator, auto-discovery from `plugins/` dir + `--plugin-dir` + entry-points
- **Scan profiles**: `--profile quick|standard|full|compliance|cve-only` — category-based gating
- **Parallel scanning**: Auto Scanner v1.2.0 uses ThreadPoolExecutor for multi-host dispatch
- **Config files**: `--config FILE` or auto-discover `skyhigh-scanner.yml/.yaml/.toml`, CLI always overrides
- **Baseline diff**: `--baseline FILE` compares current vs previous JSON scan (NEW/FIXED/UNCHANGED)
- **PDF export**: `--pdf FILE` via optional weasyprint, print-optimised white-bg layout

## CVE Database
- **510 curated CVEs** across 21 seed files, 35 platforms (deduplicated in Phase 3)
- **159 CISA KEV** flagged entries
- **SQLite** backend at `skyhigh_scanner/cve_data/skyhigh_scanner.db`
- **NVD API 2.0** sync with rate limiting (6s without key, 0.6s with key)
- **EPSS scores** from FIRST.org API — exploit probability (0-100%) for each CVE
- **Vendor feeds**: MSRC, Cisco PSIRT, Ubuntu USN, Red Hat RHSA (stubs)

### Seed Files (21 files, 510 unique CVEs)
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

### Phase 4 — EPSS Integration
- **EPSS data flow**: DB → Finding → Console/HTML/JSON/CSV (was broken, now fully connected)
- **FIRST.org API**: `CVESync.sync_epss()` fetches scores in batches of 100 CVEs
- **`epss-sync` CLI command**: Standalone EPSS enrichment for existing CVE databases
- **HTML report**: Color-coded EPSS badges (red >=50%, orange >=10%, green <10%) + dashboard card
- **Console report**: EPSS percentage shown per finding + high-risk summary count
- **CSV export**: `epss` column added to output
- **NVD sync preservation**: `cve-sync` no longer overwrites existing EPSS/KEV data with NULL
- **`enrich_epss()`**: Bulk update method on CVEDatabase
- **`flag_epss_findings()`**: Post-scan enrichment for findings from non-DB sources
- **27 new tests** in `test_epss.py` covering all integration points
- **Stats**: `cve-stats` now shows EPSS population count, average score, high-risk count

### Phase 5 — Incremental CVE Sync
- **`sync_incremental()`**: Uses NVD `lastModStartDate`/`lastModEndDate` for delta updates
- **120-day windowing**: Automatically splits wide date ranges into NVD-compliant windows
- **`--platform` filter**: `cve-sync --platform nginx tomcat` syncs only specified platforms
- **Per-platform timestamps**: Tracks `last_sync_{platform}` in `sync_metadata` table
- **`sync_platform_modified()`**: New method for date-range-based queries
- **`get_last_sync()` / `get_platform_last_sync()`**: Metadata accessors
- **`cve-stats` enhanced**: Shows last CVE sync and EPSS sync timestamps
- **23 new tests** in `test_incremental_sync.py`

### Phase 6 — Compliance Framework Mapping
- **`compliance.py`**: Maps CWE IDs + categories to 4 frameworks (NIST 800-53 Rev 5, ISO 27001:2022, PCI DSS v4.0, CIS Controls v8)
- **~60 CWE mappings**: Covering OWASP Top 10, authentication, crypto, patching, logging, memory, network
- **~30 category fallback mappings**: For findings without CWEs (SSH, SNMP, NTP, firewall, etc.)
- **Finding enrichment**: `enrich_compliance()` on ScannerBase, `enrich_finding()` / `enrich_findings()` functions
- **`--compliance` CLI flag**: Opt-in enrichment during scans
- **Console report**: Shows compliance controls per finding + framework summary with top controls
- **HTML report**: Compliance tags on findings, dashboard card, framework summary table section
- **CSV export**: Flattened `nist_800_53`, `iso_27001`, `pci_dss`, `cis_controls` columns
- **JSON export**: Nested `compliance` dict in each finding
- **`filter_by_framework()`**: Filter findings by framework or specific controls
- **`compliance_summary()`**: Aggregate control counts across all findings
- **53 new tests** in `test_compliance.py`

### Phase 7 — SARIF v2.1.0 Export
- **`save_sarif()`** on ScannerBase: GitHub Code Scanning / VS Code compatible
- Includes fingerprints, CWE tags, CVSS security-severity, severity→level mapping
- **`--sarif FILE`** CLI flag on all scan commands
- **30 new tests** in `test_sarif.py`

### Phase 8 — Plugin Architecture
- **`@scanner_plugin` decorator** with name, version, description metadata
- **Auto-discovery** from `plugins/` dir + `--plugin-dir` + entry-points
- **Validates** ScannerBase inheritance, rejects builtin command conflicts
- **`PluginInfo` dataclass** with registration metadata
- **26 new tests** in `test_plugins.py`

### Phase 9 — Scan Profiles
- **5 profiles**: quick (HIGH+ only), standard, full, compliance, cve-only
- **Category-based gating** via `_check_enabled()` in ScannerBase
- **Severity floor override**: quick profile raises minimum to HIGH
- **Profile info** in summary banner and JSON/HTML output
- **36 new tests** in `test_scan_profiles.py`

### Phase 10 — Auto Scanner v1.2.0 (Parallel Dispatch)
- **ThreadPoolExecutor** for multi-host parallel scanning
- **`_create_scanner()` / `_dispatch_one()`** for thread-safe dispatch
- **`threading.Lock`** protects shared findings list
- **Sequential fallback** when `threads <= 1` or single dispatch
- **Progress reporting** and credential-missing warnings
- **67 new tests** in `test_auto_scanner.py`

### Phase 11 — Config File Support
- **`--config FILE`** or auto-discover `skyhigh-scanner.yml/.yaml/.toml`
- **Built-in YAML parser** (no PyYAML dependency needed)
- **Key validation** against `_VALID_KEYS` frozenset
- **CLI always overrides** config file values
- **30 new tests** in `test_config.py`

### Phase 12 — Baseline / Diff Scanning
- **`--baseline FILE`** compares current scan vs previous JSON export
- **Finding identity**: `(rule_id, file_path, line_content)` composite key
- **Diff output**: NEW, FIXED, UNCHANGED with colored stderr report
- **20 new tests** in `test_baseline.py`

### Phase 13 — CVE Seed Expansion & Test Fixes
- Expanded seed CVEs from 457 to 510 (8 seed files updated)
- Fixed 26 skipped tests: installed `requests`, mocked `weasyprint`
- **521 tests all passing, 0 skipped**

### Phase 14 — DAST Module Foundation (commit `fd78c88`)
- **New `dast/` package**: ScopePolicy, RateLimiter, RequestCounter, DastConfig, DastHTTPClient, WebCrawler, SiteMap
- **`scanners/dast_scanner.py`**: DastScanner(ScannerBase) orchestrator with crawl → check dispatch flow
- **Safety controls**: Mandatory scope enforcement, token-bucket rate limiter, request hard cap, pre-scan warning banner
- **WebCrawler**: BFS crawl with depth/page limits, form/link/API/JS endpoint discovery
- **DastHTTPClient**: Scope-enforced requests.Session wrapper with auth modes (none/bearer/cookie/basic/form)
- **CLI integration**: `dast` subcommand with 12 flags (scope, rate-limit, auth, passive-only, etc.)
- **Scan profiles**: Added 9 DAST categories to CATEGORIES frozenset
- **Reporting**: Added DAST red theme to reporting.py
- **Plugin registry**: Added `dast` to BUILTIN_COMMANDS
- **95 new tests** across 4 test files (29 + 22 + 26 + 18)
- **616 tests all passing, 0 skipped**

### DAST Phase 4 — Evidence Capture
- **Evidence field** on Finding: `evidence: list[dict] | None` for DAST proof-of-concept data
- **HTML evidence section**: Request/response details rendered in DAST findings
- **All 8 check modules** updated to capture evidence on findings
- **43 new tests** in `test_dast_evidence.py`

### DAST Phase 5 — Advanced Crawling
- **`discovery.py`**: URL discovery via robots.txt, sitemap.xml, and common path probing
- **WebCrawler enhancements**: Form detection, JavaScript link extraction, depth tracking, max_pages support
- **SiteMap extensions**: `forms` and `parameters` collections for discovered form inputs
- **26 new tests** in `test_dast_discovery.py` + 26 new tests in `test_dast_crawler.py`

### DAST Phase 6 — Performance & Safety (commit `3d40256`)
- **CircuitBreaker**: closed → open → half-open pattern, threshold=10, reset_timeout=60s, thread-safe
- **Adaptive rate limiting**: `RateLimiter.adapt()` halves rate on 429/5xx, recovers by 1.5x after 30s backoff
- **Retry with exponential backoff**: `min(2^attempt, 30)` seconds, retries on 5xx/ConnectionError/Timeout only
- **Connection pooling**: `HTTPAdapter(pool_connections=20, pool_maxsize=20)` on http/https
- **Response time tracking**: `avg_response_time_ms` and `p95_response_time_ms` properties on DastHTTPClient
- **Concurrent check dispatch**: `ThreadPoolExecutor(max_workers=4)` with `as_completed()` for 8 check modules
- **6 new CLI args**: `--dast-request-timeout`, `--dast-verify-ssl`, `--dast-max-pages`, `--dast-user-agent`, `--dast-proxy`, `--dast-retries`
- **5 new DastConfig fields**: `verify_ssl`, `user_agent`, `proxy`, `max_pages`, `max_retries`
- **Error logging**: All 8 check modules improved with rule_id context in exception handlers
- **Performance metrics**: `summary()["dast_metadata"]["performance"]` includes avg/p95 response times
- **39 new tests** in `test_dast_perf_safety.py` + 12 new tests in `test_dast_config.py` + 4 new in `test_dast_scanner.py`
- **913 tests all passing, 0 skipped**

### DAST Phase 7 — High-Priority Checks (commit `aeded82`)
- **SSRF detection** (`checks/ssrf.py`): 4 rules (DAST-SSRF-001 to 004) — URL param, form input, blind callback, header injection
- **XXE injection** (`checks/xxe.py`): 4 rules (DAST-XXE-001 to 004) — form/upload, content-type, parameter, error-based
- **Blind injection** (in `checks/injection.py`): 2 rules (DAST-INJ-009/010) — blind SQLi (time-based), blind command injection
- **Report sections** (in `core/reporting.py`): DAST summary sections in HTML/JSON reports
- **Rule count**: 60 → 70 DAST rules

### DAST Phase 8 — Medium-Priority Improvements (commit `aeded82`)
- **JWT token analysis** (`checks/jwt_security.py`): 5 rules (DAST-JWT-001 to 005)
  - Algorithm confusion (alg:none), signature stripping, expired token acceptance, claim tampering, weak signing secret
  - Uses stdlib only (no PyJWT): base64url, json, hmac for offline secret brute-force
- **WAF detection** (`dast/waf_detect.py`): Pre-scan utility fingerprinting 8 WAFs via headers, cookies, and block-probe responses
  - Cloudflare, AWS WAF, Imperva/Incapsula, Akamai, ModSecurity, F5 BIG-IP, Sucuri, Barracuda
  - `WAFInfo` dataclass with detected, name, confidence, evidence fields
  - Called from `dast_scanner.py` between crawl and check dispatch
- **Stored XSS** (in `checks/xss.py`): 2 rules (DAST-XSS-006/007) — multi-phase inject-then-verify with unique canaries (`SKYHIGH_STORED_{sha256[:8]}`)
- **LDAP injection** (in `checks/injection.py`): 1 rule (DAST-INJ-011, CWE-90) — error pattern + wildcard length anomaly detection
- **HTTP Parameter Pollution** (in `checks/injection.py`): 1 rule (DAST-INJ-012, CWE-235) — duplicate param bypass detection
- **GraphQL DoS** (in `checks/api_security.py`): 3 rules (DAST-API-009 to 011, CWE-400) — query batching, field aliasing, deep nesting
- **CHECK_DISPATCH**: Expanded from 8 to 11 categories (added ssrf, xxe, jwt)
- **Passive mode skip set**: Now includes jwt alongside injection, xss, file_inclusion, access_control
- **Rule count**: 70 → 82 DAST rules
- **999 tests all passing, 0 skipped**

## Testing
```bash
pip install -r requirements-dev.txt    # pytest, pytest-cov, ruff, mypy
pip install requests                    # Required for EPSS/sync tests
pytest                                  # Run all 999 tests
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
| `tests/test_reporting.py` | 49 | HTML/PDF generation, charts, dashboard, XSS escaping |
| `tests/test_seed_validation.py` | 12 | JSON schema, CVE format, CVSS/EPSS ranges, dedup |
| `tests/test_epss.py` | 27 | EPSS flow: DB→Finding, enrichment, HTML/console/CSV, API mock |
| `tests/test_cli.py` | 25 | All argparse subcommands, flags, defaults |
| `tests/test_incremental_sync.py` | 23 | Incremental sync, date windows, platform filter, metadata |
| `tests/test_compliance.py` | 53 | CWE/category mapping, enrichment, filter, format, HTML/CSV/JSON |
| `tests/test_sarif.py` | 30 | SARIF v2.1.0 export, fingerprints, CWE tags, severity mapping |
| `tests/test_plugins.py` | 26 | Plugin decorator, discovery, validation, ScannerBase check |
| `tests/test_scan_profiles.py` | 36 | Profile definitions, category gating, severity floor |
| `tests/test_auto_scanner.py` | 67 | Auto scanner, parallel dispatch, thread safety, progress |
| `tests/test_config.py` | 30 | YAML/TOML parsing, find_config, merge_config, key validation |
| `tests/test_baseline.py` | 20 | Finding keys, load baseline, compute diff, diff summary |
| `tests/test_dast_config.py` | 41 | ScopePolicy, RateLimiter, RequestCounter, CircuitBreaker, DastConfig |
| `tests/test_dast_http_client.py` | 22 | RequestEvidence, scope enforcement, auth modes, convenience methods |
| `tests/test_dast_crawler.py` | 52 | SiteMap, FormInfo, HTML parser, JS extraction, WebCrawler BFS |
| `tests/test_dast_discovery.py` | 26 | URL discovery, robots.txt, sitemap.xml, common paths |
| `tests/test_dast_evidence.py` | 43 | Evidence capture in all 8 check modules |
| `tests/test_dast_perf_safety.py` | 39 | Circuit breaker, retry logic, adaptive rate limiter, response time |
| `tests/test_dast_scanner.py` | 22 | DastScanner init, concurrent dispatch, perf metrics, CLI parsing |
| `tests/test_dast_injection.py` | 21 | SQL, cmd, SSTI, CRLF, host, NoSQL, XPath, LDAP, HPP injection |
| `tests/test_dast_xss.py` | 20 | Reflected, DOM, header, error, stored XSS detection |
| `tests/test_dast_api_security.py` | 18 | API security, GraphQL introspection/batch/alias/nesting DoS |
| `tests/test_dast_jwt_security.py` | 10 | JWT collection, alg none, sig strip, expired, tampering, weak secret |
| `tests/test_dast_waf_detect.py` | 6 | WAF fingerprinting (Cloudflare, AWS, ModSecurity, Imperva, Sucuri) |
| `tests/test_dast_ssrf.py` | — | SSRF detection checks |
| `tests/test_dast_xxe.py` | — | XXE injection checks |
| `tests/test_dast_injection_blind.py` | — | Blind SQL/command injection |
| `tests/test_dast_report_sections.py` | — | DAST HTML/JSON report sections |

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
- **Optional runtime**: `requests` (CVE sync, HTTP probing), `paramiko` (SSH), `netmiko` (Cisco SSH), `pysnmp-lextudio` (SNMP), `pywinrm` (WinRM), `impacket` (SMB), `weasyprint` (PDF reports)
- **Dev/Test**: `pytest`, `pytest-cov`, `ruff`, `mypy`, `requests` (see `requirements-dev.txt`)
