<p align="center">
  <img src="banner.svg" alt="Vulnerability Management Scanner Banner" width="100%" />
</p>

<p align="center">
  <strong>Comprehensive Active Vulnerability Scanner</strong><br>
  <em>Enterprise-grade security scanning for Windows, Linux, Cisco, Web Servers, Middleware & Databases</em>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License" /></a>
  <a href="#supported-platforms"><img src="https://img.shields.io/badge/platforms-23-orange.svg" alt="23 Platforms" /></a>
  <a href="#cve-database"><img src="https://img.shields.io/badge/CVEs-32%2C000+-red.svg" alt="32,000+ CVEs" /></a>
  <a href="#features"><img src="https://img.shields.io/badge/rules-~820-purple.svg" alt="~820 Rules" /></a>
  <a href="#testing"><img src="https://img.shields.io/badge/tests-999_passing-brightgreen.svg" alt="999 Tests" /></a>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Supported Platforms](#supported-platforms)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [CVE Database](#cve-database)
- [Scan Modules](#scan-modules)
- [HTML Reports](#html-reports)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**Vulnerability Management Scanner** is an open-source active vulnerability scanner. It connects to live hosts over SSH, WinRM, SNMP, and HTTP to perform authenticated security assessments, CIS benchmark checks, and CVE detection across 23 platforms.

Unlike static analysis tools, Vulnerability Management Scanner actively queries running systems — reading configurations, checking installed software versions, probing services, and correlating findings against a local CVE database seeded from the NVD and CISA KEV feeds.

### Key Highlights

- **Active scanning** — Connects to live hosts via SSH, WinRM, Netmiko, SNMP, SMB, and HTTP
- **DAST scanning** — Dynamic Application Security Testing with crawling, scope enforcement, and rate limiting
- **Auto-discovery** — Scans IP ranges, fingerprints services, classifies hosts, and dispatches the right scanner
- **~820 security rules** across 21 check modules + 11 DAST check categories
- **32,000+ CVEs** via NVD API 2.0 sync (2010-2025) with CISA KEV + EPSS overlay
- **510 bundled seed CVEs** with 159 CISA KEV entries for offline scanning
- **6 CIS benchmarks** — Windows, Linux, Cisco, Oracle DB, MySQL, MongoDB
- **Interactive HTML reports** — Dark theme, Chart.js dashboard, JS filtering, PDF export
- **SARIF v2.1.0 export** — GitHub Code Scanning and VS Code compatible
- **Plugin architecture** — Extend with custom scanners via `@scanner_plugin` decorator
- **Scan profiles** — quick, standard, full, compliance, cve-only presets
- **Parallel scanning** — ThreadPoolExecutor-based multi-host dispatch
- **Config files** — YAML/TOML configuration with CLI override precedence
- **Baseline diff scanning** — Track NEW/FIXED/UNCHANGED findings across scans
- **Compliance mapping** — NIST 800-53, ISO 27001, PCI DSS v4.0, CIS Controls v8
- **Graceful degradation** — All transport dependencies are optional; missing libraries are handled cleanly

---

## Features

| Category | Details |
|----------|---------|
| **OS Scanning** | Windows (WinRM/SMB), Linux (SSH), Cisco IOS/IOS-XE/NX-OS (Netmiko/SNMP) |
| **Web Server Scanning** | IIS, Apache HTTPD, Nginx, Tomcat, WebLogic, WebSphere |
| **Middleware Scanning** | Java/JDK, .NET Framework, PHP, Node.js, Laravel, Oracle Middleware |
| **Database Scanning** | Oracle DB, MySQL/MariaDB, MongoDB |
| **CVE Detection** | Version-based CVE matching against local SQLite database with EPSS scores |
| **CIS Benchmarks** | Hardening checks based on CIS benchmark guidelines |
| **Network Discovery** | TCP port scanning, banner grabbing, OS classification |
| **Compliance Mapping** | NIST SP 800-53, ISO 27001:2022, PCI DSS v4.0, CIS Controls v8 |
| **Credential Management** | CLI args, environment variables, or credential files |
| **Reporting** | Console (colored), JSON, CSV, SARIF, interactive HTML, PDF |
| **Scan Profiles** | quick, standard, full, compliance, cve-only presets |
| **Plugins** | Extensible scanner architecture with auto-discovery |
| **DAST Scanning** | Web app testing with crawling, scope enforcement, rate limiting, auth modes |
| **Baseline Diff** | Track new, fixed, and unchanged findings across scans |
| **Config Files** | YAML/TOML config with built-in parser (no PyYAML needed) |

---

## Supported Platforms

### Operating Systems
| Platform | Transport | Checks |
|----------|-----------|--------|
| Windows Server / Desktop | WinRM, SMB | Patches, account policies, registry, services, firewall, audit, CIS |
| Linux (Ubuntu, RHEL, CentOS, Debian, SUSE) | SSH (paramiko) | sshd, accounts, permissions, sysctl, packages, CVEs, CIS |
| Cisco IOS / IOS-XE / NX-OS | Netmiko, SNMP | Authentication, SSH, VTY, SNMP, services, interfaces, L2, CVEs, CIS |

### Web Servers
| Server | Detection | Key Checks |
|--------|-----------|------------|
| Microsoft IIS | HTTP headers | Version CVEs, ASP.NET disclosure, WebDAV, default pages |
| Apache HTTPD | Server header | Version CVEs, ServerTokens, directory listing, server-status |
| Nginx | Server header | Version CVEs, stub_status exposure |
| Apache Tomcat | Server header, `/manager` | Version CVEs, Manager app, default credentials, sample apps |
| Oracle WebLogic | `/console` probe | Version CVEs, console exposure, wls-wsat, UDDI SSRF |
| IBM WebSphere | Admin console probe | Admin console, snoop servlet, version leaks |

### Middleware
| Runtime | Detection | Key Checks |
|---------|-----------|------------|
| Java / JDK | `java -version` | EOL versions, Log4j (CVE-2021-44228), Spring Boot Actuator |
| .NET Framework | Registry / `dotnet` | EOL .NET Core, .NET Framework version |
| PHP | `php -v` | EOL versions, php.ini hardening, phpinfo() exposure |
| Node.js | `node -v` | EOL versions, npm audit, Express X-Powered-By |
| Laravel | `php artisan --version` | APP_DEBUG, APP_ENV, APP_KEY, .env exposure, Ignition RCE |
| Oracle Middleware | `sqlplus -V` | Version CVEs, TNS Listener, OEM console |

### Databases
| Database | Detection | Key Checks |
|----------|-----------|------------|
| Oracle DB | Port 1521 | sqlnet.ora encryption, listener security, REMOTE_OS_AUTHENT |
| MySQL / MariaDB | Port 3306 | EOL versions, local_infile, bind-address, TLS |
| MongoDB | Port 27017 | Authorization, bindIp, TLS, audit logging, unauthenticated access |

### DAST (Dynamic Application Security Testing)
| Feature | Details |
|---------|---------|
| **Crawling** | BFS web crawler with form, link, API endpoint, and JavaScript extraction |
| **URL Discovery** | robots.txt, sitemap.xml, and common path probing |
| **Scope Enforcement** | Mandatory host/path allowlist prevents out-of-scope requests |
| **Rate Limiting** | Adaptive token-bucket algorithm — halves on 429/5xx, auto-recovers |
| **Request Cap** | Hard limit on total requests (default 10,000) |
| **Circuit Breaker** | Trips after consecutive failures, auto-resets after timeout |
| **Retry Logic** | Exponential backoff on transient failures (5xx, timeouts) |
| **Connection Pooling** | HTTPAdapter with 20 pooled connections for performance |
| **Response Time Tracking** | Average and P95 response time metrics in scan summary |
| **Concurrent Checks** | ThreadPoolExecutor (4 workers) for parallel check dispatch |
| **Evidence Capture** | Proof-of-concept request/response pairs attached to findings |
| **Auth Modes** | None, Bearer token, Cookie, Basic auth, Form login |
| **Passive Mode** | `--dast-passive-only` skips injection/XSS/file-inclusion checks |
| **Safety Controls** | Pre-scan warning banner, `--dast-accept-risk` to suppress |
| **WAF Detection** | Pre-scan WAF fingerprinting: Cloudflare, AWS WAF, Imperva, Akamai, ModSecurity, F5, Sucuri, Barracuda |
| **Check Categories** | Injection (12 rules), XSS (7 rules), Auth/Session, Access Control, API Security (11 rules), File Inclusion, Info Disclosure, Config/Misconfig, SSRF (4 rules), XXE (4 rules), JWT (5 rules) |

---

## Architecture

```
                          +------------------+
                          |   CLI (__main__) |
                          +--------+---------+
                                   |
              +--------------------+--------------------+
              |                    |                     |
        +-----+------+    +-------+-------+    +--------+--------+
        | AutoScanner |    | DAST Scanner  |    | Direct Scanners |
        +-----+------+    +-------+-------+    +--------+--------+
              |                    |                     |
      +-------+-------+   +-------+-------+   +---------+---------+
      |NetworkDiscovery|   | WebCrawler    |   | windows | linux   |
      +-------+-------+   | ScopePolicy   |   | cisco | webserver |
              |            | RateLimiter   |   | middleware | db   |
      +-------+-------+   | DastHTTPClient|   +-------------------+
      |   Classify &   |   +-------+-------+
      |   Dispatch     |           |
      +----------------+   +-------+-------+
              |            | Check Modules |
   +----------+----------+ | injection     |
   |          |          | | xss, auth     |
+--+---+ +---+----+ +---+-| api, config   |
|Trans-| |CVE DB  | |Report+---------------+
|port  | | SQLite | | HTML |
| SSH  | | NVD    | | JSON |
| WinRM| | KEV    | | CSV  |
| HTTP | +--------+ +------+
+------+
```

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| `Finding` | `core/finding.py` | Standardized finding dataclass shared by all scanners |
| `ScannerBase` | `core/scanner_base.py` | Abstract base class with reporting, filtering, exit codes |
| `Transport` | `core/transport.py` | 6 transport abstractions (SSH, WinRM, Netmiko, SNMP, SMB, HTTP) |
| `CredentialManager` | `core/credential_manager.py` | Unified credential loading (CLI / env / file) |
| `NetworkDiscovery` | `core/discovery.py` | Host probe, port scan, service fingerprint, OS classification |
| `CVEDatabase` | `core/cve_database.py` | SQLite-backed CVE storage with version matching |
| `CVESync` | `core/cve_sync.py` | NVD API 2.0 sync, CISA KEV overlay, vendor feeds |
| `Reporting` | `core/reporting.py` | HTML/PDF report generation with Chart.js dashboard |
| `Compliance` | `core/compliance.py` | CWE/category → NIST/ISO/PCI/CIS mapping engine |
| `Config` | `core/config.py` | YAML/TOML config file loader with built-in parser |
| `Baseline` | `core/baseline.py` | Diff scanning — compare current vs previous scan |
| `ScanProfiles` | `core/scan_profiles.py` | Scan profile definitions and category gating |
| `PluginRegistry` | `core/plugin_registry.py` | Plugin discovery, registration, and validation |

---

## Installation

### Prerequisites

- **Python 3.9+** (3.10-3.12 recommended)
- **pip** (package manager)

### Install from Source

```bash
git clone https://github.com/Krishcalin/Vulnerability-Management.git
cd Vulnerability-Management
pip install -e .
```

### Install with Extras

Install only the transport dependencies you need:

```bash
# Linux scanning (SSH)
pip install -e ".[linux]"

# Cisco scanning (SSH + SNMP)
pip install -e ".[cisco]"

# Windows scanning (WinRM)
pip install -e ".[windows]"

# Everything
pip install -e ".[all]"
```

### Manual Dependency Install

```bash
pip install -r requirements.txt
```

| Dependency | Required For | Optional? |
|------------|-------------|-----------|
| `requests` | HTTP transport, NVD sync, web scanning | Recommended |
| `paramiko` | Linux SSH scanning | Yes |
| `netmiko` | Cisco SSH scanning | Yes |
| `pysnmp-lextudio` | Cisco SNMP scanning | Yes |
| `pywinrm` | Windows WinRM scanning | Yes |
| `impacket` | Windows SMB scanning | Yes |

> All dependencies are optional. The scanner gracefully degrades when a library is missing -- you will see a warning but can still use other scan types.

---

## Quick Start

### 1. Import Seed CVE Data

```bash
python -m vulnerability_management cve-import
```

This loads 510 curated CVEs (159 CISA KEV flagged) from the bundled seed files.

### 2. Check CVE Database Stats

```bash
python -m vulnerability_management cve-stats
```

### 3. Run a Scan

```bash
# Auto-discover and scan a subnet
python -m vulnerability_management auto -r 192.168.1.0/24 -u admin -p secret

# Scan a specific Linux host
python -m vulnerability_management linux -t 10.0.1.50 -u root -p password

# Scan a Windows host
python -m vulnerability_management windows -t 10.0.1.100 -u administrator -p password

# Scan Cisco devices
python -m vulnerability_management cisco -r 10.0.1.0/24 -u admin -p secret --enable-password enable123

# Scan a web server
python -m vulnerability_management webserver -t https://example.com

# Scan middleware on a host
python -m vulnerability_management middleware -t 10.0.1.50 -u admin -p secret

# Scan databases on a host
python -m vulnerability_management database -t 10.0.1.50

# DAST scan a web application
python -m vulnerability_management dast --target https://app.example.com --dast-accept-risk
```

### 4. Generate Reports

```bash
# JSON output
python -m vulnerability_management linux -t 10.0.1.50 -u root -p pass --json report.json

# HTML report
python -m vulnerability_management linux -t 10.0.1.50 -u root -p pass --html report.html

# Filter by severity
python -m vulnerability_management linux -t 10.0.1.50 -u root -p pass --severity HIGH

# Verbose output
python -m vulnerability_management linux -t 10.0.1.50 -u root -p pass -v
```

---

## CLI Reference

```
usage: python -m vulnerability_management <command> [options]

Commands:
  auto          Auto-discover hosts and run appropriate scanners
  windows       Scan Windows hosts via WinRM
  linux         Scan Linux hosts via SSH
  cisco         Scan Cisco IOS/IOS-XE devices via SSH/SNMP
  webserver     Scan web servers via HTTP
  middleware    Scan middleware runtimes via SSH/WinRM
  database      Scan database services
  dast          Dynamic Application Security Testing (web app scanning)
  cve-sync      Sync CVEs from NVD API 2.0 (includes EPSS + KEV)
  cve-import    Import seed CVE data from bundled JSON files
  cve-stats     Display CVE database statistics (includes EPSS coverage)
  epss-sync     Fetch/update EPSS scores from FIRST.org API
```

### Common Options

| Flag | Description |
|------|-------------|
| `-t, --target` | Target host (IP or hostname) |
| `-r, --range` | IP range (CIDR, start-end, or comma-separated) |
| `-u, --username` | Authentication username |
| `-p, --password` | Authentication password |
| `--severity` | Minimum severity filter: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--profile` | Scan profile: `quick`, `standard`, `full`, `compliance`, `cve-only` |
| `--config FILE` | YAML/TOML config file (auto-discovers `vulnerability-management.yml` if omitted) |
| `--baseline FILE` | Compare against previous JSON scan for diff reporting |
| `--threads N` | Number of parallel scan threads (default: 4) |
| `--compliance` | Enrich findings with compliance framework mappings |
| `--json FILE` | Save findings to JSON file |
| `--html FILE` | Save findings to interactive HTML report |
| `--csv FILE` | Save findings to CSV file |
| `--sarif FILE` | Save findings to SARIF v2.1.0 (GitHub Code Scanning compatible) |
| `--pdf FILE` | Save findings to PDF report (requires `weasyprint`) |
| `-v, --verbose` | Enable verbose output |
| `--version` | Show scanner version |

### DAST Options

```bash
# Basic DAST scan
python -m vulnerability_management dast --target https://app.example.com

# Passive-only mode (no injection payloads)
python -m vulnerability_management dast --target https://app.example.com --dast-passive-only

# Custom rate limit and auth
python -m vulnerability_management dast --target https://app.example.com \
  --dast-rate-limit 20 --dast-auth-mode bearer --dast-auth-token mytoken

# Skip crawling (test seed URL only)
python -m vulnerability_management dast --target https://app.example.com --dast-no-crawl

# Accept risk (suppress warning banner)
python -m vulnerability_management dast --target https://app.example.com --dast-accept-risk
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target URL` | (required) | Target URL to scan |
| `--dast-scope FILE` | auto | JSON scope file (auto-generated from target if omitted) |
| `--dast-rate-limit N` | 10.0 | Max requests per second |
| `--dast-max-requests N` | 10000 | Hard cap on total requests |
| `--dast-crawl-depth N` | 5 | Maximum crawl depth |
| `--dast-auth-mode MODE` | none | Auth mode: `none`, `bearer`, `cookie`, `basic`, `form` |
| `--dast-auth-token TOKEN` | — | Auth token/credentials |
| `--dast-login-url URL` | — | Login URL for form-based auth |
| `--dast-passive-only` | false | Skip active injection checks |
| `--dast-no-crawl` | false | Skip crawling, test seed URL only |
| `--dast-accept-risk` | false | Suppress pre-scan warning banner |
| `--dast-follow-subdomains` | false | Include subdomains in scope |
| `--dast-request-timeout N` | 15 | Per-request timeout in seconds |
| `--dast-verify-ssl` | false | Verify SSL certificates |
| `--dast-max-pages N` | 500 | Maximum pages to crawl |
| `--dast-user-agent STR` | VulnMgmt-DAST/1.0 | Custom User-Agent header |
| `--dast-proxy URL` | — | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `--dast-retries N` | 3 | Max retries per request on failure |

### CVE Sync Options

```bash
# Full sync from NVD (2010-2025, ~32,000 CVEs)
python -m vulnerability_management cve-sync --api-key YOUR_NVD_API_KEY

# Sync from a specific year
python -m vulnerability_management cve-sync --api-key YOUR_NVD_API_KEY --since 2020

# Incremental sync (only CVEs modified since last sync)
python -m vulnerability_management cve-sync --incremental --api-key YOUR_NVD_API_KEY

# Sync specific platforms only
python -m vulnerability_management cve-sync --platform nginx tomcat apache_httpd

# Combine: incremental sync for specific platforms
python -m vulnerability_management cve-sync --incremental --platform openssl openssh

# Sync without API key (slower, 6s rate limit)
python -m vulnerability_management cve-sync
```

> Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key to increase sync speed (0.6s vs 6s between requests).

**Incremental sync** uses the NVD `lastModStartDate`/`lastModEndDate` API parameters to fetch only CVEs that were created or updated since the previous sync. This is significantly faster than a full sync and is ideal for daily/weekly updates. The NVD API limits date ranges to 120 days, so wider gaps are automatically split into multiple windows.

### EPSS Sync Options

```bash
# Update EPSS scores for all CVEs in the database
python -m vulnerability_management epss-sync

# With verbose output
python -m vulnerability_management epss-sync -v
```

EPSS (Exploit Prediction Scoring System) scores are fetched from the FIRST.org API and indicate the probability that a CVE will be exploited in the wild within 30 days. Scores are shown in reports as color-coded badges:
- **Red** (>=50%) -- High exploit probability
- **Orange** (>=10%) -- Moderate exploit probability
- **Green** (<10%) -- Low exploit probability

> EPSS is also automatically synced during `cve-sync`. Use `epss-sync` to update scores independently.

### Environment Variables

Instead of passing credentials on the command line, set environment variables:

| Variable | Purpose |
|----------|---------|
| `VULNMGMT_SSH_USERNAME` | SSH username for Linux scanning |
| `VULNMGMT_SSH_PASSWORD` | SSH password |
| `VULNMGMT_WINRM_USERNAME` | WinRM username for Windows scanning |
| `VULNMGMT_WINRM_PASSWORD` | WinRM password |
| `VULNMGMT_SNMP_COMMUNITY` | SNMP community string |
| `VULNMGMT_ENABLE_PASSWORD` | Cisco enable password |
| `NVD_API_KEY` | NVD API key for CVE sync |

---

## CVE Database

Vulnerability Management Scanner maintains a local SQLite database of CVEs for offline version-based vulnerability matching.

### Database Schema

| Table | Purpose |
|-------|---------|
| `cves` | CVE ID, description, CVSS score, EPSS score, severity, published date, CISA KEV flag |
| `affected_versions` | CPE strings and version ranges per CVE |
| `linux_packages` | Package-level CVE mappings for Linux distributions |
| `sync_metadata` | Tracks last sync timestamps per platform |

### Data Sources

| Source | Coverage | Method |
|--------|----------|--------|
| **Seed files** | 510 curated CVEs (bundled, 21 files) | `cve-import` command |
| **NVD API 2.0** | ~32,000 CVEs (2010-2025) | `cve-sync` command, 47 CPE queries |
| **CISA KEV** | 1,100+ actively exploited CVEs | Overlay during sync |
| **FIRST.org EPSS** | Exploit probability scores (0-100%) | `epss-sync` command or during `cve-sync` |

### CPE Coverage

The scanner syncs CVEs for 47 CPE (Common Platform Enumeration) strings covering:

- Microsoft Windows (Server 2008-2022, Desktop 7-11)
- Linux distributions (Ubuntu, RHEL, CentOS, Debian, SUSE)
- Cisco IOS, IOS-XE, NX-OS
- Apache HTTPD, Nginx, IIS, Tomcat, WebLogic, WebSphere
- Java/JDK, .NET, PHP, Node.js
- Oracle Database, MySQL, MariaDB, MongoDB
- OpenSSL, OpenSSH, Log4j, Spring Framework

---

## Scan Modules

### Rule ID Formats

| Scanner | Format | Example |
|---------|--------|---------|
| Windows | `WIN-{CATEGORY}-{NNN}` | `WIN-ACCT-001` |
| Linux | `LNX-{CATEGORY}-{NNN}` | `LNX-SSH-003` |
| Cisco | `CISCO-{CATEGORY}-{NNN}` | `CISCO-AUTH-001` |
| Web Server | `WEB-{SERVER}-{NNN}` | `WEB-IIS-002` |
| Middleware | `MW-{PLATFORM}-{CAT}-{NNN}` | `MW-JAVA-EOL-001` |
| Database | `DB-{PLATFORM}-{CAT}-{NNN}` | `DB-MYSQL-CFG-001` |
| DAST | `DAST-{CATEGORY}-{NNN}` | `DAST-INJ-001` |
| CVE | `CVE-YYYY-NNNNN` | `CVE-2021-44228` |

### Check Categories

| Category | Description | Rule Count |
|----------|-------------|------------|
| Authentication | Passwords, secrets, AAA, MFA | ~40 |
| Access Control | ACLs, VTY lines, permissions | ~30 |
| Encryption / TLS | SSL/TLS config, ciphers, certificates | ~25 |
| Network Security | Firewall, interfaces, routing, L2 | ~35 |
| Services | Unnecessary services, default configs | ~30 |
| Logging & Audit | Syslog, audit trails, retention | ~20 |
| Patch Management | Missing patches, EOL software | ~50 |
| CVE Detection | Known vulnerability matching | ~800 |
| CIS Benchmarks | Hardening compliance checks | ~100 |
| Configuration | Misconfigurations, defaults | ~70 |

---

## Compliance Framework Mapping

Vulnerability Management Scanner maps findings to four major compliance frameworks, enabling audit-ready reports:

| Framework | Standard | Controls Mapped |
|-----------|----------|-----------------|
| **NIST SP 800-53** | Rev 5 | AC, AU, CM, IA, SC, SI, SA, CP families |
| **ISO 27001** | 2022 | Annex A controls (A.5-A.8) |
| **PCI DSS** | v4.0 | Requirements 1-10 |
| **CIS Controls** | v8 | Controls 3-16 |

### How It Works

1. **CWE-based mapping** (primary) -- ~60 CWE IDs mapped to all four frameworks
2. **Category-based fallback** -- ~30 finding categories for findings without CWEs
3. **Opt-in enrichment** -- Add `--compliance` to any scan command

```bash
# Scan with compliance mapping
python -m vulnerability_management linux -r 10.0.0.0/24 --compliance

# Compliance tags appear in all output formats
python -m vulnerability_management cisco -r 10.1.1.0/24 --compliance --html report.html --csv report.csv
```

### Output

- **Console**: Each finding shows `Compliance: NIST: SI-10, SI-3 | ISO: A.8.28 | PCI: 6.2.4 | CIS: 16.12`
- **HTML**: Compliance tags on findings + framework summary table with control-to-finding counts
- **JSON**: Nested `compliance` dict per finding: `{"nist_800_53": ["SI-10"], "pci_dss": ["6.2.4"], ...}`
- **CSV**: Flattened columns: `nist_800_53`, `iso_27001`, `pci_dss`, `cis_controls`

---

## Reports & Exports

### Interactive HTML Reports

Vulnerability Management Scanner generates interactive HTML reports with:

- **Dark theme** with platform-specific accent colors
- **Chart.js dashboard** -- Severity doughnut, EPSS distribution, category bar, top targets bar charts
- **Summary cards** -- total findings, severity breakdown, EPSS high-risk count, scan metadata
- **Severity-colored finding cards** -- CRITICAL (red), HIGH (orange), MEDIUM (yellow), LOW (blue), INFO (gray)
- **EPSS badges** -- Color-coded exploit probability: red (>=50%), orange (>=10%), green (<10%)
- **CISA KEV badges** -- Pulse animation for actively exploited vulnerabilities
- **JavaScript filtering** -- Filter by severity, category, target, or free-text search
- **Compliance tags** -- NIST, ISO, PCI DSS, CIS control references per finding
- **Print-friendly CSS** -- Charts hidden, clean layout for printing
- **Self-contained** -- Single HTML file, no external dependencies

### PDF Reports

Print-optimised reports via optional `weasyprint` dependency:
- White background, A4 pages, all findings expanded
- Executive summary with severity breakdown
- Same data as HTML but formatted for offline distribution

### SARIF Export

SARIF v2.1.0 output for CI/CD integration:
- GitHub Code Scanning compatible
- VS Code SARIF Viewer compatible
- Includes fingerprints, CWE tags, CVSS security-severity
- Severity-to-level mapping (CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note)

### Baseline Diff Scanning

Compare scans against a previous baseline to track remediation progress:

```bash
# Create a baseline
python -m vulnerability_management linux -r 10.0.0.0/24 --json baseline.json

# Compare against baseline
python -m vulnerability_management linux -r 10.0.0.0/24 --baseline baseline.json
```

Output shows NEW findings (not in baseline), FIXED findings (resolved), and UNCHANGED findings.

---

## Project Structure

```
Vulnerability-Management/
├── banner.svg                    # Project banner
├── LICENSE                       # MIT License
├── README.md                     # This file
├── CLAUDE.md                     # AI assistant project context
├── requirements.txt              # Runtime dependencies
├── requirements-dev.txt          # Dev/test dependencies (pytest, ruff, mypy)
├── setup.py                      # pip install configuration
├── pyproject.toml                # pytest, ruff, mypy configuration
│
├── .github/workflows/
│   └── ci.yml                    # GitHub Actions CI (test, lint, seed validation)
│
├── tests/                        # Test suite (999 tests)
│   ├── conftest.py               # Shared fixtures
│   ├── test_version_utils.py     # Version parsing & range matching (20 tests)
│   ├── test_ip_utils.py          # IP range expansion & DNS (16 tests)
│   ├── test_finding.py           # Finding dataclass & serialisation (10 tests)
│   ├── test_credential_manager.py # Credential loading & env vars (18 tests)
│   ├── test_scanner_base.py      # Base scanner, filtering, export (17 tests)
│   ├── test_cve_database.py      # SQLite import, lookup, KEV flagging (14 tests)
│   ├── test_reporting.py         # HTML/PDF generation, charts, XSS escaping (49 tests)
│   ├── test_seed_validation.py   # Seed file integrity & dedup (12 tests)
│   ├── test_epss.py              # EPSS integration end-to-end (27 tests)
│   ├── test_cli.py               # CLI argument parsing (25 tests)
│   ├── test_incremental_sync.py  # Incremental CVE sync (23 tests)
│   ├── test_compliance.py        # Compliance framework mapping (53 tests)
│   ├── test_sarif.py             # SARIF v2.1.0 export (30 tests)
│   ├── test_plugins.py           # Plugin architecture (26 tests)
│   ├── test_scan_profiles.py     # Scan profiles & category gating (36 tests)
│   ├── test_auto_scanner.py      # Auto scanner & parallel dispatch (67 tests)
│   ├── test_config.py            # Config file loading (30 tests)
│   ├── test_baseline.py          # Baseline diff scanning (20 tests)
│   ├── test_dast_config.py       # DAST config, scope, rate limiter, circuit breaker (41 tests)
│   ├── test_dast_http_client.py  # DAST HTTP client, auth, evidence (22 tests)
│   ├── test_dast_crawler.py      # Web crawler, HTML parser, JS extraction (52 tests)
│   ├── test_dast_discovery.py    # URL discovery, robots.txt, sitemap.xml (26 tests)
│   ├── test_dast_evidence.py     # Evidence capture in check modules (43 tests)
│   ├── test_dast_perf_safety.py  # Circuit breaker, retry, adaptive rate limiter (39 tests)
│   ├── test_dast_scanner.py      # DAST scanner orchestrator, concurrent dispatch (22 tests)
│   ├── test_dast_injection.py    # Injection checks: SQL, cmd, SSTI, CRLF, LDAP, HPP (21 tests)
│   ├── test_dast_xss.py          # XSS checks: reflected, DOM, stored (20 tests)
│   ├── test_dast_api_security.py # API security + GraphQL DoS (18 tests)
│   ├── test_dast_ssrf.py         # SSRF detection (tests)
│   ├── test_dast_xxe.py          # XXE injection (tests)
│   ├── test_dast_jwt_security.py # JWT token analysis (10 tests)
│   ├── test_dast_waf_detect.py   # WAF detection (6 tests)
│   ├── test_dast_injection_blind.py # Blind injection (tests)
│   └── test_dast_report_sections.py # DAST report sections (tests)
│
└── vulnerability_management/              # Main package
    ├── __init__.py               # VERSION = "1.0.0"
    ├── __main__.py               # CLI entry point (argparse)
    │
    ├── core/                     # Shared engine
    │   ├── finding.py            # Finding dataclass
    │   ├── scanner_base.py       # ScannerBase ABC
    │   ├── version_utils.py      # Version parsing & comparison
    │   ├── ip_utils.py           # IP range expansion
    │   ├── transport.py          # SSH, WinRM, Netmiko, SNMP, SMB, HTTP
    │   ├── credential_manager.py # Credential loading
    │   ├── discovery.py          # Network discovery & classification
    │   ├── cve_database.py       # SQLite CVE storage
    │   ├── cve_sync.py           # NVD API 2.0 & CISA KEV sync
    │   ├── reporting.py          # HTML/PDF report generation
    │   ├── compliance.py         # Compliance framework mapping engine
    │   ├── config.py             # YAML/TOML config file loader
    │   ├── baseline.py           # Baseline diff scanning
    │   ├── scan_profiles.py      # Scan profile definitions
    │   └── plugin_registry.py    # Plugin discovery & registration
    │
    ├── scanners/                 # Scanner modules
    │   ├── auto_scanner.py       # Auto-discover & dispatch
    │   ├── dast_scanner.py       # DAST orchestrator (crawl → check dispatch)
    │   ├── windows_scanner.py    # Windows (WinRM/SMB)
    │   ├── linux_scanner.py      # Linux (SSH)
    │   ├── cisco_scanner.py      # Cisco IOS/IOS-XE (Netmiko/SNMP)
    │   ├── webserver_scanner.py  # Web server fingerprint & dispatch
    │   ├── middleware_scanner.py  # Middleware detection & dispatch
    │   └── database_scanner.py   # Database detection & dispatch
    │
    ├── dast/                     # DAST engine
    │   ├── __init__.py           # Package exports
    │   ├── config.py             # ScopePolicy, RateLimiter, RequestCounter, CircuitBreaker, DastConfig
    │   ├── http_client.py        # DastHTTPClient (scope + rate limiting + retries + evidence)
    │   ├── crawler.py            # WebCrawler, SiteMap, HTML parser, JS extraction
    │   ├── discovery.py          # URL discovery (robots.txt, sitemap.xml, common paths)
    │   ├── waf_detect.py          # WAF fingerprinting utility (8 WAFs)
    │   └── checks/               # Check modules (82 DAST rules across 11 categories)
    │       ├── __init__.py        # Check module interface
    │       ├── injection.py       # SQL/cmd/SSTI/CRLF/host/NoSQL/XPath/blind/LDAP/HPP (12 rules)
    │       ├── xss.py             # Reflected/DOM/header/error/stored XSS (7 rules)
    │       ├── auth_session.py    # Auth & session checks
    │       ├── access_control.py  # Access control checks
    │       ├── api_security.py    # API security + GraphQL DoS (11 rules)
    │       ├── file_inclusion.py  # LFI/RFI checks
    │       ├── info_disclosure.py # Info disclosure checks
    │       ├── config_misconfig.py# Configuration checks
    │       ├── ssrf.py            # SSRF detection (4 rules)
    │       ├── xxe.py             # XXE injection (4 rules)
    │       └── jwt_security.py    # JWT token analysis (5 rules)
    │
    ├── webservers/               # Web server check modules
    │   ├── iis_checks.py, apache_checks.py, nginx_checks.py
    │   ├── tomcat_checks.py, weblogic_checks.py, websphere_checks.py
    │
    ├── middleware/                # Middleware check modules
    │   ├── java_checks.py, dotnet_checks.py, php_checks.py
    │   ├── nodejs_checks.py, laravel_checks.py, oracle_checks.py
    │
    ├── databases/                # Database check modules
    │   ├── oracle_db_checks.py, mysql_checks.py, mongodb_checks.py
    │
    ├── cve_data/                 # CVE data files
    │   ├── cpe_mappings.json     # 47 CPE strings for NVD sync
    │   └── seed/                 # 21 seed JSON files (510 curated CVEs)
    │
    ├── plugins/                  # Auto-discovered plugin directory
    │   └── example_scanner.py    # Example plugin template
    │
    └── benchmarks/               # CIS benchmark definitions (6 JSON files)
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed -- no CRITICAL or HIGH findings |
| `1` | Scan completed -- CRITICAL or HIGH findings detected |

---

## Testing

Vulnerability Management Scanner has a comprehensive test suite covering all core modules.

### Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage report
pytest --cov=vulnerability_management --cov-report=term-missing

# Run a specific test file
pytest tests/test_version_utils.py

# Run seed validation only
pytest tests/test_seed_validation.py -v
```

### Test Coverage

| Module | Tests | Coverage |
|--------|-------|----------|
| `core/finding.py` | 10 | 100% |
| `core/reporting.py` | 49 | 100% |
| `core/credential_manager.py` | 18 | 98% |
| `core/ip_utils.py` | 16 | 97% |
| `core/version_utils.py` | 20 | 94% |
| `core/scanner_base.py` | 17 | 93% |
| `core/cve_database.py` | 14 | 85% |
| EPSS integration | 27 | N/A (cross-module) |
| Incremental CVE sync | 23 | N/A (cross-module) |
| Compliance mapping | 53 | N/A (cross-module) |
| SARIF export | 30 | N/A (cross-module) |
| Plugin architecture | 26 | N/A (cross-module) |
| Scan profiles | 36 | N/A (cross-module) |
| Auto scanner & parallel | 67 | N/A (cross-module) |
| Config file loading | 30 | N/A (cross-module) |
| Baseline diff scanning | 20 | N/A (cross-module) |
| DAST config & scope | 41 | N/A (cross-module) |
| DAST HTTP client | 22 | N/A (cross-module) |
| DAST crawler | 52 | N/A (cross-module) |
| DAST discovery | 26 | N/A (cross-module) |
| DAST evidence | 43 | N/A (cross-module) |
| DAST perf & safety | 39 | N/A (cross-module) |
| DAST scanner | 22 | N/A (cross-module) |
| DAST injection checks | 21 | N/A (cross-module) |
| DAST XSS checks | 20 | N/A (cross-module) |
| DAST API security | 18 | N/A (cross-module) |
| DAST JWT security | 10 | N/A (cross-module) |
| DAST WAF detection | 6 | N/A (cross-module) |
| DAST SSRF/XXE/blind/reports | ~30 | N/A (cross-module) |
| Seed file validation | 12 | N/A |
| CLI argument parsing | 25 | N/A |
| **Total** | **999** | |

### CI Pipeline

GitHub Actions runs automatically on push/PR to `main`:

- **Test** -- Matrix across Python 3.9, 3.10, 3.11, 3.12 with coverage
- **Lint** -- `ruff check` for code quality
- **Seed Validation** -- Schema, format, and duplicate checks on all CVE seed files

### Seed File Validation

The test suite validates all 21 seed JSON files for:
- Valid JSON structure (array or `{"cves": [...]}` wrapper)
- Required fields: `cve_id`, `platform`, `severity`, `published`, `name`
- Valid severity values (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
- CVE ID format (`CVE-YYYY-NNNNN`)
- CVSS scores in 0.0-10.0 range
- EPSS scores in 0.0-1.0 range
- No duplicate CVE IDs within files
- No same-platform duplicates across files

---

## Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Install** dev dependencies: `pip install -r requirements-dev.txt`
4. **Make** your changes
5. **Run tests**: `pytest` -- all 999 tests must pass
6. **Lint**: `ruff check vulnerability_management/ tests/`
7. **Commit**: `git commit -m "Add my feature"`
8. **Push**: `git push origin feature/my-feature`
9. **Open** a Pull Request

### Adding a New Scanner Module

1. Create a new scanner class extending `ScannerBase`
2. Define rule dictionaries with `id`, `category`, `name`, `severity`, `description`, `recommendation`
3. Implement `scan()` method using the appropriate transport from `core/transport.py`
4. Register the scanner in `__main__.py` as a new sub-command
5. Add seed CVE data in `cve_data/seed/`
6. Add CPE strings in `cve_data/cpe_mappings.json`

### Adding New CVE Seed Data

1. Create or update a JSON file in `cve_data/seed/`
2. Follow the existing format: `{ "cves": [ { "cve_id": "...", "description": "...", ... } ] }`
3. Run `python -m vulnerability_management cve-import` to load the data

---

## Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before scanning any systems. Unauthorized scanning may violate laws and regulations. The authors are not responsible for misuse of this tool.

---

## License

This project is licensed under the **MIT License** -- see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 KRISH

---

<p align="center">
  <sub>Built with care for the security community</sub>
</p>
