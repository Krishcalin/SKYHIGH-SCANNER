"""Tests for CLI argument parsing (__main__.py)."""

import pytest

from vulnerability_management.__main__ import _build_parser


class TestCliParser:
    @pytest.fixture
    def parser(self):
        return _build_parser()

    def test_no_args_returns_none_command(self, parser):
        args = parser.parse_args([])
        assert args.command is None

    def test_version_flag(self, parser):
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    # ── Scan sub-commands ─────────────────────────────────────────────

    @pytest.mark.parametrize("cmd", [
        "auto", "windows", "linux", "cisco",
        "webserver", "middleware", "database",
    ])
    def test_scan_commands_parse(self, parser, cmd):
        args = parser.parse_args([cmd, "-r", "10.0.0.0/24"])
        assert args.command == cmd
        assert args.ip_range == "10.0.0.0/24"

    def test_target_flag(self, parser):
        args = parser.parse_args(["webserver", "-t", "https://example.com"])
        assert args.target == "https://example.com"

    def test_max_hosts(self, parser):
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24", "--max-hosts", "50"])
        assert args.max_hosts == 50

    def test_default_max_hosts(self, parser):
        args = parser.parse_args(["linux", "-r", "10.0.0.0/24"])
        assert args.max_hosts == 256

    # ── Credential flags ──────────────────────────────────────────────

    def test_ssh_credentials(self, parser):
        args = parser.parse_args([
            "linux", "-r", "10.0.0.1",
            "--ssh-user", "admin", "--ssh-password", "secret",
            "--ssh-key", "/tmp/id_rsa", "--ssh-port", "2222",
        ])
        assert args.ssh_user == "admin"
        assert args.ssh_password == "secret"
        assert args.ssh_key == "/tmp/id_rsa"
        assert args.ssh_port == 2222

    def test_winrm_credentials(self, parser):
        args = parser.parse_args([
            "windows", "-r", "10.0.0.1",
            "--win-user", "admin", "--win-password", "P@ss",
            "--win-domain", "CORP", "--win-ssl",
        ])
        assert args.win_user == "admin"
        assert args.win_domain == "CORP"
        assert args.win_ssl is True

    def test_snmp_credentials(self, parser):
        args = parser.parse_args([
            "cisco", "-r", "10.0.0.1",
            "--snmp-community", "private",
            "--enable-password", "enable123",
        ])
        assert args.snmp_community == "private"
        assert args.enable_password == "enable123"

    def test_db_credentials(self, parser):
        args = parser.parse_args([
            "database", "-r", "10.0.0.1",
            "--db-user", "sys", "--db-password", "oracle",
            "--db-port", "1521", "--db-sid", "ORCL",
        ])
        assert args.db_user == "sys"
        assert args.db_port == 1521
        assert args.db_sid == "ORCL"

    # ── Output flags ──────────────────────────────────────────────────

    def test_output_flags(self, parser):
        args = parser.parse_args([
            "linux", "-r", "10.0.0.1",
            "--json", "out.json", "--html", "out.html", "--csv", "out.csv",
        ])
        assert args.json_file == "out.json"
        assert args.html_file == "out.html"
        assert args.csv_file == "out.csv"

    def test_severity_filter(self, parser):
        args = parser.parse_args([
            "linux", "-r", "10.0.0.1", "--severity", "HIGH",
        ])
        assert args.severity == "HIGH"

    def test_default_severity(self, parser):
        args = parser.parse_args(["linux", "-r", "10.0.0.1"])
        assert args.severity == "LOW"

    def test_verbose_flag(self, parser):
        args = parser.parse_args(["linux", "-r", "10.0.0.1", "-v"])
        assert args.verbose is True

    def test_scan_options(self, parser):
        args = parser.parse_args([
            "auto", "-r", "10.0.0.0/24",
            "--timeout", "60", "--threads", "20", "--no-discovery",
        ])
        assert args.timeout == 60
        assert args.threads == 20
        assert args.no_discovery is True

    # ── CVE sub-commands ──────────────────────────────────────────────

    def test_cve_sync(self, parser):
        args = parser.parse_args([
            "cve-sync", "--api-key", "abc123", "--since", "2020",
        ])
        assert args.command == "cve-sync"
        assert args.api_key == "abc123"
        assert args.since == 2020

    def test_cve_sync_incremental(self, parser):
        args = parser.parse_args(["cve-sync", "--incremental"])
        assert args.incremental is True

    def test_cve_import(self, parser):
        args = parser.parse_args(["cve-import", "--seed-dir", "/tmp/seeds"])
        assert args.command == "cve-import"
        assert args.seed_dir == "/tmp/seeds"

    def test_cve_stats(self, parser):
        args = parser.parse_args(["cve-stats"])
        assert args.command == "cve-stats"
