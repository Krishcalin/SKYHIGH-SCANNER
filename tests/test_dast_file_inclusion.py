"""Tests for DAST file_inclusion check module."""

from __future__ import annotations

from unittest.mock import MagicMock

from skyhigh_scanner.dast.checks.file_inclusion import run_checks
from skyhigh_scanner.dast.crawler import SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _mock_client(get_text: str = "", get_status: int = 200) -> MagicMock:
    client = MagicMock()

    resp = MagicMock()
    resp.text = get_text
    resp.status_code = get_status
    resp.headers = {}
    client.get.return_value = resp

    client.probe_path.return_value = (404, "")

    return client


def _url_sitemap(*urls: str) -> SiteMap:
    sm = SiteMap()
    sm.urls = set(urls)
    return sm


def _empty_sitemap() -> SiteMap:
    return SiteMap()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestLFIParams:
    """DAST-FI-001: Local File Inclusion."""

    def test_lfi_passwd_read(self):
        passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        client = _mock_client(get_text=passwd)
        sm = _url_sitemap("https://example.com/view?file=readme.txt")
        findings = run_checks(client, "https://example.com", sm)
        fi_001 = [f for f in findings if f.rule_id == "DAST-FI-001"]
        assert len(fi_001) == 1
        assert fi_001[0].severity == "CRITICAL"

    def test_no_file_param_no_test(self):
        client = _mock_client()
        sm = _url_sitemap("https://example.com/page?id=1")
        findings = run_checks(client, "https://example.com", sm)
        fi_001 = [f for f in findings if f.rule_id == "DAST-FI-001"]
        assert len(fi_001) == 0

    def test_lfi_no_sensitive_content(self):
        client = _mock_client(get_text="<html>Normal page</html>")
        sm = _url_sitemap("https://example.com/view?file=readme.txt")
        findings = run_checks(client, "https://example.com", sm)
        fi_001 = [f for f in findings if f.rule_id == "DAST-FI-001"]
        assert len(fi_001) == 0


class TestLFIEncoded:
    """DAST-FI-002: LFI with encoding bypass."""

    def test_encoded_lfi(self):
        passwd = "root:x:0:0:root:/root:/bin/bash"
        client = _mock_client(get_text=passwd)
        sm = _url_sitemap("https://example.com/include?path=header.php")
        findings = run_checks(client, "https://example.com", sm)
        fi_002 = [f for f in findings if f.rule_id == "DAST-FI-002"]
        assert len(fi_002) == 1


class TestPathTraversal:
    """DAST-FI-003: Path traversal in all parameters."""

    def test_traversal_detected(self):
        passwd = "root:x:0:0:root:/root:/bin/bash"
        client = _mock_client(get_text=passwd)
        sm = _url_sitemap("https://example.com/download?name=report.pdf")
        findings = run_checks(client, "https://example.com", sm)
        fi_003 = [f for f in findings if f.rule_id == "DAST-FI-003"]
        assert len(fi_003) == 1

    def test_no_traversal(self):
        client = _mock_client(get_text="PDF content here")
        sm = _url_sitemap("https://example.com/download?name=report.pdf")
        findings = run_checks(client, "https://example.com", sm)
        fi_003 = [f for f in findings if f.rule_id == "DAST-FI-003"]
        assert len(fi_003) == 0


class TestRFI:
    """DAST-FI-004: Remote File Inclusion."""

    def test_rfi_attempt_detected(self):
        client = _mock_client(get_text="Warning: include(): failed to open stream")
        sm = _url_sitemap("https://example.com/view?template=header")
        findings = run_checks(client, "https://example.com", sm)
        fi_004 = [f for f in findings if f.rule_id == "DAST-FI-004"]
        assert len(fi_004) == 1
        assert fi_004[0].severity == "CRITICAL"

    def test_no_rfi(self):
        client = _mock_client(get_text="<html>Normal page</html>")
        sm = _url_sitemap("https://example.com/view?template=header")
        findings = run_checks(client, "https://example.com", sm)
        fi_004 = [f for f in findings if f.rule_id == "DAST-FI-004"]
        assert len(fi_004) == 0


class TestBackupFiles:
    """DAST-FI-005: Backup files accessible."""

    def test_backup_found(self):
        backup_body = (
            "<?php\n$db_host = 'localhost';\n$db_password = 'secret123';\n"
            "$db_name = 'production';\n$db_user = 'root';\n?>"
        )
        def _probe(base, path):
            if base.endswith(".bak"):
                return (200, backup_body)
            return (404, "")
        client = MagicMock()
        client.get.return_value = MagicMock(text="", status_code=200, headers={})
        client.probe_path.side_effect = _probe

        sm = _url_sitemap("https://example.com/config.php")
        findings = run_checks(client, "https://example.com", sm)
        fi_005 = [f for f in findings if f.rule_id == "DAST-FI-005"]
        assert len(fi_005) == 1


class TestRunChecks:
    """Integration tests."""

    def test_all_findings_correct_category(self):
        passwd = "root:x:0:0:root:/root:/bin/bash"
        client = _mock_client(get_text=passwd)
        sm = _url_sitemap("https://example.com/view?file=test")
        findings = run_checks(client, "https://example.com", sm)
        for f in findings:
            assert f.category == "file_inclusion"
            assert f.target_type == "dast"

    def test_empty_sitemap(self):
        client = _mock_client()
        findings = run_checks(client, "https://example.com", _empty_sitemap())
        assert isinstance(findings, list)
