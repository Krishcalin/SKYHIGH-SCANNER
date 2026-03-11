"""Tests for incremental CVE sync functionality."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from skyhigh_scanner.core.cve_database import CVEDatabase

try:
    import requests as _requests  # noqa: F401
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── CLI: --incremental and --platform flags ───────────────────────────

class TestCliIncrementalFlags:
    def test_incremental_flag_parses(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["cve-sync", "--incremental"])
        assert args.incremental is True
        assert args.command == "cve-sync"

    def test_platform_filter_parses(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["cve-sync", "--platform", "nginx", "tomcat"])
        assert args.platform == ["nginx", "tomcat"]

    def test_incremental_with_platform(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["cve-sync", "--incremental", "--platform", "apache_httpd"])
        assert args.incremental is True
        assert args.platform == ["apache_httpd"]

    def test_platform_default_none(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["cve-sync"])
        assert args.platform is None


# ── CVESync helper methods ────────────────────────────────────────────

@pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
class TestDateWindows:
    def _make_sync(self, tmp_cve_db):
        from skyhigh_scanner.core.cve_sync import CVESync
        db = CVEDatabase(db_path=tmp_cve_db)
        db.open()
        sync = CVESync(db, verbose=False)
        return sync, db

    def test_single_window_short_range(self, tmp_cve_db):
        sync, db = self._make_sync(tmp_cve_db)
        try:
            start = datetime(2025, 1, 1, tzinfo=timezone.utc)
            end = datetime(2025, 2, 1, tzinfo=timezone.utc)
            windows = sync._build_date_windows(start, end)
            assert len(windows) == 1
            assert windows[0] == (start, end)
        finally:
            db.close()

    def test_multiple_windows_long_range(self, tmp_cve_db):
        sync, db = self._make_sync(tmp_cve_db)
        try:
            start = datetime(2024, 1, 1, tzinfo=timezone.utc)
            end = datetime(2025, 1, 1, tzinfo=timezone.utc)  # 366 days
            windows = sync._build_date_windows(start, end)
            # 366 / 120 = 3.05 → 4 windows
            assert len(windows) == 4
            # First window is exactly 120 days
            assert windows[0][1] - windows[0][0] == timedelta(days=120)
            # Last window ends at 'end'
            assert windows[-1][1] == end
        finally:
            db.close()

    def test_exact_120_day_range(self, tmp_cve_db):
        sync, db = self._make_sync(tmp_cve_db)
        try:
            start = datetime(2025, 1, 1, tzinfo=timezone.utc)
            end = start + timedelta(days=120)
            windows = sync._build_date_windows(start, end)
            assert len(windows) == 1
        finally:
            db.close()

    def test_zero_range(self, tmp_cve_db):
        sync, db = self._make_sync(tmp_cve_db)
        try:
            now = datetime(2025, 3, 1, tzinfo=timezone.utc)
            windows = sync._build_date_windows(now, now)
            assert len(windows) == 0
        finally:
            db.close()


class TestParseIso:
    """Test _parse_iso — static method, no requests needed."""

    @pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
    def test_parse_with_timezone(self):
        from skyhigh_scanner.core.cve_sync import CVESync
        dt = CVESync._parse_iso("2025-03-01T12:00:00+00:00")
        assert dt is not None
        assert dt.tzinfo is not None

    @pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
    def test_parse_without_timezone(self):
        from skyhigh_scanner.core.cve_sync import CVESync
        dt = CVESync._parse_iso("2025-03-01T12:00:00")
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    @pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
    def test_parse_invalid(self):
        from skyhigh_scanner.core.cve_sync import CVESync
        assert CVESync._parse_iso("not-a-date") is None
        assert CVESync._parse_iso("") is None


@pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
class TestResolvePlatforms:
    def test_resolve_all(self, tmp_cve_db):
        from skyhigh_scanner.core.cve_sync import CVESync, CPE_QUERIES
        db = CVEDatabase(db_path=tmp_cve_db)
        db.open()
        try:
            sync = CVESync(db, verbose=False)
            result = sync._resolve_platforms(None)
            assert len(result) == len(CPE_QUERIES)
        finally:
            db.close()

    def test_resolve_specific(self, tmp_cve_db):
        from skyhigh_scanner.core.cve_sync import CVESync
        db = CVEDatabase(db_path=tmp_cve_db)
        db.open()
        try:
            sync = CVESync(db, verbose=False)
            result = sync._resolve_platforms(["nginx", "tomcat"])
            assert len(result) == 2
            assert result[0][0] == "nginx"
            assert result[1][0] == "tomcat"
        finally:
            db.close()

    def test_resolve_unknown_skipped(self, tmp_cve_db, capsys):
        from skyhigh_scanner.core.cve_sync import CVESync
        db = CVEDatabase(db_path=tmp_cve_db)
        db.open()
        try:
            sync = CVESync(db, verbose=False)
            result = sync._resolve_platforms(["nginx", "nonexistent_platform"])
            assert len(result) == 1
            assert result[0][0] == "nginx"
        finally:
            db.close()


# ── Sync metadata persistence ─────────────────────────────────────────

@pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
class TestSyncMetadata:
    def test_save_and_get_sync_ts(self, tmp_cve_db):
        from skyhigh_scanner.core.cve_sync import CVESync
        with CVEDatabase(db_path=tmp_cve_db) as db:
            sync = CVESync(db, verbose=False)
            sync._save_sync_ts("test_key")
            ts = sync._get_sync_ts("test_key")
            assert ts is not None
            assert "T" in ts  # ISO format

    def test_get_nonexistent_ts(self, tmp_cve_db):
        from skyhigh_scanner.core.cve_sync import CVESync
        with CVEDatabase(db_path=tmp_cve_db) as db:
            sync = CVESync(db, verbose=False)
            assert sync._get_sync_ts("nonexistent") is None

    def test_get_last_sync(self, tmp_cve_db):
        from skyhigh_scanner.core.cve_sync import CVESync
        with CVEDatabase(db_path=tmp_cve_db) as db:
            sync = CVESync(db, verbose=False)
            assert sync.get_last_sync() is None
            sync._save_sync_ts("last_full_sync")
            assert sync.get_last_sync() is not None

    def test_platform_sync_ts(self, tmp_cve_db):
        from skyhigh_scanner.core.cve_sync import CVESync
        with CVEDatabase(db_path=tmp_cve_db) as db:
            sync = CVESync(db, verbose=False)
            sync._save_platform_sync_ts("nginx")
            ts = sync.get_platform_last_sync("nginx")
            assert ts is not None

    def test_stats_include_sync_metadata(self, tmp_cve_db, mini_seed_dir):
        from skyhigh_scanner.core.cve_sync import CVESync
        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            sync = CVESync(db, verbose=False)
            sync._save_sync_ts("last_full_sync")
            stats = db.stats()
            assert "sync_metadata" in stats
            assert "last_full_sync" in stats["sync_metadata"]


# ── Incremental sync requires previous sync ──────────────────────────

@pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
class TestIncrementalNoHistory:
    def test_incremental_without_prior_sync_returns_empty(self, tmp_cve_db, capsys):
        from skyhigh_scanner.core.cve_sync import CVESync
        with CVEDatabase(db_path=tmp_cve_db) as db:
            sync = CVESync(db, verbose=False)
            result = sync.sync_incremental()
        assert result == {}


# ── Incremental sync with mocked NVD API ─────────────────────────────

@pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
class TestIncrementalSyncMocked:
    def test_incremental_sync_calls_modified_endpoint(self, tmp_cve_db, mini_seed_dir):
        from skyhigh_scanner.core.cve_sync import CVESync

        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            sync = CVESync(db, verbose=False)

            # Set a previous sync timestamp
            sync._save_sync_ts("last_full_sync")

            # Mock NVD API to return empty results
            mock_nvd = MagicMock()
            mock_nvd.status_code = 200
            mock_nvd.json.return_value = {
                "totalResults": 0,
                "vulnerabilities": [],
            }
            mock_nvd.raise_for_status = MagicMock()

            # Mock CISA KEV
            mock_kev = MagicMock()
            mock_kev.status_code = 200
            mock_kev.json.return_value = {"vulnerabilities": []}
            mock_kev.raise_for_status = MagicMock()

            # Mock EPSS
            mock_epss = MagicMock()
            mock_epss.status_code = 200
            mock_epss.json.return_value = {"data": []}
            mock_epss.raise_for_status = MagicMock()

            def side_effect(url, **kwargs):
                if "first.org" in url:
                    return mock_epss
                if "cisa.gov" in url:
                    return mock_kev
                return mock_nvd

            with patch.object(sync._session, "get", side_effect=side_effect):
                results = sync.sync_incremental(platforms=["nginx"])

            assert "nginx" in results
            assert "_cisa_kev_flagged" in results
            assert "_epss_enriched" in results

    def test_incremental_sync_processes_modified_cves(self, tmp_cve_db, mini_seed_dir):
        from skyhigh_scanner.core.cve_sync import CVESync

        with CVEDatabase(db_path=tmp_cve_db) as db:
            db.import_seed(str(mini_seed_dir))
            sync = CVESync(db, verbose=False)
            sync._save_sync_ts("last_full_sync")

            # NVD response with one updated CVE
            mock_nvd = MagicMock()
            mock_nvd.status_code = 200
            mock_nvd.json.return_value = {
                "totalResults": 1,
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-2025-99999",
                        "metrics": {"cvssMetricV31": [{
                            "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}
                        }]},
                        "weaknesses": [{"description": [{"value": "CWE-89"}]}],
                        "descriptions": [{"lang": "en", "value": "Test vuln"}],
                        "published": "2025-03-01T00:00:00",
                        "lastModified": "2025-03-10T00:00:00",
                        "configurations": [],
                    }
                }],
            }
            mock_nvd.raise_for_status = MagicMock()

            mock_kev = MagicMock()
            mock_kev.status_code = 200
            mock_kev.json.return_value = {"vulnerabilities": []}
            mock_kev.raise_for_status = MagicMock()

            mock_epss = MagicMock()
            mock_epss.status_code = 200
            mock_epss.json.return_value = {"data": []}
            mock_epss.raise_for_status = MagicMock()

            def side_effect(url, **kwargs):
                if "first.org" in url:
                    return mock_epss
                if "cisa.gov" in url:
                    return mock_kev
                return mock_nvd

            with patch.object(sync._session, "get", side_effect=side_effect):
                results = sync.sync_incremental(platforms=["nginx"])

            assert results["nginx"] == 1

            # Verify CVE was inserted
            cur = db.conn.cursor()
            cur.execute("SELECT * FROM cves WHERE cve_id = 'CVE-2025-99999'")
            row = cur.fetchone()
            assert row is not None
            assert row["severity"] == "CRITICAL"


# ── Full sync with --platform filter ─────────────────────────────────

@pytest.mark.skipif(not HAS_REQUESTS, reason="requests not installed")
class TestPlatformFilter:
    def test_sync_all_with_platform_filter(self, tmp_cve_db):
        from skyhigh_scanner.core.cve_sync import CVESync

        with CVEDatabase(db_path=tmp_cve_db) as db:
            sync = CVESync(db, verbose=False)

            mock_nvd = MagicMock()
            mock_nvd.status_code = 200
            mock_nvd.json.return_value = {"totalResults": 0, "vulnerabilities": []}
            mock_nvd.raise_for_status = MagicMock()

            mock_kev = MagicMock()
            mock_kev.status_code = 200
            mock_kev.json.return_value = {"vulnerabilities": []}
            mock_kev.raise_for_status = MagicMock()

            mock_epss = MagicMock()
            mock_epss.status_code = 200
            mock_epss.json.return_value = {"data": []}
            mock_epss.raise_for_status = MagicMock()

            def side_effect(url, **kwargs):
                if "first.org" in url:
                    return mock_epss
                if "cisa.gov" in url:
                    return mock_kev
                return mock_nvd

            with patch.object(sync._session, "get", side_effect=side_effect):
                results = sync.sync_all(platforms=["nginx", "tomcat"])

            # Only the 2 specified platforms should appear
            platform_keys = [k for k in results if not k.startswith("_")]
            assert set(platform_keys) == {"nginx", "tomcat"}
