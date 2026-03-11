"""Shared fixtures for SkyHigh Scanner test suite."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

# Project root and data directories
PROJECT_ROOT = Path(__file__).parent.parent
SEED_DIR = PROJECT_ROOT / "skyhigh_scanner" / "cve_data" / "seed"
BENCHMARK_DIR = PROJECT_ROOT / "skyhigh_scanner" / "benchmarks"


@pytest.fixture
def sample_finding():
    """Return a minimal Finding instance for testing."""
    from skyhigh_scanner.core.finding import Finding

    return Finding(
        rule_id="TEST-001",
        name="Test Finding",
        category="Test",
        severity="HIGH",
        file_path="192.168.1.1",
        line_num=0,
        line_content="test=true",
        description="A test finding.",
        recommendation="Fix it.",
        cwe="CWE-200",
        cve="CVE-2024-99999",
        target_type="generic",
        cvss=7.5,
        cisa_kev=True,
    )


@pytest.fixture
def sample_findings():
    """Return a list of findings across severities."""
    from skyhigh_scanner.core.finding import Finding

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    findings = []
    for i, sev in enumerate(severities, 1):
        findings.append(Finding(
            rule_id=f"TEST-{i:03d}",
            name=f"{sev.title()} Finding",
            category="Test",
            severity=sev,
            file_path=f"10.0.0.{i}",
            line_num=0,
            line_content=f"test_{sev.lower()}=true",
            description=f"A {sev.lower()} severity test finding.",
            recommendation="Apply patch.",
        ))
    return findings


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def tmp_cve_db(tmp_dir):
    """Provide a path for a temporary CVE SQLite database."""
    return str(tmp_dir / "test_cve.db")


@pytest.fixture
def mini_seed_file(tmp_dir):
    """Create a minimal seed JSON file for import testing."""
    seed = [
        {
            "cve_id": "CVE-2024-00001",
            "platform": "test_platform",
            "severity": "HIGH",
            "cvss_v3": 8.1,
            "cwe": "CWE-79",
            "published": "2024-01-15",
            "name": "Test XSS Vulnerability",
            "description": "A test XSS vulnerability.",
            "recommendation": "Update to v2.0.",
            "cisa_kev": True,
            "epss_score": 0.85,
            "affected": ">=1.0,<2.0",
        },
        {
            "cve_id": "CVE-2024-00002",
            "platform": "test_platform",
            "severity": "CRITICAL",
            "cvss_v3": 9.8,
            "cwe": "CWE-89",
            "published": "2024-03-20",
            "name": "Test SQL Injection",
            "description": "A test SQL injection.",
            "recommendation": "Update to v3.0.",
            "cisa_kev": False,
            "epss_score": 0.45,
            "affected": ">=1.0,<3.0",
        },
    ]
    path = tmp_dir / "test_seed.json"
    path.write_text(json.dumps(seed, indent=2))
    return path


@pytest.fixture
def mini_seed_dir(tmp_dir, mini_seed_file):
    """Return the directory containing the mini seed file."""
    return tmp_dir


@pytest.fixture
def credential_file(tmp_dir):
    """Create a temporary credentials JSON file."""
    creds = {
        "ssh": {"username": "admin", "password": "s3cret", "port": 22},
        "winrm": {"username": "admin", "password": "P@ssw0rd", "domain": "CORP"},
        "snmp": {"community": "private"},
        "enable": {"password": "en@ble"},
        "web": {"username": "api_user", "api_key": "abc123"},
        "db": {"username": "dba", "password": "ora123", "port": 1521, "sid": "ORCL"},
    }
    path = tmp_dir / "creds.json"
    path.write_text(json.dumps(creds, indent=2))
    return str(path)
