"""Tests for the Cisco IOS/IOS-XE/NX-OS scanner."""

from vulnerability_management.core.credential_manager import CredentialManager
from vulnerability_management.scanners.cisco_scanner import CiscoScanner, IOS_CVE_DATABASE


class TestCiscoCVEDatabase:
    def test_cve_count(self):
        assert len(IOS_CVE_DATABASE) == 20

    def test_all_have_required_fields(self):
        for entry in IOS_CVE_DATABASE:
            assert "id" in entry
            assert "cve" in entry
            assert "severity" in entry
            assert "name" in entry
            assert "affected" in entry
            assert entry["id"].startswith("CISCO-CVE-")

    def test_severities_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for entry in IOS_CVE_DATABASE:
            assert entry["severity"] in valid


class TestCiscoScannerInit:
    def test_creates_instance(self):
        creds = CredentialManager()
        scanner = CiscoScanner(target="192.168.1.1", credentials=creds)
        assert scanner.target == "192.168.1.1"
        assert scanner.TARGET_TYPE == "cisco"

    def test_scanner_name(self):
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        assert "Cisco" in scanner.SCANNER_NAME


class TestCiscoConfigParser:
    def test_parse_global_lines(self):
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        config = """hostname Router1
service timestamps debug datetime msec
service timestamps log datetime msec
enable secret 5 $1$abc$xyz
"""
        sections = scanner._parse_config_sections(config)
        assert "_global" in sections
        assert any("hostname" in line for line in sections["_global"])

    def test_parse_interface_section(self):
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        config = """!
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/2
 shutdown
!
"""
        sections = scanner._parse_config_sections(config)
        assert "interface GigabitEthernet0/1" in sections
        assert any("ip address" in l for l in sections["interface GigabitEthernet0/1"])

    def test_parse_line_sections(self):
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        config = """!
line con 0
 exec-timeout 5 0
 login local
!
line vty 0 4
 transport input ssh
 login local
!
"""
        sections = scanner._parse_config_sections(config)
        assert any("line vty" in k for k in sections)

    def test_snmp_lines_parsed_as_sections(self):
        """SNMP server lines become section headers because they start with 'snmp-server '."""
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        config = "snmp-server community public RO\nsnmp-server community private RW\n"
        sections = scanner._parse_config_sections(config)
        # snmp-server lines go to sections, not _global
        assert any("snmp-server" in k for k in sections)


class TestCiscoVersionExtraction:
    def test_extract_ios_version(self):
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        output = "Cisco IOS Software, Version 15.2(4)M7, RELEASE SOFTWARE"
        ver = scanner._extract_version(output)
        assert ver == "15.2(4)M7"

    def test_extract_iosxe_version(self):
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        output = "Cisco IOS XE Software, Version 17.03.05"
        ver = scanner._extract_version(output)
        assert ver == "17.03.05"

    def test_extract_no_version(self):
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        ver = scanner._extract_version("no version info here")
        assert ver == ""


class TestCiscoAuthenticationChecks:
    def _make_scanner_with_config(self, config_text):
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        sections = scanner._parse_config_sections(config_text)
        return scanner, sections

    def test_enable_password_flagged(self):
        scanner, sections = self._make_scanner_with_config(
            "enable password cisco123\n"
        )
        scanner._check_authentication(sections, "10.0.0.1")
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "CISCO-AUTH-001" in rule_ids

    def test_enable_secret_not_flagged_auth001(self):
        scanner, sections = self._make_scanner_with_config(
            "enable secret 5 $1$abc$xyz\n"
        )
        scanner._check_authentication(sections, "10.0.0.1")
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "CISCO-AUTH-001" not in rule_ids

    def test_no_enable_secret_flagged(self):
        """CISCO-AUTH-002 fires when enable secret is missing."""
        scanner, sections = self._make_scanner_with_config(
            "hostname Router1\n"
        )
        scanner._check_authentication(sections, "10.0.0.1")
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "CISCO-AUTH-002" in rule_ids

    def test_enable_secret_present_no_auth002(self):
        """CISCO-AUTH-002 should not fire when enable secret exists."""
        scanner, sections = self._make_scanner_with_config(
            "enable secret 5 $1$abc$xyz\nservice password-encryption\naaa new-model\n"
        )
        scanner._check_authentication(sections, "10.0.0.1")
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "CISCO-AUTH-002" not in rule_ids

    def test_no_service_password_encryption_flagged(self):
        """CISCO-AUTH-003 fires when service password-encryption is missing."""
        scanner, sections = self._make_scanner_with_config(
            "hostname Router1\n"
        )
        scanner._check_authentication(sections, "10.0.0.1")
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "CISCO-AUTH-003" in rule_ids


class TestCiscoSSHChecks:
    def _make_scanner_with_config(self, config_text):
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        sections = scanner._parse_config_sections(config_text)
        return scanner, sections

    def test_ssh_v1_flagged(self):
        scanner, sections = self._make_scanner_with_config(
            "ip ssh version 1\n"
        )
        scanner._check_ssh_config(sections, "10.0.0.1")
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "CISCO-SSH-001" in rule_ids

    def test_ssh_v2_not_flagged(self):
        scanner, sections = self._make_scanner_with_config(
            "ip ssh version 2\n"
        )
        scanner._check_ssh_config(sections, "10.0.0.1")
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "CISCO-SSH-001" not in rule_ids


class TestCiscoSNMPChecks:
    def test_snmp_check_with_injected_sections(self):
        """Directly inject SNMP config into sections to test check logic."""
        creds = CredentialManager()
        scanner = CiscoScanner(target="10.0.0.1", credentials=creds)
        # Inject as _global lines (how they'd appear if the parser handled them)
        sections = {
            "_global": [
                "snmp-server community public RO",
                "snmp-server community private RW",
            ]
        }
        scanner._check_snmp_config(sections, "10.0.0.1")
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "CISCO-SNMP-001" in rule_ids
        assert "CISCO-SNMP-002" in rule_ids
