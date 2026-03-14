"""Tests for the Palo Alto NGFW / Panorama scanner."""

import xml.etree.ElementTree as ET

from vulnerability_management.core.credential_manager import CredentialManager
from vulnerability_management.scanners.paloalto_scanner import (
    HIGH_RISK_DOH_APPS,
    HIGH_RISK_P2P_APPS,
    HIGH_RISK_REMOTE_APPS,
    HIGH_RISK_TUNNEL_APPS,
    HIGH_RISK_TUNNEL_SSH_APPS,
    PANOS_CVE_DATABASE,
    PaloAltoScanner,
)


def _make_scanner(**kwargs):
    creds = CredentialManager()
    creds.set_web(api_key="dummy-api-key")
    return PaloAltoScanner(target="10.0.0.1", credentials=creds, **kwargs)


def _set_config(scanner, xml_str):
    """Inject parsed XML as config root so checks can run without API calls."""
    scanner._config_root = ET.fromstring(xml_str)


class TestPANOSCVEDatabase:
    def test_cve_count(self):
        assert len(PANOS_CVE_DATABASE) == 20

    def test_all_have_required_fields(self):
        for entry in PANOS_CVE_DATABASE:
            assert "id" in entry
            assert "cve" in entry
            assert "severity" in entry
            assert "name" in entry
            assert "affected_branches" in entry
            assert entry["id"].startswith("PAN-CVE-")

    def test_severities_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for entry in PANOS_CVE_DATABASE:
            assert entry["severity"] in valid

    def test_expedition_cves_have_no_branches(self):
        expedition = [e for e in PANOS_CVE_DATABASE if not e["affected_branches"]]
        assert len(expedition) == 3  # CVE-006, 007, 008


class TestHighRiskAppSets:
    def test_tunnel_apps_not_empty(self):
        assert len(HIGH_RISK_TUNNEL_APPS) > 0

    def test_remote_apps_not_empty(self):
        assert len(HIGH_RISK_REMOTE_APPS) > 0

    def test_p2p_apps_not_empty(self):
        assert len(HIGH_RISK_P2P_APPS) > 0

    def test_doh_apps_not_empty(self):
        assert len(HIGH_RISK_DOH_APPS) > 0

    def test_ssh_tunnel_apps_not_empty(self):
        assert len(HIGH_RISK_TUNNEL_SSH_APPS) > 0


class TestPaloAltoScannerInit:
    def test_creates_instance(self):
        scanner = _make_scanner()
        assert scanner.host == "10.0.0.1"
        assert scanner.TARGET_TYPE == "paloalto"

    def test_scanner_name(self):
        scanner = _make_scanner()
        assert "Palo Alto" in scanner.SCANNER_NAME

    def test_panorama_flag(self):
        scanner = _make_scanner(panorama=True)
        assert scanner.panorama is True


class TestVersionParsing:
    def test_parse_standard_version(self):
        ver = PaloAltoScanner._parse_ver("10.2.7")
        assert ver == (10, 2, 7)

    def test_parse_hotfix_version(self):
        ver = PaloAltoScanner._parse_ver("10.2.7-h1")
        assert ver == (10, 2, 7)

    def test_parse_candidate_version(self):
        ver = PaloAltoScanner._parse_ver("11.0.3-c1")
        assert ver == (11, 0, 3)

    def test_version_comparison(self):
        assert PaloAltoScanner._parse_ver("10.2.7") < PaloAltoScanner._parse_ver("10.2.10")
        assert PaloAltoScanner._parse_ver("11.0.5") >= PaloAltoScanner._parse_ver("11.0.5")


class TestCVEChecks:
    def test_vulnerable_version_detected(self):
        scanner = _make_scanner()
        scanner.device_info = {"sw-version": "10.2.7"}
        scanner._check_cves()
        rule_ids = [f.rule_id for f in scanner.findings]
        # 10.2.7 < 10.2.10 → PAN-CVE-001 should fire
        assert "PAN-CVE-001" in rule_ids

    def test_fixed_version_not_flagged(self):
        scanner = _make_scanner()
        scanner.device_info = {"sw-version": "11.2.5"}
        scanner._check_cves()
        branch_ids = [f.rule_id for f in scanner.findings
                      if f.file_path.startswith("PAN-OS")]
        # 11.2.5 >= 11.2.4 → PAN-CVE-002 and 003 should NOT fire
        assert "PAN-CVE-002" not in branch_ids
        assert "PAN-CVE-003" not in branch_ids

    def test_expedition_cves_always_reported(self):
        scanner = _make_scanner()
        scanner.device_info = {"sw-version": "11.2.5"}
        scanner._check_cves()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-CVE-006" in rule_ids
        assert "PAN-CVE-007" in rule_ids
        assert "PAN-CVE-008" in rule_ids


class TestSecurityRuleChecks:
    def test_allow_all_rule_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry><vsys><entry name="vsys1">
                <rulebase><security><rules>
                    <entry name="allow-all">
                        <action>allow</action>
                        <from><member>any</member></from>
                        <to><member>any</member></to>
                        <source><member>any</member></source>
                        <destination><member>any</member></destination>
                        <application><member>any</member></application>
                        <service><member>any</member></service>
                    </entry>
                </rules></security></rulebase>
            </entry></vsys></entry></devices>
        </config>""")
        scanner._check_security_rules()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-RULE-001" in rule_ids

    def test_specific_rule_not_flagged_as_allow_all(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry><vsys><entry name="vsys1">
                <rulebase><security><rules>
                    <entry name="web-access">
                        <action>allow</action>
                        <from><member>trust</member></from>
                        <to><member>untrust</member></to>
                        <source><member>10.0.0.0/24</member></source>
                        <destination><member>any</member></destination>
                        <application><member>web-browsing</member></application>
                        <service><member>application-default</member></service>
                        <description>Allow web browsing</description>
                    </entry>
                </rules></security></rulebase>
            </entry></vsys></entry></devices>
        </config>""")
        scanner._check_security_rules()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-RULE-001" not in rule_ids
        assert "PAN-RULE-002" not in rule_ids

    def test_any_application_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry><vsys><entry name="vsys1">
                <rulebase><security><rules>
                    <entry name="broad-rule">
                        <action>allow</action>
                        <from><member>trust</member></from>
                        <to><member>untrust</member></to>
                        <source><member>10.0.0.0/24</member></source>
                        <destination><member>any</member></destination>
                        <application><member>any</member></application>
                        <service><member>any</member></service>
                    </entry>
                </rules></security></rulebase>
            </entry></vsys></entry></devices>
        </config>""")
        scanner._check_security_rules()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-RULE-002" in rule_ids
        assert "PAN-RULE-003" in rule_ids

    def test_disabled_rule_flagged_low(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry><vsys><entry name="vsys1">
                <rulebase><security><rules>
                    <entry name="old-rule">
                        <action>allow</action>
                        <disabled>yes</disabled>
                        <from><member>any</member></from>
                        <to><member>any</member></to>
                        <source><member>any</member></source>
                        <destination><member>any</member></destination>
                        <application><member>any</member></application>
                        <service><member>any</member></service>
                    </entry>
                </rules></security></rulebase>
            </entry></vsys></entry></devices>
        </config>""")
        scanner._check_security_rules()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-RULE-008" in rule_ids
        # Should NOT flag as allow-all since it's disabled
        assert "PAN-RULE-001" not in rule_ids

    def test_no_description_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry><vsys><entry name="vsys1">
                <rulebase><security><rules>
                    <entry name="no-desc-rule">
                        <action>allow</action>
                        <from><member>trust</member></from>
                        <to><member>untrust</member></to>
                        <source><member>10.0.0.0/8</member></source>
                        <destination><member>any</member></destination>
                        <application><member>web-browsing</member></application>
                        <service><member>application-default</member></service>
                    </entry>
                </rules></security></rulebase>
            </entry></vsys></entry></devices>
        </config>""")
        scanner._check_security_rules()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-RULE-009" in rule_ids


class TestSecurityProfileChecks:
    def test_no_profiles_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry><vsys><entry name="vsys1">
                <rulebase><security><rules>
                    <entry name="no-profiles">
                        <action>allow</action>
                        <from><member>trust</member></from>
                        <to><member>untrust</member></to>
                        <source><member>any</member></source>
                        <destination><member>any</member></destination>
                        <application><member>web-browsing</member></application>
                        <service><member>application-default</member></service>
                    </entry>
                </rules></security></rulebase>
            </entry></vsys></entry></devices>
        </config>""")
        scanner._check_security_profiles()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-PROF-007" in rule_ids

    def test_group_profile_not_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry><vsys><entry name="vsys1">
                <rulebase><security><rules>
                    <entry name="with-group">
                        <action>allow</action>
                        <from><member>trust</member></from>
                        <to><member>untrust</member></to>
                        <source><member>any</member></source>
                        <destination><member>any</member></destination>
                        <application><member>web-browsing</member></application>
                        <service><member>application-default</member></service>
                        <profile-setting>
                            <group><member>strict</member></group>
                        </profile-setting>
                    </entry>
                </rules></security></rulebase>
            </entry></vsys></entry></devices>
        </config>""")
        scanner._check_security_profiles()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-PROF-007" not in rule_ids


class TestManagementChecks:
    def test_http_enabled_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry>
                <network><interface-management-profile>
                    <entry name="mgmt-profile">
                        <http>yes</http>
                    </entry>
                </interface-management-profile></network>
                <deviceconfig><setting><management>
                    <admin-lockout>
                        <failed-attempts>5</failed-attempts>
                        <lockout-time>30</lockout-time>
                    </admin-lockout>
                    <password-complexity>
                        <enabled>yes</enabled>
                        <minimum-length>12</minimum-length>
                    </password-complexity>
                    <idle-timeout>15</idle-timeout>
                </management></setting></deviceconfig>
            </entry></devices>
        </config>""")
        scanner._check_management()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-MGMT-001" in rule_ids

    def test_telnet_enabled_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry>
                <network><interface-management-profile>
                    <entry name="mgmt-profile">
                        <telnet>yes</telnet>
                    </entry>
                </interface-management-profile></network>
                <deviceconfig><setting><management>
                    <admin-lockout>
                        <failed-attempts>5</failed-attempts>
                        <lockout-time>30</lockout-time>
                    </admin-lockout>
                    <password-complexity>
                        <enabled>yes</enabled>
                        <minimum-length>12</minimum-length>
                    </password-complexity>
                    <idle-timeout>15</idle-timeout>
                </management></setting></deviceconfig>
            </entry></devices>
        </config>""")
        scanner._check_management()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-MGMT-002" in rule_ids

    def test_no_lockout_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry>
                <deviceconfig><setting><management>
                    <password-complexity>
                        <enabled>yes</enabled>
                        <minimum-length>12</minimum-length>
                    </password-complexity>
                    <idle-timeout>15</idle-timeout>
                </management></setting></deviceconfig>
            </entry></devices>
        </config>""")
        scanner._check_management()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-MGMT-004" in rule_ids


class TestZoneProtectionChecks:
    def test_zone_without_protection_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry><vsys><entry name="vsys1">
                <zone><entry name="trust">
                    <network><layer3><member>ethernet1/1</member></layer3></network>
                </entry></zone>
            </entry></vsys></entry></devices>
        </config>""")
        scanner._check_zone_protection()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-ZONE-001" in rule_ids


class TestDynamicUpdateChecks:
    def test_no_updates_scheduled_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry>
                <deviceconfig><system></system></deviceconfig>
            </entry></devices>
        </config>""")
        scanner._check_dynamic_updates()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-UPDATE-001" in rule_ids
        assert "PAN-UPDATE-002" in rule_ids
        assert "PAN-UPDATE-003" in rule_ids


class TestHAChecks:
    def test_no_ha_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry></entry></devices>
        </config>""")
        scanner._check_ha()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-HA-001" in rule_ids

    def test_ha_enabled_link_monitoring_missing(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry>
                <high-availability>
                    <enabled>yes</enabled>
                    <group><entry name="1"><mode><active-passive></active-passive></mode></entry></group>
                </high-availability>
            </entry></devices>
        </config>""")
        scanner._check_ha()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-HA-001" not in rule_ids
        assert "PAN-HA-002" in rule_ids
        assert "PAN-HA-003" in rule_ids


class TestDecryptionChecks:
    def test_no_decryption_flagged(self):
        scanner = _make_scanner()
        _set_config(scanner, """<config>
            <devices><entry><vsys><entry name="vsys1">
                <rulebase></rulebase>
            </entry></vsys></entry></devices>
        </config>""")
        scanner._check_decryption()
        rule_ids = [f.rule_id for f in scanner.findings]
        assert "PAN-DECRYPT-001" in rule_ids


class TestXMLHelpers:
    def test_find_text_default(self):
        scanner = _make_scanner()
        _set_config(scanner, "<config><a>hello</a></config>")
        assert scanner._find_text(".//a") == "hello"
        assert scanner._find_text(".//nonexistent", "fallback") == "fallback"

    def test_get_member_list(self):
        scanner = _make_scanner()
        xml = ET.fromstring("<parent><items><member>a</member><member>b</member></items></parent>")
        result = scanner._get_member_list(xml, "items")
        assert result == ["a", "b"]

    def test_get_member_list_empty(self):
        scanner = _make_scanner()
        result = scanner._get_member_list(None, "items")
        assert result == []

    def test_get_entry_name(self):
        scanner = _make_scanner()
        el = ET.fromstring('<entry name="test-rule"/>')
        assert scanner._get_entry_name(el) == "test-rule"

    def test_get_entry_name_missing(self):
        scanner = _make_scanner()
        el = ET.fromstring("<entry/>")
        assert scanner._get_entry_name(el) == "(unnamed)"
