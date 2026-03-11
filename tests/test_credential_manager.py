"""Tests for skyhigh_scanner.core.credential_manager."""

import os
from unittest.mock import patch

from skyhigh_scanner.core.credential_manager import (
    CredentialManager,
    DBCredential,
)


class TestCredentialSetters:
    def test_set_ssh(self):
        cm = CredentialManager()
        cm.set_ssh("admin", "pass123", key_file="/tmp/id_rsa", port=2222)
        assert cm.ssh.username == "admin"
        assert cm.ssh.password == "pass123"
        assert cm.ssh.key_file == "/tmp/id_rsa"
        assert cm.ssh.port == 2222

    def test_set_winrm(self):
        cm = CredentialManager()
        cm.set_winrm("admin", "P@ss", domain="CORP", port=5986, use_ssl=True)
        assert cm.winrm.username == "admin"
        assert cm.winrm.domain == "CORP"
        assert cm.winrm.use_ssl is True

    def test_set_snmp(self):
        cm = CredentialManager()
        cm.set_snmp("private", v3_user="snmpuser")
        assert cm.snmp.community == "private"
        assert cm.snmp.v3_user == "snmpuser"

    def test_set_enable(self):
        cm = CredentialManager()
        cm.set_enable("en@ble")
        assert cm.enable.password == "en@ble"

    def test_set_web(self):
        cm = CredentialManager()
        cm.set_web(api_key="key123")
        assert cm.web.api_key == "key123"

    def test_set_db(self):
        cm = CredentialManager()
        cm.set_db("dba", "oracle", port=1521, sid="ORCL")
        assert cm.db.username == "dba"
        assert cm.db.sid == "ORCL"


class TestCredentialHas:
    def test_has_ssh_false(self):
        cm = CredentialManager()
        assert cm.has_ssh() is False

    def test_has_ssh_true(self):
        cm = CredentialManager()
        cm.set_ssh("admin", "pass")
        assert cm.has_ssh() is True

    def test_has_winrm_false(self):
        cm = CredentialManager()
        assert cm.has_winrm() is False

    def test_has_db_requires_username(self):
        cm = CredentialManager()
        cm.db = DBCredential(username="", password="pass")
        assert cm.has_db() is False


class TestCredentialSummary:
    def test_summary_empty(self):
        cm = CredentialManager()
        s = cm.summary()
        assert s["ssh"] is False
        assert s["winrm"] is False
        assert s["snmp"] is False
        assert s["enable"] is False
        assert s["web"] is False
        assert s["db"] is False

    def test_summary_populated(self):
        cm = CredentialManager()
        cm.set_ssh("admin", "pass")
        cm.set_snmp("public")
        s = cm.summary()
        assert s["ssh"] is True
        assert s["snmp"] is True
        assert s["winrm"] is False


class TestCredentialFromFile:
    def test_load_from_file(self, credential_file):
        cm = CredentialManager()
        cm.load_from_file(credential_file)
        assert cm.ssh.username == "admin"
        assert cm.winrm.domain == "CORP"
        assert cm.snmp.community == "private"
        assert cm.enable.password == "en@ble"
        assert cm.web.api_key == "abc123"
        assert cm.db.sid == "ORCL"

    def test_cli_takes_priority_over_file(self, credential_file):
        cm = CredentialManager()
        cm.set_ssh("cli_user", "cli_pass")
        cm.load_from_file(credential_file)
        # CLI value should NOT be overwritten
        assert cm.ssh.username == "cli_user"


class TestCredentialFromEnv:
    @patch.dict(os.environ, {
        "SKYHIGH_SSH_USERNAME": "env_user",
        "SKYHIGH_SSH_PASSWORD": "env_pass",
        "SKYHIGH_SSH_PORT": "2222",
    })
    def test_ssh_from_env(self):
        cm = CredentialManager()
        cm.load_from_env()
        assert cm.ssh.username == "env_user"
        assert cm.ssh.port == 2222

    @patch.dict(os.environ, {"SKYHIGH_SSH_USERNAME": "env_user"})
    def test_cli_takes_priority_over_env(self):
        cm = CredentialManager()
        cm.set_ssh("cli_user", "cli_pass")
        cm.load_from_env()
        assert cm.ssh.username == "cli_user"

    @patch.dict(os.environ, {
        "SKYHIGH_SNMP_COMMUNITY": "env_community",
        "SKYHIGH_ENABLE_PASSWORD": "env_enable",
    })
    def test_snmp_and_enable_from_env(self):
        cm = CredentialManager()
        cm.load_from_env()
        assert cm.snmp.community == "env_community"
        assert cm.enable.password == "env_enable"

    @patch.dict(os.environ, {
        "SKYHIGH_DB_USERNAME": "env_dba",
        "SKYHIGH_DB_PASSWORD": "env_pass",
        "SKYHIGH_DB_PORT": "3306",
        "SKYHIGH_DB_NAME": "mydb",
    })
    def test_db_from_env(self):
        cm = CredentialManager()
        cm.load_from_env()
        assert cm.db.username == "env_dba"
        assert cm.db.port == 3306
        assert cm.db.database == "mydb"
