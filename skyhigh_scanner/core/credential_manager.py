"""
Credential management for SkyHigh Scanner.

Handles credential storage, environment variable fallback, and
file-based credential loading. Passwords are never logged or
written to reports.
"""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SSHCredential:
    username: str
    password: Optional[str] = None
    key_file: Optional[str] = None
    port: int = 22


@dataclass
class WinRMCredential:
    username: str
    password: str
    domain: Optional[str] = None
    port: int = 5985
    use_ssl: bool = False


@dataclass
class SNMPCredential:
    community: str = "public"
    v3_user: Optional[str] = None
    v3_auth_key: Optional[str] = None
    v3_priv_key: Optional[str] = None
    port: int = 161


@dataclass
class EnableCredential:
    password: str


@dataclass
class WebCredential:
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None


@dataclass
class DBCredential:
    username: str = ""
    password: str = ""
    port: int = 0
    sid: Optional[str] = None          # Oracle SID/service name
    database: Optional[str] = None     # MySQL/MongoDB database


class CredentialManager:
    """Centralised credential store for all target types."""

    # Environment variable prefixes
    ENV_PREFIX = "SKYHIGH"

    def __init__(self):
        self.ssh: Optional[SSHCredential] = None
        self.winrm: Optional[WinRMCredential] = None
        self.snmp: Optional[SNMPCredential] = None
        self.enable: Optional[EnableCredential] = None
        self.web: Optional[WebCredential] = None
        self.db: Optional[DBCredential] = None

    # ── CLI argument setters ─────────────────────────────────────────
    def set_ssh(self, username: str, password: str = None,
                key_file: str = None, port: int = 22) -> None:
        self.ssh = SSHCredential(username, password, key_file, port)

    def set_winrm(self, username: str, password: str,
                  domain: str = None, port: int = 5985,
                  use_ssl: bool = False) -> None:
        self.winrm = WinRMCredential(username, password, domain, port, use_ssl)

    def set_snmp(self, community: str = "public", v3_user: str = None,
                 v3_auth_key: str = None, v3_priv_key: str = None,
                 port: int = 161) -> None:
        self.snmp = SNMPCredential(community, v3_user, v3_auth_key, v3_priv_key, port)

    def set_enable(self, password: str) -> None:
        self.enable = EnableCredential(password)

    def set_web(self, username: str = None, password: str = None,
                api_key: str = None) -> None:
        self.web = WebCredential(username, password, api_key)

    def set_db(self, username: str, password: str, port: int = 0,
               sid: str = None, database: str = None) -> None:
        self.db = DBCredential(username, password, port, sid, database)

    # ── Environment variable fallback ────────────────────────────────
    def load_from_env(self) -> None:
        """Load credentials from environment variables if not already set."""
        # SSH
        if not self.ssh:
            ssh_user = os.environ.get(f"{self.ENV_PREFIX}_SSH_USERNAME")
            if ssh_user:
                self.ssh = SSHCredential(
                    username=ssh_user,
                    password=os.environ.get(f"{self.ENV_PREFIX}_SSH_PASSWORD"),
                    key_file=os.environ.get(f"{self.ENV_PREFIX}_SSH_KEY"),
                    port=int(os.environ.get(f"{self.ENV_PREFIX}_SSH_PORT", "22")),
                )

        # WinRM
        if not self.winrm:
            win_user = os.environ.get(f"{self.ENV_PREFIX}_WIN_USERNAME")
            if win_user:
                self.winrm = WinRMCredential(
                    username=win_user,
                    password=os.environ.get(f"{self.ENV_PREFIX}_WIN_PASSWORD", ""),
                    domain=os.environ.get(f"{self.ENV_PREFIX}_WIN_DOMAIN"),
                    port=int(os.environ.get(f"{self.ENV_PREFIX}_WIN_PORT", "5985")),
                )

        # SNMP
        if not self.snmp:
            community = os.environ.get(f"{self.ENV_PREFIX}_SNMP_COMMUNITY")
            if community:
                self.snmp = SNMPCredential(
                    community=community,
                    v3_user=os.environ.get(f"{self.ENV_PREFIX}_SNMP_V3_USER"),
                    v3_auth_key=os.environ.get(f"{self.ENV_PREFIX}_SNMP_V3_AUTH"),
                    v3_priv_key=os.environ.get(f"{self.ENV_PREFIX}_SNMP_V3_PRIV"),
                )

        # Enable password
        if not self.enable:
            enable_pw = os.environ.get(f"{self.ENV_PREFIX}_ENABLE_PASSWORD")
            if enable_pw:
                self.enable = EnableCredential(enable_pw)

        # Web
        if not self.web:
            web_user = os.environ.get(f"{self.ENV_PREFIX}_WEB_USERNAME")
            web_key = os.environ.get(f"{self.ENV_PREFIX}_WEB_API_KEY")
            if web_user or web_key:
                self.web = WebCredential(
                    username=web_user,
                    password=os.environ.get(f"{self.ENV_PREFIX}_WEB_PASSWORD"),
                    api_key=web_key,
                )

        # Database
        if not self.db:
            db_user = os.environ.get(f"{self.ENV_PREFIX}_DB_USERNAME")
            if db_user:
                self.db = DBCredential(
                    username=db_user,
                    password=os.environ.get(f"{self.ENV_PREFIX}_DB_PASSWORD", ""),
                    port=int(os.environ.get(f"{self.ENV_PREFIX}_DB_PORT", "0")),
                    sid=os.environ.get(f"{self.ENV_PREFIX}_DB_SID"),
                    database=os.environ.get(f"{self.ENV_PREFIX}_DB_NAME"),
                )

    # ── File-based credential loading ────────────────────────────────
    def load_from_file(self, path: str) -> None:
        """Load credentials from a JSON or YAML file.

        Expected format::

            {
              "ssh": {"username": "admin", "password": "secret"},
              "winrm": {"username": "admin", "password": "P@ss", "domain": "CORP"},
              "snmp": {"community": "private"},
              "enable": {"password": "enable123"},
              "web": {"username": "admin", "password": "secret"},
              "db": {"username": "sys", "password": "oracle", "port": 1521, "sid": "ORCL"}
            }
        """
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        if "ssh" in data and not self.ssh:
            self.ssh = SSHCredential(**data["ssh"])
        if "winrm" in data and not self.winrm:
            self.winrm = WinRMCredential(**data["winrm"])
        if "snmp" in data and not self.snmp:
            self.snmp = SNMPCredential(**data["snmp"])
        if "enable" in data and not self.enable:
            self.enable = EnableCredential(**data["enable"])
        if "web" in data and not self.web:
            self.web = WebCredential(**data["web"])
        if "db" in data and not self.db:
            self.db = DBCredential(**data["db"])

    # ── Utility ──────────────────────────────────────────────────────
    def has_ssh(self) -> bool:
        return self.ssh is not None and bool(self.ssh.username)

    def has_winrm(self) -> bool:
        return self.winrm is not None and bool(self.winrm.username)

    def has_snmp(self) -> bool:
        return self.snmp is not None

    def has_web(self) -> bool:
        return self.web is not None

    def has_db(self) -> bool:
        return self.db is not None and bool(self.db.username)

    def summary(self) -> dict[str, bool]:
        """Return which credential types are configured (no secrets)."""
        return {
            "ssh": self.has_ssh(),
            "winrm": self.has_winrm(),
            "snmp": self.has_snmp(),
            "enable": self.enable is not None,
            "web": self.has_web(),
            "db": self.has_db(),
        }
