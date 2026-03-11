"""
Configuration file loader for SkyHigh Scanner.

Supports YAML (.yml/.yaml) and TOML (.toml) config files.
Config file search order:
  1. --config CLI flag
  2. ./skyhigh-scanner.yml (or .yaml / .toml)
  3. ~/.skyhigh-scanner.yml (or .yaml / .toml)

Config keys map directly to CLI argument names (snake_case).
CLI arguments always override config file values.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

# Config file names searched in order
_CONFIG_NAMES = [
    "skyhigh-scanner.yml",
    "skyhigh-scanner.yaml",
    "skyhigh-scanner.toml",
    ".skyhigh-scanner.yml",
    ".skyhigh-scanner.yaml",
    ".skyhigh-scanner.toml",
]

# Keys allowed in config (prevents typos from silently being ignored)
_VALID_KEYS = frozenset({
    # Target
    "ip_range", "target", "max_hosts",
    # Scan options
    "profile", "severity", "verbose", "timeout", "threads",
    "no_discovery", "compliance",
    # SSH
    "ssh_user", "ssh_password", "ssh_key", "ssh_port",
    # Windows
    "win_user", "win_password", "win_domain", "win_port", "win_ssl",
    # SNMP
    "snmp_community", "snmp_v3_user", "snmp_v3_auth", "snmp_v3_priv",
    # Cisco
    "enable_password",
    # Web
    "web_user", "web_password", "web_api_key",
    # Database
    "db_user", "db_password", "db_port", "db_sid", "db_name",
    # Credentials
    "credentials_file",
    # Output
    "json_file", "html_file", "csv_file", "pdf_file", "sarif_file",
    # Plugin
    "plugin_dir",
})


def find_config(explicit_path: Optional[str] = None) -> Optional[Path]:
    """Find a config file in standard locations.

    Args:
        explicit_path: Path provided via --config CLI flag.

    Returns:
        Path to config file or None.
    """
    if explicit_path:
        p = Path(explicit_path)
        if p.is_file():
            return p
        return None

    # Search current directory, then home directory
    search_dirs = [Path.cwd()]
    home = Path.home()
    if home != Path.cwd():
        search_dirs.append(home)

    for d in search_dirs:
        for name in _CONFIG_NAMES:
            candidate = d / name
            if candidate.is_file():
                return candidate

    return None


def load_config(path: Path) -> Dict[str, Any]:
    """Load and validate a config file.

    Args:
        path: Path to YAML or TOML config file.

    Returns:
        Dict of configuration key-value pairs.

    Raises:
        ValueError: If file format is unsupported or contains invalid keys.
    """
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")

    if suffix in (".yml", ".yaml"):
        data = _parse_yaml(text)
    elif suffix == ".toml":
        data = _parse_toml(text)
    else:
        raise ValueError(f"Unsupported config format: {suffix}")

    if not isinstance(data, dict):
        raise ValueError(f"Config file must be a mapping, got {type(data).__name__}")

    # Validate keys
    unknown = set(data.keys()) - _VALID_KEYS
    if unknown:
        raise ValueError(
            f"Unknown config keys: {', '.join(sorted(unknown))}. "
            f"Valid keys: {', '.join(sorted(_VALID_KEYS))}"
        )

    return data


def merge_config_into_args(config: Dict[str, Any], args) -> None:
    """Apply config values to argparse namespace, without overriding CLI values.

    Only sets values where the argparse attribute is None or at its default.
    CLI arguments always take priority.
    """
    for key, value in config.items():
        # Only set if not explicitly provided on CLI
        current = getattr(args, key, None)
        if current is None or (isinstance(current, bool) and not current):
            setattr(args, key, value)


def _parse_yaml(text: str) -> dict:
    """Parse YAML text using PyYAML (safe_load) or basic fallback."""
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except ImportError:
        # Basic fallback parser for simple key: value YAML
        return _parse_simple_yaml(text)


def _parse_simple_yaml(text: str) -> dict:
    """Minimal YAML parser for flat key: value files (no PyYAML needed)."""
    result: Dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        # Strip quotes
        if (val.startswith('"') and val.endswith('"')) or \
           (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        # Type coercion
        if val.lower() in ("true", "yes"):
            result[key] = True
        elif val.lower() in ("false", "no"):
            result[key] = False
        elif val.isdigit():
            result[key] = int(val)
        elif val == "":
            result[key] = None
        else:
            try:
                result[key] = float(val)
            except ValueError:
                result[key] = val
    return result


def _parse_toml(text: str) -> dict:
    """Parse TOML text using tomllib (3.11+) or tomli."""
    try:
        import tomllib
        return tomllib.loads(text)
    except ImportError:
        pass
    try:
        import tomli
        return tomli.loads(text)
    except ImportError:
        raise ImportError(
            "TOML config requires Python >= 3.11 or 'pip install tomli'"
        )
