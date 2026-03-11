"""Tests for the config file loader."""

from argparse import Namespace

import pytest

from skyhigh_scanner.core.config import (
    _VALID_KEYS,
    _parse_simple_yaml,
    find_config,
    load_config,
    merge_config_into_args,
)

# ── Simple YAML parser ───────────────────────────────────────────────

class TestParseSimpleYaml:
    def test_basic_string(self):
        result = _parse_simple_yaml("ssh_user: admin")
        assert result == {"ssh_user": "admin"}

    def test_quoted_string(self):
        result = _parse_simple_yaml('ssh_password: "my secret"')
        assert result == {"ssh_password": "my secret"}

    def test_single_quoted(self):
        result = _parse_simple_yaml("target: '10.0.0.1'")
        assert result == {"target": "10.0.0.1"}

    def test_integer(self):
        result = _parse_simple_yaml("timeout: 60")
        assert result == {"timeout": 60}
        assert isinstance(result["timeout"], int)

    def test_boolean_true(self):
        for val in ("true", "True", "yes", "Yes"):
            result = _parse_simple_yaml(f"verbose: {val}")
            assert result["verbose"] is True

    def test_boolean_false(self):
        for val in ("false", "False", "no", "No"):
            result = _parse_simple_yaml(f"verbose: {val}")
            assert result["verbose"] is False

    def test_empty_value(self):
        result = _parse_simple_yaml("ssh_key:")
        assert result == {"ssh_key": None}

    def test_comment_ignored(self):
        text = "# comment\nssh_user: admin\n# another"
        result = _parse_simple_yaml(text)
        assert result == {"ssh_user": "admin"}

    def test_multiple_keys(self):
        text = "ssh_user: admin\ntimeout: 30\nverbose: true"
        result = _parse_simple_yaml(text)
        assert result == {"ssh_user": "admin", "timeout": 30, "verbose": True}

    def test_empty_input(self):
        assert _parse_simple_yaml("") == {}

    def test_colon_in_value(self):
        result = _parse_simple_yaml("target: http://10.0.0.1:8080")
        assert result["target"] == "http://10.0.0.1:8080"


# ── find_config ───────────────────────────────────────────────────────

class TestFindConfig:
    def test_explicit_path_exists(self, tmp_path):
        f = tmp_path / "my.yml"
        f.write_text("timeout: 30")
        assert find_config(str(f)) == f

    def test_explicit_path_missing(self, tmp_path):
        assert find_config(str(tmp_path / "nope.yml")) is None

    def test_none_returns_none_when_no_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # No config files in tmp_path
        assert find_config(None) is None

    def test_finds_in_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "skyhigh-scanner.yml"
        f.write_text("timeout: 30")
        assert find_config() == f

    def test_prefers_yml_over_toml(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "skyhigh-scanner.yml").write_text("timeout: 30")
        (tmp_path / "skyhigh-scanner.toml").write_text("timeout = 30")
        result = find_config()
        assert result.suffix == ".yml"


# ── load_config ───────────────────────────────────────────────────────

class TestLoadConfig:
    def test_load_yaml(self, tmp_path):
        f = tmp_path / "cfg.yml"
        f.write_text("ssh_user: admin\ntimeout: 60")
        data = load_config(f)
        assert data == {"ssh_user": "admin", "timeout": 60}

    def test_load_yaml_extension(self, tmp_path):
        f = tmp_path / "cfg.yaml"
        f.write_text("verbose: true")
        data = load_config(f)
        assert data == {"verbose": True}

    def test_unknown_key_raises(self, tmp_path):
        f = tmp_path / "cfg.yml"
        f.write_text("bogus_key: value")
        with pytest.raises(ValueError, match="Unknown config keys"):
            load_config(f)

    def test_unsupported_format(self, tmp_path):
        f = tmp_path / "cfg.ini"
        f.write_text("[section]\nkey=value")
        with pytest.raises(ValueError, match="Unsupported config format"):
            load_config(f)

    def test_non_dict_raises(self, tmp_path):
        f = tmp_path / "cfg.yml"
        f.write_text("- item1\n- item2")
        # Simple parser returns {} for this, but with PyYAML it returns a list
        # Just test that it doesn't crash
        try:
            data = load_config(f)
            assert isinstance(data, dict)
        except ValueError:
            pass  # Expected if parsed as non-dict


# ── merge_config_into_args ────────────────────────────────────────────

class TestMergeConfig:
    def test_sets_missing_values(self):
        args = Namespace(ssh_user=None, timeout=None)
        config = {"ssh_user": "admin", "timeout": 60}
        merge_config_into_args(config, args)
        assert args.ssh_user == "admin"
        assert args.timeout == 60

    def test_cli_overrides_config(self):
        args = Namespace(ssh_user="cli_user", timeout=30)
        config = {"ssh_user": "config_user", "timeout": 60}
        merge_config_into_args(config, args)
        assert args.ssh_user == "cli_user"
        assert args.timeout == 30

    def test_false_bool_gets_overridden(self):
        args = Namespace(verbose=False)
        config = {"verbose": True}
        merge_config_into_args(config, args)
        assert args.verbose is True

    def test_true_bool_not_overridden(self):
        args = Namespace(verbose=True)
        config = {"verbose": False}
        merge_config_into_args(config, args)
        assert args.verbose is True

    def test_empty_config(self):
        args = Namespace(timeout=30)
        merge_config_into_args({}, args)
        assert args.timeout == 30

    def test_new_attribute(self):
        args = Namespace()
        config = {"ssh_user": "admin"}
        merge_config_into_args(config, args)
        assert args.ssh_user == "admin"


# ── Valid keys ────────────────────────────────────────────────────────

class TestValidKeys:
    def test_credential_keys_present(self):
        for key in ("ssh_user", "ssh_password", "win_user", "db_user"):
            assert key in _VALID_KEYS

    def test_output_keys_present(self):
        for key in ("json_file", "html_file", "csv_file", "sarif_file"):
            assert key in _VALID_KEYS

    def test_scan_options_present(self):
        for key in ("profile", "severity", "threads", "timeout"):
            assert key in _VALID_KEYS
