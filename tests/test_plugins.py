"""Tests for the plugin architecture."""

import json
import textwrap

import pytest

from skyhigh_scanner.core.plugin_registry import (
    clear_registry,
    discover_plugins,
    get_plugin,
    get_registry,
    list_plugins,
    scanner_plugin,
)
from skyhigh_scanner.core.scanner_base import ScannerBase


@pytest.fixture(autouse=True)
def _clean_registry():
    """Clear the plugin registry before and after each test."""
    clear_registry()
    yield
    clear_registry()


# ── Decorator registration ──────────────────────────────────────────

class TestScannerPluginDecorator:
    def test_register_basic_plugin(self):
        @scanner_plugin(command="test-basic", help="A basic test plugin")
        class BasicPlugin(ScannerBase):
            SCANNER_NAME = "Basic Plugin"
            SCANNER_VERSION = "1.0.0"
            TARGET_TYPE = "test"

            def scan(self):
                pass

        reg = get_registry()
        assert "test-basic" in reg
        assert reg["test-basic"].scanner_class is BasicPlugin
        assert reg["test-basic"].help == "A basic test plugin"

    def test_decorator_returns_original_class(self):
        @scanner_plugin(command="test-identity", help="Test")
        class IdentityPlugin(ScannerBase):
            def scan(self):
                pass

        # The decorator should not wrap or modify the class
        assert IdentityPlugin.__name__ == "IdentityPlugin"
        assert issubclass(IdentityPlugin, ScannerBase)

    def test_register_with_required_deps(self):
        @scanner_plugin(
            command="test-deps",
            help="Plugin with deps",
            required_deps=["boto3", "requests"],
        )
        class DepsPlugin(ScannerBase):
            def scan(self):
                pass

        info = get_plugin("test-deps")
        assert info is not None
        assert info.required_deps == ["boto3", "requests"]

    def test_plugin_info_properties(self):
        @scanner_plugin(command="test-props", help="Props test")
        class PropsPlugin(ScannerBase):
            SCANNER_NAME = "Props Scanner"
            SCANNER_VERSION = "2.0.0"

            def scan(self):
                pass

        info = get_plugin("test-props")
        assert info.name == "Props Scanner"
        assert info.version == "2.0.0"
        assert info.command == "test-props"


# ── Validation ──────────────────────────────────────────────────────

class TestRegistrationValidation:
    def test_reject_non_scanner_class(self):
        with pytest.raises(TypeError, match="must inherit ScannerBase"):
            @scanner_plugin(command="bad-class", help="Bad")
            class NotAScanner:
                pass

    def test_reject_builtin_command_name(self):
        for builtin in ("auto", "windows", "linux", "cisco", "cve-sync"):
            with pytest.raises(ValueError, match="conflicts with a built-in"):
                @scanner_plugin(command=builtin, help="Conflict")
                class ConflictPlugin(ScannerBase):
                    def scan(self):
                        pass

    def test_reject_duplicate_command(self):
        @scanner_plugin(command="unique-cmd", help="First")
        class First(ScannerBase):
            def scan(self):
                pass

        with pytest.raises(ValueError, match="already registered"):
            @scanner_plugin(command="unique-cmd", help="Duplicate")
            class Second(ScannerBase):
                def scan(self):
                    pass


# ── Registry operations ─────────────────────────────────────────────

class TestRegistryOperations:
    def test_get_plugin_returns_none_for_unknown(self):
        assert get_plugin("nonexistent") is None

    def test_get_registry_returns_copy(self):
        @scanner_plugin(command="reg-copy", help="Test")
        class RegCopy(ScannerBase):
            def scan(self):
                pass

        reg1 = get_registry()
        reg2 = get_registry()
        assert reg1 == reg2
        assert reg1 is not reg2  # must be a copy

    def test_clear_registry(self):
        @scanner_plugin(command="to-clear", help="Test")
        class ClearMe(ScannerBase):
            def scan(self):
                pass

        assert len(get_registry()) == 1
        clear_registry()
        assert len(get_registry()) == 0

    def test_list_plugins_sorted(self):
        @scanner_plugin(command="zzz-plugin", help="Last")
        class ZPlugin(ScannerBase):
            def scan(self):
                pass

        @scanner_plugin(command="aaa-plugin", help="First")
        class APlugin(ScannerBase):
            def scan(self):
                pass

        plugins = list_plugins()
        assert len(plugins) == 2
        assert plugins[0].command == "aaa-plugin"
        assert plugins[1].command == "zzz-plugin"


# ── File-based discovery ─────────────────────────────────────────────

class TestFileDiscovery:
    def test_discover_from_directory(self, tmp_path):
        plugin_file = tmp_path / "custom_scanner.py"
        plugin_file.write_text(textwrap.dedent("""\
            from skyhigh_scanner.core.scanner_base import ScannerBase
            from skyhigh_scanner.core.plugin_registry import scanner_plugin

            @scanner_plugin(command="custom-scan", help="Custom scanner")
            class CustomScanner(ScannerBase):
                SCANNER_NAME = "Custom Scanner"
                SCANNER_VERSION = "1.0.0"
                TARGET_TYPE = "custom"

                def __init__(self, target="", credentials=None, **kwargs):
                    super().__init__(verbose=kwargs.get("verbose", False))
                    self.target = target
                    self.credentials = credentials

                def scan(self):
                    self._start_timer()
                    self.targets_scanned.append(self.target)
                    self._stop_timer()
        """))

        plugins = discover_plugins(extra_dirs=[str(tmp_path)])
        assert "custom-scan" in plugins
        assert plugins["custom-scan"].name == "Custom Scanner"

    def test_skip_underscore_files(self, tmp_path):
        (tmp_path / "_private.py").write_text(
            "raise RuntimeError('should not be loaded')"
        )
        plugins = discover_plugins(extra_dirs=[str(tmp_path)])
        # No crash, and no new plugins registered
        assert "_private" not in str(plugins)

    def test_skip_non_python_files(self, tmp_path):
        (tmp_path / "notes.txt").write_text("not a plugin")
        # Discover once to load builtins, then discover again with txt-only dir
        discover_plugins()
        before = len(get_registry())
        discover_plugins(extra_dirs=[str(tmp_path)])
        after = len(get_registry())
        # No new plugins should be added from txt files
        assert after == before

    def test_bad_plugin_does_not_crash(self, tmp_path):
        (tmp_path / "broken.py").write_text("raise SyntaxError('broken')\n")
        # Should log warning but not crash
        plugins = discover_plugins(extra_dirs=[str(tmp_path)])
        assert isinstance(plugins, dict)

    def test_nonexistent_dir_does_not_crash(self):
        plugins = discover_plugins(extra_dirs=["/nonexistent/path/xyz"])
        assert isinstance(plugins, dict)

    def test_discover_builtin_plugins(self):
        # The built-in plugins/ dir has example_scanner.py
        plugins = discover_plugins()
        assert "example" in plugins
        assert plugins["example"].name == "Example Scanner"

    def test_discover_from_multiple_dirs(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()

        (dir_a / "scanner_a.py").write_text(textwrap.dedent("""\
            from skyhigh_scanner.core.scanner_base import ScannerBase
            from skyhigh_scanner.core.plugin_registry import scanner_plugin

            @scanner_plugin(command="plug-a", help="Plugin A")
            class ScannerA(ScannerBase):
                def scan(self): pass
        """))
        (dir_b / "scanner_b.py").write_text(textwrap.dedent("""\
            from skyhigh_scanner.core.scanner_base import ScannerBase
            from skyhigh_scanner.core.plugin_registry import scanner_plugin

            @scanner_plugin(command="plug-b", help="Plugin B")
            class ScannerB(ScannerBase):
                def scan(self): pass
        """))

        plugins = discover_plugins(extra_dirs=[str(dir_a), str(dir_b)])
        assert "plug-a" in plugins
        assert "plug-b" in plugins


# ── Plugin execution ─────────────────────────────────────────────────

class TestPluginExecution:
    def test_plugin_scanner_runs(self):
        @scanner_plugin(command="run-test", help="Runnable")
        class RunPlugin(ScannerBase):
            SCANNER_NAME = "Run Plugin"
            TARGET_TYPE = "test"

            def __init__(self, target="", credentials=None, **kwargs):
                super().__init__(verbose=kwargs.get("verbose", False))
                self.target = target
                self.credentials = credentials

            def scan(self):
                self._start_timer()
                self.targets_scanned.append(self.target)
                self._add(
                    rule_id="RUN-001", name="Test",
                    category="Test", severity="INFO",
                    file_path=self.target, line_num=0,
                    line_content="test", description="A test.",
                    recommendation="None.",
                )
                self._stop_timer()

        info = get_plugin("run-test")
        scanner = info.scanner_class(target="10.0.0.1")
        scanner.scan()

        assert len(scanner.findings) == 1
        assert scanner.findings[0].rule_id == "RUN-001"
        assert scanner.targets_scanned == ["10.0.0.1"]
        assert scanner.exit_code() == 0

    def test_plugin_inherits_all_base_methods(self):
        @scanner_plugin(command="inherit-test", help="Inheritance test")
        class InheritPlugin(ScannerBase):
            def __init__(self):
                super().__init__()

            def scan(self):
                pass

        info = get_plugin("inherit-test")
        scanner = info.scanner_class()
        scanner.scan()

        # Should have all export methods
        assert hasattr(scanner, "save_json")
        assert hasattr(scanner, "save_csv")
        assert hasattr(scanner, "save_sarif")
        assert hasattr(scanner, "print_report")
        assert hasattr(scanner, "summary")
        assert hasattr(scanner, "enrich_compliance")

    def test_plugin_save_json(self, tmp_path):
        @scanner_plugin(command="json-test", help="JSON test")
        class JsonPlugin(ScannerBase):
            SCANNER_NAME = "JSON Plugin"

            def __init__(self):
                super().__init__()

            def scan(self):
                self._add(
                    rule_id="JP-001", name="Test",
                    category="Test", severity="HIGH",
                    file_path="host", line_num=0,
                    line_content="val", description="desc",
                    recommendation="fix",
                )

        scanner = JsonPlugin()
        scanner.scan()
        path = str(tmp_path / "out.json")
        scanner.save_json(path)

        with open(path) as f:
            data = json.load(f)
        assert data["scanner"] == "JSON Plugin"
        assert len(data["findings"]) == 1


# ── CLI integration ──────────────────────────────────────────────────

class TestCliPluginIntegration:
    def test_plugin_subcommand_registered(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        # The example plugin should be available as a subcommand
        args = parser.parse_args([
            "example", "-t", "10.0.0.1",
        ])
        assert args.command == "example"
        assert args.target == "10.0.0.1"

    def test_plugin_subcommand_has_output_args(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "example", "-t", "10.0.0.1",
            "--json", "report.json",
            "--sarif", "report.sarif",
        ])
        assert args.json_file == "report.json"
        assert args.sarif_file == "report.sarif"

    def test_plugin_subcommand_has_scan_args(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "example", "-t", "10.0.0.1",
            "--severity", "HIGH",
            "--compliance",
        ])
        assert args.severity == "HIGH"
        assert args.compliance is True

    def test_plugin_dir_flag_accepted(self):
        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser()
        args = parser.parse_args([
            "--plugin-dir", "/some/dir",
            "example", "-t", "10.0.0.1",
        ])
        assert "/some/dir" in args.plugin_dir

    def test_plugin_dir_from_external(self, tmp_path):
        plugin_file = tmp_path / "ext_scanner.py"
        plugin_file.write_text(textwrap.dedent("""\
            from skyhigh_scanner.core.scanner_base import ScannerBase
            from skyhigh_scanner.core.plugin_registry import scanner_plugin

            @scanner_plugin(command="ext-scan", help="External scanner")
            class ExtScanner(ScannerBase):
                SCANNER_NAME = "External Scanner"
                def __init__(self, target="", credentials=None, **kwargs):
                    super().__init__(verbose=kwargs.get("verbose", False))
                    self.target = target
                    self.credentials = credentials
                def scan(self):
                    self._start_timer()
                    self.targets_scanned.append(self.target)
                    self._stop_timer()
        """))

        from skyhigh_scanner.__main__ import _build_parser
        parser = _build_parser(plugin_dirs=[str(tmp_path)])
        args = parser.parse_args(["ext-scan", "-t", "10.0.0.1"])
        assert args.command == "ext-scan"
