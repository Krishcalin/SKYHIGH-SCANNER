"""
Plugin registry for SkyHigh Scanner.

Discovers, loads, and manages scanner plugins from:
  1. Built-in ``skyhigh_scanner/plugins/`` directory
  2. User-specified directories via ``--plugin-dir``
  3. Installed entry-point packages (``skyhigh_scanner.plugins`` group)

Plugins are Python modules that contain a class inheriting from
``ScannerBase`` and decorated with ``@scanner_plugin``.

Example plugin::

    from skyhigh_scanner.core.scanner_base import ScannerBase
    from skyhigh_scanner.core.plugin_registry import scanner_plugin

    @scanner_plugin(
        command="my-scanner",
        help="Scan my custom targets",
    )
    class MyScanner(ScannerBase):
        SCANNER_NAME = "My Custom Scanner"
        SCANNER_VERSION = "1.0.0"
        TARGET_TYPE = "custom"

        def __init__(self, target, credentials, **kwargs):
            super().__init__(verbose=kwargs.get("verbose", False))
            self.target = target
            self.credentials = credentials

        def scan(self):
            self._start_timer()
            # ... scanning logic ...
            self._stop_timer()
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    """Metadata about a registered scanner plugin."""

    command: str                    # CLI sub-command name (e.g. "my-scanner")
    help: str                      # One-line description for argparse
    scanner_class: type            # The ScannerBase subclass
    module_path: str | None = None  # File path of the plugin module
    required_deps: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return getattr(self.scanner_class, "SCANNER_NAME", self.command)

    @property
    def version(self) -> str:
        return getattr(self.scanner_class, "SCANNER_VERSION", "0.0.0")


# ── Global registry ─────────────────────────────────────────────────

_registry: dict[str, PluginInfo] = {}


def scanner_plugin(
    command: str,
    help: str = "",
    required_deps: list[str] | None = None,
):
    """Decorator to register a ScannerBase subclass as a plugin.

    Args:
        command: CLI sub-command name (e.g. ``"my-scanner"``).
        help: One-line help text shown in ``--help``.
        required_deps: Optional list of pip package names required.

    Returns:
        The original class, unmodified.

    Raises:
        ValueError: If the command name conflicts with a built-in or
            another plugin.
    """
    def decorator(cls):
        _register_class(cls, command, help, required_deps or [])
        return cls
    return decorator


def _register_class(
    cls: type,
    command: str,
    help_text: str,
    required_deps: list[str],
) -> None:
    """Register a scanner class in the global registry."""
    from .scanner_base import ScannerBase  # deferred to avoid circular import

    # Validate
    if not (isinstance(cls, type) and issubclass(cls, ScannerBase)):
        raise TypeError(
            f"Plugin '{command}': class {cls.__name__} must inherit ScannerBase"
        )

    BUILTIN_COMMANDS = frozenset({
        "auto", "windows", "linux", "cisco",
        "webserver", "middleware", "database", "dast",
        "cve-sync", "cve-import", "cve-stats", "epss-sync",
    })
    if command in BUILTIN_COMMANDS:
        raise ValueError(
            f"Plugin command '{command}' conflicts with a built-in command"
        )

    if command in _registry:
        existing = _registry[command]
        raise ValueError(
            f"Plugin command '{command}' already registered by "
            f"{existing.scanner_class.__name__}"
        )

    _registry[command] = PluginInfo(
        command=command,
        help=help_text,
        scanner_class=cls,
        required_deps=required_deps,
    )
    logger.debug("Registered plugin: %s → %s", command, cls.__name__)


def get_registry() -> dict[str, PluginInfo]:
    """Return a copy of the current plugin registry."""
    return dict(_registry)


def get_plugin(command: str) -> PluginInfo | None:
    """Look up a plugin by its CLI command name."""
    return _registry.get(command)


def clear_registry() -> None:
    """Clear all registered plugins (for testing)."""
    _registry.clear()


# ── Discovery & loading ─────────────────────────────────────────────

def _load_module_from_path(path: Path) -> str | None:
    """Import a Python module from a file path. Returns module name or None."""
    if not path.is_file() or path.suffix != ".py":
        return None
    if path.name.startswith("_"):
        return None

    module_name = f"skyhigh_plugin_{path.stem}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, str(path))
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        # Update module_path on any plugins that were registered during import
        for info in _registry.values():
            if info.module_path is None:
                info.module_path = str(path)

        return module_name
    except Exception as exc:
        logger.warning("Failed to load plugin %s: %s", path, exc)
        return None


def discover_plugins(
    extra_dirs: list[str] | None = None,
) -> dict[str, PluginInfo]:
    """Discover and load plugins from all sources.

    Sources (in order):
      1. Built-in ``skyhigh_scanner/plugins/`` directory
      2. Directories listed in *extra_dirs*
      3. Installed packages advertising the ``skyhigh_scanner.plugins``
         entry-point group

    Returns:
        The updated plugin registry.
    """
    # 1. Built-in plugins directory (use import_module for package context)
    builtin_dir = Path(__file__).parent.parent / "plugins"
    if builtin_dir.is_dir():
        for py_file in sorted(builtin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            module_name = f"skyhigh_scanner.plugins.{py_file.stem}"
            try:
                if module_name in sys.modules:
                    importlib.reload(sys.modules[module_name])
                else:
                    importlib.import_module(module_name)
            except Exception as exc:
                logger.warning("Failed to load built-in plugin %s: %s",
                               py_file.name, exc)

    # 2. Extra directories (e.g. --plugin-dir)
    for dir_path_str in (extra_dirs or []):
        dir_path = Path(dir_path_str)
        if dir_path.is_dir():
            for py_file in sorted(dir_path.glob("*.py")):
                _load_module_from_path(py_file)
        else:
            logger.warning("Plugin directory not found: %s", dir_path)

    # 3. Entry-point packages (pip-installable plugins)
    try:
        if sys.version_info >= (3, 10):
            from importlib.metadata import entry_points
            eps = entry_points(group="skyhigh_scanner.plugins")
        else:
            from importlib.metadata import entry_points
            all_eps = entry_points()
            eps = all_eps.get("skyhigh_scanner.plugins", [])

        for ep in eps:
            try:
                ep.load()  # importing triggers @scanner_plugin decorator
            except Exception as exc:
                logger.warning("Failed to load entry-point plugin %s: %s",
                               ep.name, exc)
    except Exception:
        pass  # importlib.metadata not available

    return get_registry()


def list_plugins() -> list[PluginInfo]:
    """Return all registered plugins sorted by command name."""
    return sorted(_registry.values(), key=lambda p: p.command)
