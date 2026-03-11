"""
Example SkyHigh Scanner plugin.

This demonstrates how to create a custom scanner plugin. Copy this file,
rename it, and modify the class to add your own scanning logic.

Usage:
    python -m skyhigh_scanner example -t 10.0.0.1 --ssh-user admin --ssh-password secret

The plugin is automatically discovered from the ``plugins/`` directory.
"""

from __future__ import annotations

from skyhigh_scanner.core.plugin_registry import scanner_plugin
from skyhigh_scanner.core.scanner_base import ScannerBase


@scanner_plugin(
    command="example",
    help="Example plugin — demonstrates the plugin architecture",
)
class ExampleScanner(ScannerBase):
    """Example scanner plugin that generates a sample finding."""

    SCANNER_NAME = "Example Scanner"
    SCANNER_VERSION = "1.0.0"
    TARGET_TYPE = "generic"

    def __init__(self, target: str, credentials=None,
                 max_hosts: int = 256, timeout: int = 30,
                 verbose: bool = False, **kwargs):
        super().__init__(verbose=verbose)
        self.target = target
        self.credentials = credentials
        self.max_hosts = max_hosts
        self.timeout = timeout

    def scan(self) -> None:
        self._start_timer()
        self._info(f"Example plugin scanning: {self.target}")

        self.targets_scanned.append(self.target)
        self._add(
            rule_id="EXAMPLE-001",
            name="Example Finding",
            category="Example",
            severity="INFO",
            file_path=self.target,
            line_num=0,
            line_content="This is a demonstration finding.",
            description="The example plugin generated this finding to show "
                        "that the plugin architecture is working correctly.",
            recommendation="No action required — this is a demo.",
        )

        self._stop_timer()
        self._info(f"Example scan complete ({self.duration_seconds}s)")
