"""
DAST Scanner — Dynamic Application Security Testing orchestrator.

Sends active security test payloads against a live web application to
discover vulnerabilities that static analysis cannot find.

Usage::

    python -m skyhigh_scanner dast --target https://app.example.com [options]

Safety controls:
  - Scope enforcement (mandatory for non-localhost)
  - Rate limiting (default 10 req/s)
  - Request cap (default 10,000)
  - Pre-scan warning banner (--dast-accept-risk to suppress)
  - Passive-only mode (--dast-passive-only)

Rule ID format: DAST-{CATEGORY}-{NNN}
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from ..core.scanner_base import ScannerBase
from ..dast.config import DastConfig, ScopePolicy
from ..dast.crawler import SiteMap, WebCrawler
from ..dast.http_client import DastHTTPClient

if TYPE_CHECKING:
    from ..core.credential_manager import CredentialManager
    from ..core.scan_profiles import ScanProfile


class DastScanner(ScannerBase):
    """Dynamic Application Security Testing scanner.

    Crawls the target, then dispatches check modules based on the
    active scan profile.
    """

    SCANNER_NAME = "SkyHigh DAST Scanner"
    SCANNER_VERSION = "1.0.0"
    TARGET_TYPE = "dast"

    # Map scan profile categories → DAST check module names
    CHECK_DISPATCH: dict[str, str] = {
        "injection":        "injection",
        "xss":              "xss",
        "auth_session":     "auth_session",
        "access_control":   "access_control",
        "api_security":     "api_security",
        "file_inclusion":   "file_inclusion",
        "info_disclosure":  "info_disclosure",
        "config_misconfig": "config_misconfig",
    }

    def __init__(
        self,
        target: str,
        credentials: CredentialManager | None = None,
        timeout: int = 30,
        verbose: bool = False,
        profile: ScanProfile | None = None,
        dast_config: DastConfig | None = None,
        **kwargs,
    ):
        super().__init__(verbose=verbose, profile=profile)
        self.target = target
        self.credentials = credentials
        self.timeout = timeout

        # Build DAST config — auto-generate scope from target if not provided
        if dast_config:
            self.dast_config = dast_config
        else:
            scope = ScopePolicy.from_target(self._target_url)
            self.dast_config = DastConfig(
                scope=scope,
                request_timeout=timeout,
            )

    # ── Properties ────────────────────────────────────────────────────

    @property
    def _target_url(self) -> str:
        """Resolve the target to a full URL."""
        if self.target.startswith("http://") or self.target.startswith("https://"):
            return self.target
        return f"https://{self.target}"

    # ── Main scan flow ────────────────────────────────────────────────

    def scan(self) -> None:
        """Execute the DAST scan."""
        from ..core.transport import HAS_REQUESTS
        if not HAS_REQUESTS:
            self._error("requests not installed. Run: pip install requests")
            return

        self._start_timer()

        # Pre-scan warning
        if not self.dast_config.accept_risk:
            self._print_warning_banner()

        url = self._target_url
        self._info(f"DAST scan starting: {url}")
        self._info(f"Scope: {', '.join(self.dast_config.scope.allowed_hosts)}")
        self._info(f"Rate limit: {self.dast_config.rate_limit_rps} req/s | "
                    f"Max requests: {self.dast_config.max_requests}")

        try:
            client = DastHTTPClient(config=self.dast_config)
            # Phase 1: Crawl
            sitemap = SiteMap()
            if self.dast_config.crawl_enabled and self._check_enabled("crawl"):
                self._info("Phase 1: Crawling target...")
                crawler = WebCrawler(
                    client=client,
                    verbose=self.verbose,
                )
                sitemap = crawler.crawl(url)
                self._info(
                    f"Crawl complete: {len(sitemap.urls)} pages, "
                    f"{len(sitemap.forms)} forms, "
                    f"{len(sitemap.api_endpoints)} API endpoints"
                )
            else:
                # No crawl — just test the seed URL
                sitemap.urls.add(url)
                self._vprint("Crawling disabled — testing seed URL only")

            # Phase 2: Dispatch check modules
            self._info("Phase 2: Running security checks...")
            self._dispatch_checks(client, url, sitemap)

            self.targets_scanned.append(url)
            self._info(f"Requests sent: {client.request_count}")

        except Exception as e:
            self._error(f"DAST scan failed: {e}")
            self.targets_failed.append(url)
            client = None
        finally:
            if client is not None:
                client.close()

        self._stop_timer()

    # ── Check dispatch ────────────────────────────────────────────────

    def _dispatch_checks(
        self,
        client: DastHTTPClient,
        target_url: str,
        sitemap: SiteMap,
    ) -> None:
        """Dispatch to DAST check modules based on the active scan profile."""
        for category, module_name in self.CHECK_DISPATCH.items():
            if not self._check_enabled(category):
                self._vprint(f"Skipping {category} (disabled by profile)")
                continue

            # Skip active injection checks in passive-only mode
            if self.dast_config.passive_only and category in (
                "injection", "xss", "file_inclusion", "access_control",
            ):
                self._vprint(f"Skipping {category} (passive-only mode)")
                continue

            self._vprint(f"Running {category} checks...")
            try:
                findings = self._run_check_module(
                    module_name, client, target_url, sitemap,
                )
                for f in findings:
                    self._add_finding(f)
                if findings:
                    self._vprint(f"  {category}: {len(findings)} findings")
            except ImportError:
                self._vprint(f"  {category} check module not yet implemented")
            except Exception as e:
                self._warn(f"  {category} checks failed: {e}")

    def _run_check_module(
        self,
        module_name: str,
        client: DastHTTPClient,
        target_url: str,
        sitemap: SiteMap,
    ) -> list:
        """Import and run a specific check module."""
        import importlib
        module = importlib.import_module(f"..dast.checks.{module_name}", __package__)
        run_checks = module.run_checks
        return run_checks(
            client=client,
            target_url=target_url,
            sitemap=sitemap,
            credentials=self.credentials,
            verbose=self.verbose,
        )

    # ── Warning banner ────────────────────────────────────────────────

    def _print_warning_banner(self) -> None:
        """Print a prominent warning before the scan starts."""
        hosts = ", ".join(self.dast_config.scope.allowed_hosts) or "(none)"
        passive = " (PASSIVE ONLY)" if self.dast_config.passive_only else ""
        banner = f"""
{'='*70}
  {self.BOLD}\033[91mWARNING: DAST scanning sends active attack payloads{passive}{self.RESET}
{'='*70}
  Target : {self._target_url}
  Scope  : {hosts}
  Rate   : {self.dast_config.rate_limit_rps} req/s
  Max Req: {self.dast_config.max_requests}
  Auth   : {self.dast_config.auth_mode}

  Ensure you have written authorization to test this target.
  Use --dast-accept-risk to suppress this warning.
{'='*70}
"""
        print(banner, file=sys.stderr)
