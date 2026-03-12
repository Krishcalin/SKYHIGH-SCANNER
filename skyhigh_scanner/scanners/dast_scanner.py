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

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from ..core.scanner_base import ScannerBase
from ..dast.auth_manager import AuthManager
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

        # DAST scan metadata (populated during scan)
        self._request_count: int = 0
        self._crawl_stats: dict[str, int] = {}
        self._auth_mode: str = "none"
        self._perf_metrics: dict[str, float] = {}

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
                    max_pages=self.dast_config.max_pages,
                    verbose=self.verbose,
                )
                sitemap = crawler.crawl(url)
                cs = sitemap.crawl_stats
                self._info(
                    f"Crawl complete: {len(sitemap.urls)} pages, "
                    f"{len(sitemap.forms)} forms, "
                    f"{len(sitemap.api_endpoints)} API endpoints"
                )
                if cs.sitemap_urls_added:
                    self._info(f"  Sitemap URLs: {cs.sitemap_urls_added}")
                if cs.robots_paths_added:
                    self._info(f"  Robots.txt paths: {cs.robots_paths_added}")
                if cs.redirect_count:
                    self._info(f"  Redirects tracked: {cs.redirect_count}")
                if sitemap.tech_fingerprint:
                    self._info(
                        f"  Tech: {sitemap.tech_fingerprint.summary_line()}"
                    )
            else:
                # No crawl — just test the seed URL
                sitemap.urls.add(url)
                self._vprint("Crawling disabled — testing seed URL only")

            # Phase 1.5: Authentication
            auth_mgr = AuthManager(
                client=client,
                config=self.dast_config,
                credentials=self.credentials,
            )
            if self.dast_config.auth_mode != "none":
                self._info("Phase 1.5: Authenticating...")
                auth_result = auth_mgr.authenticate(url, sitemap)
                if auth_result:
                    self._info(f"Auth: {auth_result.message}")
                else:
                    self._warn(f"Auth: {auth_result.message}")
                if self.verbose:
                    info = auth_mgr.get_session_info()
                    self._vprint(
                        f"  Mode={info['auth_mode']} | "
                        f"Cookies={info['session_cookies']}"
                    )

            # Phase 2: Dispatch check modules
            self._info("Phase 2: Running security checks...")
            self._dispatch_checks(client, url, sitemap)

            self.targets_scanned.append(url)
            self._request_count = client.request_count
            cs = sitemap.crawl_stats
            self._crawl_stats = {
                "pages": len(sitemap.urls),
                "forms": len(sitemap.forms),
                "api_endpoints": len(sitemap.api_endpoints),
                "sitemap_urls_added": cs.sitemap_urls_added,
                "robots_paths_added": cs.robots_paths_added,
                "redirect_count": cs.redirect_count,
                "status_codes": cs.status_codes,
                "content_types": cs.content_types,
                "duration_seconds": round(cs.duration_seconds, 2),
            }
            if sitemap.tech_fingerprint:
                self._crawl_stats["tech_fingerprint"] = {
                    "server": sitemap.tech_fingerprint.server,
                    "framework": sitemap.tech_fingerprint.framework,
                    "cms": sitemap.tech_fingerprint.cms,
                    "language": sitemap.tech_fingerprint.language,
                    "js_frameworks": sitemap.tech_fingerprint.js_frameworks,
                }
            self._auth_mode = self.dast_config.auth_mode
            self._perf_metrics = {
                "avg_response_time_ms": round(client.avg_response_time_ms, 1),
                "p95_response_time_ms": round(client.p95_response_time_ms, 1),
            }
            self._info(f"Requests sent: {client.request_count}")
            if self._perf_metrics["avg_response_time_ms"] > 0:
                self._info(
                    f"Response times: avg={self._perf_metrics['avg_response_time_ms']:.0f}ms "
                    f"p95={self._perf_metrics['p95_response_time_ms']:.0f}ms"
                )

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
        """Dispatch to DAST check modules concurrently."""
        _logger = logging.getLogger(__name__)

        # Build list of enabled checks
        enabled: list[tuple[str, str]] = []
        for category, module_name in self.CHECK_DISPATCH.items():
            if not self._check_enabled(category):
                self._vprint(f"Skipping {category} (disabled by profile)")
                continue
            if self.dast_config.passive_only and category in (
                "injection", "xss", "file_inclusion", "access_control",
            ):
                self._vprint(f"Skipping {category} (passive-only mode)")
                continue
            enabled.append((category, module_name))

        if not enabled:
            return

        def _run_one(cat_mod: tuple[str, str]) -> tuple[str, list]:
            cat, mod = cat_mod
            try:
                return cat, self._run_check_module(mod, client, target_url, sitemap)
            except ImportError:
                _logger.debug("Check module %s not yet implemented", mod)
                return cat, []
            except Exception as exc:
                _logger.debug("Check module %s failed: %s", mod, exc)
                return cat, []

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(_run_one, pair): pair[0] for pair in enabled}
            for future in as_completed(futures):
                category = futures[future]
                try:
                    cat, findings = future.result()
                    for f in findings:
                        self._add_finding(f)
                    if findings:
                        self._vprint(f"  {cat}: {len(findings)} findings")
                except Exception as exc:
                    self._warn(f"  {category} checks failed: {exc}")

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

    # ── Summary override ─────────────────────────────────────────────

    def summary(self) -> dict:
        """Return scan summary with DAST-specific metadata."""
        s = super().summary()
        s["dast_metadata"] = {
            "requests_sent": self._request_count,
            "crawl": self._crawl_stats,
            "auth_mode": self._auth_mode,
            "passive_only": self.dast_config.passive_only,
            "rate_limit_rps": self.dast_config.rate_limit_rps,
            "performance": self._perf_metrics,
        }
        return s

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
