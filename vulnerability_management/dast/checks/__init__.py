"""
DAST check modules.

Each module exports a ``run_checks()`` function with the signature::

    def run_checks(
        client: DastHTTPClient,
        target_url: str,
        sitemap: SiteMap,
        credentials: CredentialManager | None = None,
        verbose: bool = False,
    ) -> list[Finding]:
        ...

Check modules are dispatched by the DastScanner orchestrator based
on the active scan profile categories.
"""
