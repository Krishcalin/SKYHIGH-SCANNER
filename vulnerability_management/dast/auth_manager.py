"""
Authentication manager for DAST scanning.

Handles the full authentication lifecycle:
  - Form-based login with auto-detection of login forms
  - Session validation (detect login redirects, session expiry)
  - Re-authentication when sessions expire mid-scan
  - Credential extraction from DastConfig / CredentialManager
  - Unauthenticated config creation for comparison testing
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ..core.credential_manager import CredentialManager
    from .config import DastConfig
    from .crawler import SiteMap
    from .http_client import DastHTTPClient

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Patterns
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LOGIN_FIELD_NAMES = re.compile(
    r"^(user|username|email|login|usr|uid|account|user_name|user_id)$",
    re.IGNORECASE,
)

PASSWORD_FIELD_NAMES = re.compile(
    r"^(pass|password|passwd|pwd|secret|credential|user_password)$",
    re.IGNORECASE,
)

LOGIN_REDIRECT_RE = re.compile(
    r"(?:login|signin|sign-in|log-in|auth|authenticate|session/new|sso)",
    re.IGNORECASE,
)

LOGIN_FAILURE_RE = re.compile(
    r"(?:invalid\s+(?:credentials?|username|password|login)|"
    r"authentication\s+failed|login\s+failed|"
    r"incorrect\s+(?:username|password)|"
    r"access\s+denied|"
    r"bad\s+credentials?|"
    r"wrong\s+(?:username|password))",
    re.IGNORECASE,
)

LOGIN_SUCCESS_RE = re.compile(
    r"(?:dashboard|welcome|home|profile|account|logout|sign.?out|my.?account)",
    re.IGNORECASE,
)

# Common login endpoint paths to probe when no login URL is configured
COMMON_LOGIN_PATHS = (
    "login", "signin", "sign-in", "auth/login",
    "user/login", "account/login", "admin/login",
    "api/auth/login", "session/new",
)

# HTML patterns
HIDDEN_INPUT_RE = re.compile(
    r"<input[^>]+type=[\"']hidden[\"'][^>]*>",
    re.IGNORECASE,
)
INPUT_NAME_RE = re.compile(r"name=[\"']([^\"']+)[\"']")
INPUT_VALUE_RE = re.compile(r"value=[\"']([^\"']*)[\"']")
PASSWORD_TYPE_RE = re.compile(r"type=[\"']password[\"']", re.IGNORECASE)
INPUT_TAG_RE = re.compile(
    r"<input[^>]+name=[\"']([^\"']+)[\"'][^>]*>",
    re.IGNORECASE,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Auth Result
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AuthResult:
    """Result of an authentication attempt."""

    __slots__ = ("success", "message", "method", "login_url")

    def __init__(
        self,
        success: bool,
        message: str = "",
        method: str = "none",
        login_url: str = "",
    ):
        self.success = success
        self.message = message
        self.method = method
        self.login_url = login_url

    def __bool__(self) -> bool:
        return self.success

    def __repr__(self) -> str:
        return f"AuthResult(success={self.success}, method={self.method!r})"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Auth Manager
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AuthManager:
    """Manages authentication lifecycle for DAST scanning.

    Handles form-based login, session validation, and re-authentication.
    Supports comparison testing between authenticated and unauthenticated
    sessions for access control verification.
    """

    MAX_RELOGINS = 3

    def __init__(
        self,
        client: DastHTTPClient,
        config: DastConfig,
        credentials: CredentialManager | None = None,
    ):
        self.client = client
        self.config = config
        self.credentials = credentials

        self._is_authenticated = False
        self._login_url: str | None = None
        self._login_form_data: dict[str, str] = {}
        self._session_cookies: dict[str, str] = {}
        self._login_count = 0

    # ── Public API ─────────────────────────────────────────────────

    @property
    def is_authenticated(self) -> bool:
        """Whether the session is currently authenticated."""
        return self._is_authenticated

    def authenticate(
        self,
        target_url: str,
        sitemap: SiteMap | None = None,
    ) -> AuthResult:
        """Perform authentication based on configuration.

        For bearer/cookie/basic modes, auth headers are already applied
        by ``DastHTTPClient._setup_auth()``.  This method handles
        form-based login and validates the auth state.
        """
        mode = self.config.auth_mode

        if mode == "none":
            return AuthResult(True, "No authentication required", "none")

        if mode in ("bearer", "cookie", "basic"):
            # Headers already applied — just validate
            valid = self._validate_session(target_url)
            self._is_authenticated = valid
            label = {
                "bearer": "Bearer token",
                "cookie": "Session cookie",
                "basic": "HTTP Basic",
            }[mode]
            if valid:
                return AuthResult(True, f"{label} authentication active", mode)
            return AuthResult(
                False,
                f"{label} authentication could not be validated",
                mode,
            )

        if mode == "form":
            return self._form_login(target_url, sitemap)

        return AuthResult(False, f"Unknown auth mode: {mode}", mode)

    def ensure_authenticated(self, target_url: str) -> bool:
        """Re-login if the session has expired.

        Returns True if the session is valid (or was successfully
        refreshed).  Safe to call frequently — it short-circuits if
        the session is still good.
        """
        if self.config.auth_mode == "none":
            return True

        if self._validate_session(target_url):
            return True

        # Session expired — attempt re-login
        if self._login_count >= self.MAX_RELOGINS:
            logger.warning(
                "Max re-login attempts (%d) reached", self.MAX_RELOGINS,
            )
            return False

        if (
            self.config.auth_mode == "form"
            and self._login_url
            and self._login_form_data
        ):
            logger.info("Session expired, re-authenticating...")
            try:
                resp = self.client.post(
                    self._login_url, data=self._login_form_data,
                )
                success = self._check_login_success(resp, self._login_url)
                self._is_authenticated = success
                self._login_count += 1
                if success:
                    self._snapshot_session()
                return success
            except Exception as exc:
                logger.warning("Re-authentication failed: %s", exc)
                return False

        return False

    def create_unauthenticated_config(self) -> DastConfig:
        """Return a DastConfig copy with authentication disabled.

        Useful for comparing authenticated vs unauthenticated responses
        in access control checks.
        """
        from .config import DastConfig as _DC

        return _DC(
            scope=self.config.scope,
            rate_limit_rps=self.config.rate_limit_rps,
            max_requests=self.config.max_requests,
            request_timeout=self.config.request_timeout,
            auth_mode="none",
            crawl_enabled=False,
            passive_only=self.config.passive_only,
            accept_risk=True,
        )

    def get_session_info(self) -> dict:
        """Return non-sensitive session metadata for logging."""
        cookie_names = (
            list(self._session_cookies.keys())
            if self._session_cookies
            else []
        )
        return {
            "authenticated": self._is_authenticated,
            "auth_mode": self.config.auth_mode,
            "login_url": self._login_url,
            "login_attempts": self._login_count,
            "session_cookies": cookie_names,
        }

    # ── Form login ─────────────────────────────────────────────────

    def _form_login(
        self,
        target_url: str,
        sitemap: SiteMap | None = None,
    ) -> AuthResult:
        """Perform form-based login."""
        username, password = self._get_credentials()
        if not username or not password:
            return AuthResult(
                False,
                "No credentials available for form login",
                "form",
            )

        login_url = self._find_login_url(target_url, sitemap)
        if not login_url:
            return AuthResult(
                False, "Could not find login form URL", "form",
            )

        self._login_url = login_url

        form_data = self._build_login_form_data(
            login_url, username, password,
        )
        if not form_data:
            return AuthResult(
                False,
                f"Could not detect login form fields at {login_url}",
                "form",
                login_url,
            )

        self._login_form_data = form_data

        try:
            resp = self.client.post(login_url, data=form_data)
        except Exception as exc:
            return AuthResult(
                False,
                f"Login request failed: {exc}",
                "form",
                login_url,
            )

        success = self._check_login_success(resp, login_url)
        self._is_authenticated = success
        self._login_count += 1

        if success:
            self._snapshot_session()
            return AuthResult(
                True,
                f"Form login successful at {login_url}",
                "form",
                login_url,
            )

        return AuthResult(
            False,
            f"Form login failed at {login_url} (status {resp.status_code})",
            "form",
            login_url,
        )

    # ── Credential extraction ──────────────────────────────────────

    def _get_credentials(self) -> tuple[str | None, str | None]:
        """Extract username/password from config or credential manager."""
        # Priority 1: Explicit form data in config
        if self.config.auth_form_data:
            user = None
            pw = None
            for k, v in self.config.auth_form_data.items():
                if LOGIN_FIELD_NAMES.match(k):
                    user = v
                elif PASSWORD_FIELD_NAMES.match(k):
                    pw = v
            if user and pw:
                return user, pw

        # Priority 2: CredentialManager.web
        if self.credentials and self.credentials.web:
            return self.credentials.web.username, self.credentials.web.password

        # Priority 3: auth_token as "user:pass" for form mode
        if self.config.auth_token and ":" in self.config.auth_token:
            user, _, pw = self.config.auth_token.partition(":")
            return user, pw

        return None, None

    # ── Login form discovery ───────────────────────────────────────

    def _find_login_url(
        self,
        target_url: str,
        sitemap: SiteMap | None,
    ) -> str | None:
        """Find the login form URL from config, sitemap, or probing."""
        # Priority 1: Explicit config
        if self.config.auth_form_url:
            return self.config.auth_form_url

        # Priority 2: Crawled forms with password + username fields
        if sitemap:
            for form in getattr(sitemap, "forms", []):
                has_password = any(
                    f.field_type == "password" for f in form.fields
                )
                has_user = any(
                    LOGIN_FIELD_NAMES.match(f.name)
                    for f in form.fields
                    if f.name
                )
                if has_password and has_user:
                    return form.url

        # Priority 3: Probe common login paths
        base = target_url.rstrip("/")
        for path in COMMON_LOGIN_PATHS:
            try:
                status, body = self.client.probe_path(base, path)
                if status == 200 and len(body) > 100 and PASSWORD_TYPE_RE.search(body):
                    return f"{base}/{path}"
            except Exception:
                continue

        return None

    # ── Form data construction ─────────────────────────────────────

    def _build_login_form_data(
        self,
        login_url: str,
        username: str,
        password: str,
    ) -> dict[str, str]:
        """Build the POST data for login form submission.

        Fetches the login page to discover hidden fields (CSRF tokens)
        and the actual input field names.
        """
        # If explicit form_data is provided, overlay credentials
        if self.config.auth_form_data:
            data = dict(self.config.auth_form_data)
            has_user = any(LOGIN_FIELD_NAMES.match(k) for k in data)
            has_pass = any(PASSWORD_FIELD_NAMES.match(k) for k in data)
            if not has_user:
                data["username"] = username
            if not has_pass:
                data["password"] = password
            return data

        # Auto-detect by fetching the login page
        try:
            resp = self.client.get(login_url)
            body = resp.text
        except Exception:
            return {"username": username, "password": password}

        form_data: dict[str, str] = {}

        # Collect hidden fields (CSRF tokens, etc.)
        for match in HIDDEN_INPUT_RE.finditer(body):
            tag = match.group(0)
            name_m = INPUT_NAME_RE.search(tag)
            value_m = INPUT_VALUE_RE.search(tag)
            if name_m:
                form_data[name_m.group(1)] = (
                    value_m.group(1) if value_m else ""
                )

        # Detect username and password field names
        username_field = "username"
        password_field = "password"

        for match in INPUT_TAG_RE.finditer(body):
            tag = match.group(0)
            name = match.group(1)
            if PASSWORD_TYPE_RE.search(tag):
                password_field = name
            elif LOGIN_FIELD_NAMES.match(name):
                username_field = name

        form_data[username_field] = username
        form_data[password_field] = password

        return form_data

    # ── Login success detection ────────────────────────────────────

    def _check_login_success(self, resp, login_url: str) -> bool:
        """Heuristically determine if login was successful."""
        body_snippet = resp.text[:5000] if resp.text else ""

        # Failure patterns in response body
        if LOGIN_FAILURE_RE.search(body_snippet):
            return False

        # Redirect away from login page
        redirected_to_login = False
        final_url = getattr(resp, "url", "") or ""
        if final_url:
            parsed_login = urlparse(login_url)
            parsed_final = urlparse(final_url)
            if parsed_final.path != parsed_login.path:
                if LOGIN_REDIRECT_RE.search(parsed_final.path):
                    # Redirected to another login-like URL → failure
                    redirected_to_login = True
                else:
                    # Redirected to a non-login page → success
                    return True

        if redirected_to_login:
            return False

        # Success patterns in response
        if LOGIN_SUCCESS_RE.search(body_snippet):
            return True

        # New session cookies set
        if resp.cookies:
            return True

        # Status 200 without failure patterns
        return resp.status_code == 200

    # ── Session validation ─────────────────────────────────────────

    def _validate_session(self, target_url: str) -> bool:
        """Check if the current session is still valid.

        Makes a request and checks for redirect-to-login or 401/403.
        """
        try:
            resp = self.client.get(target_url, capture_evidence=False)
        except Exception:
            return False

        # Redirected to login page → session expired
        final_url = getattr(resp, "url", "") or ""
        if final_url and LOGIN_REDIRECT_RE.search(final_url):
            return False

        # 401/403 → not authenticated
        return resp.status_code not in (401, 403)

    # ── Session snapshot ───────────────────────────────────────────

    def _snapshot_session(self) -> None:
        """Save current session cookies for logging/recovery."""
        try:
            self._session_cookies = dict(self.client._session.cookies)
        except Exception:
            self._session_cookies = {}
