"""Tests for DAST authentication manager."""

from __future__ import annotations

from unittest.mock import MagicMock

from vulnerability_management.core.credential_manager import (
    CredentialManager,
)
from vulnerability_management.dast.auth_manager import AuthManager, AuthResult
from vulnerability_management.dast.config import DastConfig, ScopePolicy
from vulnerability_management.dast.crawler import FormField, FormInfo, SiteMap

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _config(**overrides) -> DastConfig:
    defaults = {
        "scope": ScopePolicy(allowed_hosts=["example.com"]),
        "auth_mode": "none",
        "accept_risk": True,
    }
    defaults.update(overrides)
    return DastConfig(**defaults)


def _mock_client(
    get_text: str = "",
    get_status: int = 200,
    post_text: str = "",
    post_status: int = 200,
    post_cookies: dict | None = None,
    post_url: str = "",
    get_url: str = "",
) -> MagicMock:
    client = MagicMock()

    get_resp = MagicMock()
    get_resp.text = get_text
    get_resp.status_code = get_status
    get_resp.headers = {}
    get_resp.url = get_url
    get_resp.cookies = {}
    client.get.return_value = get_resp

    post_resp = MagicMock()
    post_resp.text = post_text
    post_resp.status_code = post_status
    post_resp.headers = {}
    post_resp.url = post_url
    post_resp.cookies = post_cookies or {}
    client.post.return_value = post_resp

    client.probe_path.return_value = (404, "")
    client._session = MagicMock()
    client._session.cookies = {}

    return client


def _cred_manager(username: str = "admin", password: str = "secret") -> CredentialManager:
    cm = CredentialManager()
    cm.set_web(username=username, password=password)
    return cm


def _empty_sitemap() -> SiteMap:
    return SiteMap()


def _login_sitemap() -> SiteMap:
    sm = SiteMap()
    sm.forms = [FormInfo(
        url="https://example.com/login",
        action="https://example.com/login",
        method="POST",
        fields=[
            FormField(name="username", field_type="text"),
            FormField(name="password", field_type="password"),
            FormField(name="csrf_token", field_type="hidden", value="tok123"),
        ],
    )]
    return sm


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — AuthResult
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestAuthResult:
    def test_bool_true(self):
        r = AuthResult(success=True, message="OK")
        assert bool(r) is True

    def test_bool_false(self):
        r = AuthResult(success=False, message="Failed")
        assert bool(r) is False

    def test_repr(self):
        r = AuthResult(success=True, method="form")
        assert "form" in repr(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — No Auth
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestNoAuth:
    def test_no_auth_returns_success(self):
        config = _config(auth_mode="none")
        client = _mock_client()
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is True
        assert result.method == "none"

    def test_no_auth_is_not_authenticated(self):
        config = _config(auth_mode="none")
        client = _mock_client()
        mgr = AuthManager(client, config)
        assert mgr.is_authenticated is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Bearer / Cookie / Basic
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestPreConfiguredAuth:
    def test_bearer_validated(self):
        config = _config(auth_mode="bearer", auth_token="tok123")
        client = _mock_client(get_status=200)
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is True
        assert mgr.is_authenticated is True

    def test_bearer_rejected_401(self):
        config = _config(auth_mode="bearer", auth_token="badtoken")
        client = _mock_client(get_status=401)
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is False

    def test_cookie_validated(self):
        config = _config(auth_mode="cookie", auth_token="session=abc123")
        client = _mock_client(get_status=200)
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is True

    def test_basic_validated(self):
        config = _config(auth_mode="basic", auth_token="admin:pass")
        client = _mock_client(get_status=200)
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is True

    def test_basic_redirect_to_login(self):
        config = _config(auth_mode="basic", auth_token="admin:pass")
        client = _mock_client(
            get_status=302,
            get_url="https://example.com/login",
        )
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Form Login
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestFormLogin:
    def test_form_login_success_with_redirect(self):
        config = _config(
            auth_mode="form",
            auth_form_url="https://example.com/login",
            auth_form_data={"username": "admin", "password": "secret"},
        )
        client = _mock_client(
            get_text="<html><input name='username'><input type='password' name='password'></html>",
            post_status=302,
            post_url="https://example.com/dashboard",
            post_text="<html>Welcome to your dashboard</html>",
        )
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is True
        assert result.method == "form"
        assert mgr.is_authenticated is True

    def test_form_login_failure(self):
        config = _config(
            auth_mode="form",
            auth_form_url="https://example.com/login",
            auth_form_data={"username": "admin", "password": "wrong"},
        )
        client = _mock_client(
            get_text="<html><input name='username'><input type='password' name='password'></html>",
            post_status=200,
            post_url="https://example.com/login",
            post_text="<html>Invalid credentials. Please try again.</html>",
        )
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is False

    def test_form_login_no_credentials(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is False
        assert "No credentials" in result.message

    def test_form_login_no_login_url(self):
        config = _config(
            auth_mode="form",
            auth_form_data={"username": "admin", "password": "secret"},
        )
        client = _mock_client()
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is False
        assert "login form URL" in result.message

    def test_form_login_with_cookies(self):
        config = _config(
            auth_mode="form",
            auth_form_url="https://example.com/login",
            auth_form_data={"username": "admin", "password": "secret"},
        )
        client = _mock_client(
            get_text="<html><form><input name='username'><input type='password' name='pass'></form></html>",
            post_status=200,
            post_url="https://example.com/login",
            post_text="<html>Loading...</html>",
            post_cookies={"session_id": "abc123"},
        )
        mgr = AuthManager(client, config)
        result = mgr.authenticate("https://example.com")
        assert result.success is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Credential Extraction
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestCredentialExtraction:
    def test_from_auth_form_data(self):
        config = _config(
            auth_mode="form",
            auth_form_url="https://example.com/login",
            auth_form_data={"username": "testuser", "password": "testpass"},
        )
        client = _mock_client(
            post_status=200,
            post_url="https://example.com/dashboard",
            post_text="<html>Welcome</html>",
        )
        mgr = AuthManager(client, config)
        user, pw = mgr._get_credentials()
        assert user == "testuser"
        assert pw == "testpass"

    def test_from_credential_manager(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        creds = _cred_manager("webuser", "webpass")
        mgr = AuthManager(client, config, credentials=creds)
        user, pw = mgr._get_credentials()
        assert user == "webuser"
        assert pw == "webpass"

    def test_from_auth_token_colon(self):
        config = _config(
            auth_mode="form",
            auth_token="tokenuser:tokenpass",
        )
        client = _mock_client()
        mgr = AuthManager(client, config)
        user, pw = mgr._get_credentials()
        assert user == "tokenuser"
        assert pw == "tokenpass"

    def test_no_credentials(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        mgr = AuthManager(client, config)
        user, pw = mgr._get_credentials()
        assert user is None
        assert pw is None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Login URL Discovery
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLoginURLDiscovery:
    def test_explicit_url_from_config(self):
        config = _config(
            auth_mode="form",
            auth_form_url="https://example.com/auth/login",
        )
        client = _mock_client()
        mgr = AuthManager(client, config)
        url = mgr._find_login_url("https://example.com", None)
        assert url == "https://example.com/auth/login"

    def test_from_crawled_sitemap(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        mgr = AuthManager(client, config)
        sm = _login_sitemap()
        url = mgr._find_login_url("https://example.com", sm)
        assert url == "https://example.com/login"

    def test_from_probing(self):
        config = _config(auth_mode="form")
        login_body = (
            "<html><head><title>Login</title></head><body>"
            "<form method='POST' action='/login'>"
            "<input name='user' type='text'>"
            "<input name='pass' type='password'>"
            "<button>Login</button>"
            "</form></body></html>"
        )

        def _probe(base, path):
            if path == "login":
                return (200, login_body)
            return (404, "")

        client = _mock_client()
        client.probe_path.side_effect = _probe
        mgr = AuthManager(client, config)
        url = mgr._find_login_url("https://example.com", _empty_sitemap())
        assert url == "https://example.com/login"

    def test_no_login_url_found(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        mgr = AuthManager(client, config)
        url = mgr._find_login_url("https://example.com", _empty_sitemap())
        assert url is None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Form Data Construction
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestFormDataConstruction:
    def test_explicit_form_data(self):
        config = _config(
            auth_mode="form",
            auth_form_data={"username": "admin", "password": "secret", "remember": "1"},
        )
        client = _mock_client()
        mgr = AuthManager(client, config)
        data = mgr._build_login_form_data(
            "https://example.com/login", "admin", "secret",
        )
        assert data["username"] == "admin"
        assert data["password"] == "secret"
        assert data["remember"] == "1"

    def test_autodetect_from_login_page(self):
        login_html = (
            "<html><form method='POST' action='/login'>"
            "<input type='hidden' name='csrf_token' value='abc123'>"
            "<input name='email' type='text'>"
            "<input name='pass' type='password'>"
            "<button>Sign In</button>"
            "</form></html>"
        )
        config = _config(auth_mode="form")
        client = _mock_client(get_text=login_html)
        mgr = AuthManager(client, config)
        data = mgr._build_login_form_data(
            "https://example.com/login", "admin", "secret",
        )
        assert data["csrf_token"] == "abc123"
        assert data["email"] == "admin"
        assert data["pass"] == "secret"

    def test_fallback_default_field_names(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        client.get.side_effect = Exception("connection error")
        mgr = AuthManager(client, config)
        data = mgr._build_login_form_data(
            "https://example.com/login", "admin", "secret",
        )
        assert data["username"] == "admin"
        assert data["password"] == "secret"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Session Validation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSessionValidation:
    def test_valid_session(self):
        config = _config(auth_mode="bearer", auth_token="tok")
        client = _mock_client(get_status=200, get_url="https://example.com/")
        mgr = AuthManager(client, config)
        assert mgr._validate_session("https://example.com") is True

    def test_redirect_to_login(self):
        config = _config(auth_mode="bearer", auth_token="tok")
        client = _mock_client(
            get_status=302,
            get_url="https://example.com/login?next=/",
        )
        mgr = AuthManager(client, config)
        assert mgr._validate_session("https://example.com") is False

    def test_401_response(self):
        config = _config(auth_mode="bearer", auth_token="tok")
        client = _mock_client(get_status=401)
        mgr = AuthManager(client, config)
        assert mgr._validate_session("https://example.com") is False

    def test_403_response(self):
        config = _config(auth_mode="bearer", auth_token="tok")
        client = _mock_client(get_status=403)
        mgr = AuthManager(client, config)
        assert mgr._validate_session("https://example.com") is False

    def test_exception_returns_false(self):
        config = _config(auth_mode="bearer", auth_token="tok")
        client = _mock_client()
        client.get.side_effect = Exception("timeout")
        mgr = AuthManager(client, config)
        assert mgr._validate_session("https://example.com") is False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Re-authentication
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestReAuthentication:
    def test_ensure_auth_when_valid(self):
        config = _config(auth_mode="bearer", auth_token="tok")
        client = _mock_client(get_status=200)
        mgr = AuthManager(client, config)
        assert mgr.ensure_authenticated("https://example.com") is True

    def test_ensure_auth_relogin_on_expiry(self):
        config = _config(
            auth_mode="form",
            auth_form_url="https://example.com/login",
            auth_form_data={"username": "admin", "password": "secret"},
        )

        call_count = 0

        def _mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.headers = {}
            resp.cookies = {}
            if call_count == 1:
                # First call (validate): expired
                resp.status_code = 302
                resp.url = "https://example.com/login"
                resp.text = "<html>Login</html>"
            else:
                resp.status_code = 200
                resp.url = "https://example.com/"
                resp.text = "<html>Dashboard</html>"
            return resp

        client = _mock_client(
            post_status=302,
            post_url="https://example.com/dashboard",
            post_text="<html>Welcome dashboard</html>",
        )
        client.get.side_effect = _mock_get

        mgr = AuthManager(client, config)
        mgr._login_url = "https://example.com/login"
        mgr._login_form_data = {"username": "admin", "password": "secret"}

        assert mgr.ensure_authenticated("https://example.com") is True
        assert mgr._login_count == 1

    def test_ensure_auth_max_relogins(self):
        config = _config(auth_mode="form")
        client = _mock_client(
            get_status=302,
            get_url="https://example.com/login",
        )
        mgr = AuthManager(client, config)
        mgr._login_count = AuthManager.MAX_RELOGINS
        mgr._login_url = "https://example.com/login"
        mgr._login_form_data = {"username": "admin", "password": "secret"}
        assert mgr.ensure_authenticated("https://example.com") is False

    def test_ensure_auth_none_mode(self):
        config = _config(auth_mode="none")
        client = _mock_client()
        mgr = AuthManager(client, config)
        assert mgr.ensure_authenticated("https://example.com") is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Login Success Detection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestLoginSuccessDetection:
    def _make_resp(
        self, text="", status=200, url="", cookies=None,
    ) -> MagicMock:
        resp = MagicMock()
        resp.text = text
        resp.status_code = status
        resp.url = url
        resp.cookies = cookies or {}
        return resp

    def test_failure_pattern_detected(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        mgr = AuthManager(client, config)
        resp = self._make_resp(text="Invalid credentials, please try again")
        assert mgr._check_login_success(resp, "https://example.com/login") is False

    def test_redirect_to_dashboard(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        mgr = AuthManager(client, config)
        resp = self._make_resp(
            text="<html>Dashboard</html>",
            url="https://example.com/dashboard",
        )
        assert mgr._check_login_success(resp, "https://example.com/login") is True

    def test_redirect_to_login_page(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        mgr = AuthManager(client, config)
        resp = self._make_resp(
            text="<html>Login</html>",
            url="https://example.com/signin",
        )
        assert mgr._check_login_success(resp, "https://example.com/login") is False

    def test_success_body_pattern(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        mgr = AuthManager(client, config)
        resp = self._make_resp(
            text="<html><a href='/logout'>Logout</a></html>",
            url="https://example.com/login",
        )
        assert mgr._check_login_success(resp, "https://example.com/login") is True

    def test_new_cookies_set(self):
        config = _config(auth_mode="form")
        client = _mock_client()
        mgr = AuthManager(client, config)
        resp = self._make_resp(
            text="<html>Loading</html>",
            url="https://example.com/login",
            cookies={"session_id": "abc"},
        )
        assert mgr._check_login_success(resp, "https://example.com/login") is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Unauthenticated Config
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestUnauthenticatedConfig:
    def test_creates_no_auth_config(self):
        config = _config(
            auth_mode="bearer",
            auth_token="tok123",
            passive_only=True,
        )
        client = _mock_client()
        mgr = AuthManager(client, config)
        unauth = mgr.create_unauthenticated_config()
        assert unauth.auth_mode == "none"
        assert unauth.auth_token is None
        assert unauth.passive_only is True
        assert unauth.accept_risk is True
        assert unauth.crawl_enabled is False

    def test_preserves_scope(self):
        scope = ScopePolicy(allowed_hosts=["target.example.com"])
        config = _config(auth_mode="bearer", auth_token="tok", scope=scope)
        client = _mock_client()
        mgr = AuthManager(client, config)
        unauth = mgr.create_unauthenticated_config()
        assert unauth.scope.allowed_hosts == ["target.example.com"]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Session Info
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestSessionInfo:
    def test_session_info_before_auth(self):
        config = _config(auth_mode="none")
        client = _mock_client()
        mgr = AuthManager(client, config)
        info = mgr.get_session_info()
        assert info["authenticated"] is False
        assert info["auth_mode"] == "none"
        assert info["login_url"] is None
        assert info["login_attempts"] == 0

    def test_session_info_after_auth(self):
        config = _config(
            auth_mode="form",
            auth_form_url="https://example.com/login",
            auth_form_data={"username": "admin", "password": "secret"},
        )
        client = _mock_client(
            post_status=302,
            post_url="https://example.com/dashboard",
            post_text="<html>Welcome dashboard</html>",
        )
        mgr = AuthManager(client, config)
        mgr.authenticate("https://example.com")
        info = mgr.get_session_info()
        assert info["authenticated"] is True
        assert info["login_url"] == "https://example.com/login"
        assert info["login_attempts"] == 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests — Integration with DastScanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TestDastConfigFromCLI:
    def test_login_user_password_to_form_data(self):
        args = MagicMock()
        args.target = "https://example.com"
        args.dast_scope = None
        args.dast_rate_limit = 10.0
        args.dast_max_requests = 10000
        args.timeout = 15
        args.dast_auth_mode = "form"
        args.dast_auth_token = None
        args.dast_login_url = "https://example.com/login"
        args.dast_login_user = "admin"
        args.dast_login_password = "secret"
        args.dast_no_crawl = False
        args.dast_passive_only = False
        args.dast_accept_risk = True
        args.dast_crawl_depth = 5
        args.dast_follow_subdomains = False

        config = DastConfig.from_cli_args(args)
        assert config.auth_form_data == {
            "username": "admin",
            "password": "secret",
        }
        assert config.auth_mode == "form"
        assert config.auth_form_url == "https://example.com/login"

    def test_no_login_user_no_form_data(self):
        args = MagicMock()
        args.target = "https://example.com"
        args.dast_scope = None
        args.dast_rate_limit = 10.0
        args.dast_max_requests = 10000
        args.timeout = 15
        args.dast_auth_mode = "none"
        args.dast_auth_token = None
        args.dast_login_url = None
        args.dast_login_user = None
        args.dast_login_password = None
        args.dast_no_crawl = False
        args.dast_passive_only = False
        args.dast_accept_risk = False
        args.dast_crawl_depth = 5
        args.dast_follow_subdomains = False

        config = DastConfig.from_cli_args(args)
        assert config.auth_form_data is None
