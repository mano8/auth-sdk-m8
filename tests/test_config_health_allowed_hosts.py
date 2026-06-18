"""Phase 1.2 — ALLOWED_HOSTS production gate tests.

Covers:
- CommonSettings.ALLOWED_HOSTS field: parsing (string, list, None)
- _check_allowed_hosts_config(): all rule branches
- check_config_health() integration: allowed_hosts warnings/fatals flow through
"""

import pytest

from auth_sdk_m8.core.config_health import _check_allowed_hosts_config, check_config_health
from auth_sdk_m8.core.exceptions import ConfigurationError
from tests.conftest import VALID_SETTINGS_KWARGS, IsolatedSettings


# ── CommonSettings.ALLOWED_HOSTS field / parse_allowed_hosts ─────────────────


def test_allowed_hosts_defaults_to_none() -> None:
    """ALLOWED_HOSTS is None by default (host checking disabled)."""
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)
    assert s.ALLOWED_HOSTS is None


def test_allowed_hosts_from_comma_string() -> None:
    """Comma-separated string is parsed into a list."""
    s = IsolatedSettings(
        **{**VALID_SETTINGS_KWARGS, "ALLOWED_HOSTS": "example.com,www.example.com"}
    )
    assert s.ALLOWED_HOSTS == ["example.com", "www.example.com"]


def test_allowed_hosts_strips_whitespace() -> None:
    """Whitespace around host names is stripped."""
    s = IsolatedSettings(
        **{**VALID_SETTINGS_KWARGS, "ALLOWED_HOSTS": " api.example.com , localhost "}
    )
    assert s.ALLOWED_HOSTS == ["api.example.com", "localhost"]


def test_allowed_hosts_empty_string_returns_none() -> None:
    """An empty/whitespace-only string is treated as unset (None)."""
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "ALLOWED_HOSTS": "   "})
    assert s.ALLOWED_HOSTS is None


def test_allowed_hosts_from_list() -> None:
    """A pre-parsed list is accepted and preserved."""
    s = IsolatedSettings(
        **{**VALID_SETTINGS_KWARGS, "ALLOWED_HOSTS": ["example.com", "localhost"]}
    )
    assert s.ALLOWED_HOSTS == ["example.com", "localhost"]


def test_allowed_hosts_from_empty_list_returns_none() -> None:
    """An empty list is normalised to None."""
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "ALLOWED_HOSTS": []})
    assert s.ALLOWED_HOSTS is None


def test_allowed_hosts_single_host() -> None:
    """A single hostname string is parsed into a one-element list."""
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "ALLOWED_HOSTS": "localhost"})
    assert s.ALLOWED_HOSTS == ["localhost"]


def test_allowed_hosts_testserver_non_prod() -> None:
    """ALLOWED_HOSTS=['testserver'] in local env is valid (TrustedHostMiddleware compat)."""
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "ALLOWED_HOSTS": "testserver"})
    assert s.ALLOWED_HOSTS == ["testserver"]
    assert s.ENVIRONMENT == "local"


# ── _check_allowed_hosts_config ───────────────────────────────────────────────


class _H:
    """Minimal settings stub for _check_allowed_hosts_config unit tests."""

    ACCESS_TOKEN_ALGORITHM = "HS256"
    TOKEN_MODE = "stateless"

    def __init__(self, **kw):
        self.__dict__.update(kw)

    @property
    def is_stateless(self):
        return True

    @property
    def requires_redis(self):
        return False


def test_no_attr_is_noop() -> None:
    """Settings without ALLOWED_HOSTS attribute → no-op (backward-compat)."""
    class _NoAttr:
        pass
    fatal, warnings = _check_allowed_hosts_config(_NoAttr(), "production", True)
    assert fatal == []
    assert warnings == []


def test_local_empty_is_noop() -> None:
    """local + empty/None ALLOWED_HOSTS → no warning (homelab safe)."""
    settings = _H(ALLOWED_HOSTS=None)
    fatal, warnings = _check_allowed_hosts_config(settings, "local", False)
    assert fatal == []
    assert warnings == []


def test_local_empty_strict_raises() -> None:
    """strict mode + empty ALLOWED_HOSTS → fatal even in local."""
    settings = _H(ALLOWED_HOSTS=None)
    fatal, warnings = _check_allowed_hosts_config(settings, "local", True)
    assert any("ALLOWED_HOSTS" in f for f in fatal)
    assert warnings == []


def test_prod_empty_warns() -> None:
    """production + empty ALLOWED_HOSTS (no strict) → warning only."""
    settings = _H(ALLOWED_HOSTS=None)
    fatal, warnings = _check_allowed_hosts_config(settings, "production", False)
    assert fatal == []
    assert any("ALLOWED_HOSTS" in w for w in warnings)


def test_prod_empty_strict_raises() -> None:
    """production + empty ALLOWED_HOSTS + strict → fatal."""
    settings = _H(ALLOWED_HOSTS=None)
    fatal, warnings = _check_allowed_hosts_config(settings, "production", True)
    assert any("ALLOWED_HOSTS" in f for f in fatal)
    assert warnings == []


def test_strict_wildcard_raises() -> None:
    """strict mode with '*' in ALLOWED_HOSTS → fatal."""
    settings = _H(ALLOWED_HOSTS=["*"])
    fatal, warnings = _check_allowed_hosts_config(settings, "production", True)
    assert any("wildcard" in f for f in fatal)


def test_non_strict_wildcard_no_fatal() -> None:
    """Non-strict + '*' → not fatal (warn via empty check doesn't apply)."""
    settings = _H(ALLOWED_HOSTS=["*"])
    fatal, warnings = _check_allowed_hosts_config(settings, "production", False)
    assert not any("wildcard" in f for f in fatal)


def test_valid_hosts_non_prod_no_warning() -> None:
    """Configured non-wildcard hosts in any env → clean."""
    settings = _H(ALLOWED_HOSTS=["example.com", "www.example.com"])
    for env in ("local", "development", "staging", "production"):
        fatal, warnings = _check_allowed_hosts_config(settings, env, False)
        assert fatal == [], env
        assert warnings == [], env


def test_valid_hosts_strict_no_warning() -> None:
    """Configured non-wildcard hosts in strict mode → clean."""
    settings = _H(ALLOWED_HOSTS=["example.com"])
    fatal, warnings = _check_allowed_hosts_config(settings, "production", True)
    assert fatal == []
    assert warnings == []


# ── check_config_health integration ──────────────────────────────────────────


class _MinimalLogger:
    def __init__(self):
        self.warnings: list[str] = []
        self.criticals: list[str] = []

    def warning(self, msg: str, *args: object) -> None:
        self.warnings.append(msg % args if args else msg)

    def critical(self, msg: str, *args: object) -> None:
        self.criticals.append(msg % args if args else msg)


def _base(**kw):
    base = {
        "ACCESS_TOKEN_ALGORITHM": "HS256",
        "TOKEN_MODE": "stateless",
        "JWKS_CACHE_TTL_SECONDS": 300,
        "STRICT_PRODUCTION_MODE": False,
        "ENVIRONMENT": "local",
    }
    base.update(kw)
    return _H(**base)


def test_integration_local_no_hosts_clean() -> None:
    """Local env + no ALLOWED_HOSTS → check_config_health produces no host warning."""
    settings = _base(ALLOWED_HOSTS=None)
    log = _MinimalLogger()
    check_config_health(settings, log)
    assert not any("ALLOWED_HOSTS" in w for w in log.warnings)
    assert not any("ALLOWED_HOSTS" in c for c in log.criticals)


def test_integration_prod_no_hosts_warns() -> None:
    """Production + no ALLOWED_HOSTS (non-strict) → warning emitted."""
    settings = _base(
        ENVIRONMENT="production",
        ALLOWED_HOSTS=None,
        ALLOWED_ORIGINS=[],
        SET_DOCS=False,
        SET_OPEN_API=False,
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    log = _MinimalLogger()
    check_config_health(settings, log)
    assert any("ALLOWED_HOSTS" in w for w in log.warnings)
    assert not any("ALLOWED_HOSTS" in c for c in log.criticals)


def test_integration_strict_no_hosts_fatal() -> None:
    """Strict mode + no ALLOWED_HOSTS → ConfigurationError raised."""
    settings = _base(
        ENVIRONMENT="production",
        STRICT_PRODUCTION_MODE=True,
        ALLOWED_HOSTS=None,
        ALLOWED_ORIGINS=["https://example.com"],
        SESSION_COOKIE_SECURE=True,
        SET_DOCS=False,
        SET_OPEN_API=False,
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    log = _MinimalLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, log)
    assert any("ALLOWED_HOSTS" in c for c in log.criticals)


def test_integration_strict_wildcard_hosts_fatal() -> None:
    """Strict mode + ALLOWED_HOSTS=['*'] → ConfigurationError for wildcard."""
    settings = _base(
        ENVIRONMENT="production",
        STRICT_PRODUCTION_MODE=True,
        ALLOWED_HOSTS=["*"],
        ALLOWED_ORIGINS=["https://example.com"],
        SESSION_COOKIE_SECURE=True,
        SET_DOCS=False,
        SET_OPEN_API=False,
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    log = _MinimalLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, log)
    assert any("wildcard" in c for c in log.criticals)


def test_integration_strict_valid_hosts_passes() -> None:
    """Strict mode + explicit ALLOWED_HOSTS → passes cleanly."""
    settings = _base(
        ENVIRONMENT="production",
        STRICT_PRODUCTION_MODE=True,
        ALLOWED_HOSTS=["example.com", "www.example.com"],
        ALLOWED_ORIGINS=["https://example.com"],
        SESSION_COOKIE_SECURE=True,
        SET_DOCS=False,
        SET_OPEN_API=False,
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    log = _MinimalLogger()
    check_config_health(settings, log)
    assert not any("ALLOWED_HOSTS" in c for c in log.criticals)
    assert not any("ALLOWED_HOSTS" in w for w in log.warnings)
