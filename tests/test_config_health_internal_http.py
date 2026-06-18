"""Phase 1.3 — internal http:// URL check tests.

Covers:
- CommonSettings.ALLOW_INTERNAL_HTTP field (default False)
- _check_internal_url_config(): all rule branches for JWKS_URI and
  INTROSPECTION_URL
- check_config_health() integration: http:// warnings/fatals flow through
"""

import pytest

from auth_sdk_m8.core.config_health import (
    _check_internal_url_config,
    check_config_health,
)
from auth_sdk_m8.core.exceptions import ConfigurationError
from tests.conftest import VALID_SETTINGS_KWARGS, IsolatedSettings

# ── CommonSettings.ALLOW_INTERNAL_HTTP field ─────────────────────────────────


def test_allow_internal_http_defaults_false() -> None:
    """ALLOW_INTERNAL_HTTP defaults to False (secure-by-default)."""
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)
    assert s.ALLOW_INTERNAL_HTTP is False


def test_allow_internal_http_can_be_set_true() -> None:
    """ALLOW_INTERNAL_HTTP can be explicitly opted in."""
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "ALLOW_INTERNAL_HTTP": True})
    assert s.ALLOW_INTERNAL_HTTP is True


# ── _check_internal_url_config unit tests ─────────────────────────────────────


class _S:
    """Minimal settings stub for _check_internal_url_config tests."""

    ACCESS_TOKEN_ALGORITHM = "HS256"
    TOKEN_MODE = "stateless"

    def __init__(self, **kw: object) -> None:
        self.__dict__.update(kw)

    @property
    def is_stateless(self) -> bool:
        return True

    @property
    def requires_redis(self) -> bool:
        return False


def test_local_http_jwks_uri_is_allowed() -> None:
    """http:// JWKS_URI in local environment → no warning (Docker bridge)."""
    s = _S(JWKS_URI="http://auth:9000/user/.well-known/jwks.json")
    fatal, warnings = _check_internal_url_config(s, "local", False)
    assert fatal == []
    assert warnings == []


def test_development_http_jwks_uri_is_allowed() -> None:
    """http:// JWKS_URI in development environment → no warning."""
    s = _S(JWKS_URI="http://auth:9000/user/.well-known/jwks.json")
    fatal, warnings = _check_internal_url_config(s, "development", False)
    assert fatal == []
    assert warnings == []


def test_staging_http_jwks_uri_warns() -> None:
    """http:// JWKS_URI in staging → warning (non-strict)."""
    s = _S(JWKS_URI="http://auth:9000/user/.well-known/jwks.json")
    fatal, warnings = _check_internal_url_config(s, "staging", False)
    assert fatal == []
    assert any("JWKS_URI" in w for w in warnings)
    assert any("http://" in w for w in warnings)


def test_production_http_jwks_uri_warns() -> None:
    """http:// JWKS_URI in production → warning (non-strict)."""
    s = _S(JWKS_URI="http://auth/user/.well-known/jwks.json")
    fatal, warnings = _check_internal_url_config(s, "production", False)
    assert fatal == []
    assert any("JWKS_URI" in w for w in warnings)


def test_production_http_jwks_uri_strict_fatal() -> None:
    """http:// JWKS_URI in production + strict → fatal."""
    s = _S(JWKS_URI="http://auth/user/.well-known/jwks.json")
    fatal, warnings = _check_internal_url_config(s, "production", True)
    assert any("JWKS_URI" in f for f in fatal)
    assert warnings == []


def test_https_jwks_uri_always_passes() -> None:
    """https:// JWKS_URI is always accepted regardless of environment."""
    s = _S(JWKS_URI="https://auth.example.com/user/.well-known/jwks.json")
    for env in ("local", "development", "staging", "production"):
        fatal, warnings = _check_internal_url_config(s, env, True)
        assert fatal == [], env
        assert warnings == [], env


def test_allow_internal_http_suppresses_warning() -> None:
    """ALLOW_INTERNAL_HTTP=true suppresses http:// warning in any environment."""
    s = _S(
        JWKS_URI="http://auth/user/.well-known/jwks.json",
        ALLOW_INTERNAL_HTTP=True,
    )
    for env in ("staging", "production"):
        fatal, warnings = _check_internal_url_config(s, env, True)
        assert fatal == [], env
        assert warnings == [], env


def test_no_url_fields_set_is_noop() -> None:
    """No JWKS_URI or INTROSPECTION_URL set → no warnings."""
    s = _S()
    fatal, warnings = _check_internal_url_config(s, "production", True)
    assert fatal == []
    assert warnings == []


def test_introspection_url_http_staging_warns() -> None:
    """http:// INTROSPECTION_URL in staging → warning."""
    s = _S(INTROSPECTION_URL="http://auth/user/introspect")
    fatal, warnings = _check_internal_url_config(s, "staging", False)
    assert any("INTROSPECTION_URL" in w for w in warnings)


def test_introspection_url_https_passes() -> None:
    """https:// INTROSPECTION_URL passes in all environments."""
    s = _S(INTROSPECTION_URL="https://auth.example.com/user/introspect")
    fatal, warnings = _check_internal_url_config(s, "production", True)
    assert fatal == []
    assert warnings == []


def test_both_fields_http_both_reported() -> None:
    """Both JWKS_URI and INTROSPECTION_URL with http:// → both reported."""
    s = _S(
        JWKS_URI="http://auth/jwks",
        INTROSPECTION_URL="http://auth/introspect",
    )
    fatal, warnings = _check_internal_url_config(s, "production", False)
    assert len(warnings) == 2
    assert any("JWKS_URI" in w for w in warnings)
    assert any("INTROSPECTION_URL" in w for w in warnings)


def test_warning_includes_environment_name() -> None:
    """Warning message must include the environment name for clarity."""
    s = _S(JWKS_URI="http://auth/jwks")
    _, warnings = _check_internal_url_config(s, "staging", False)
    assert any("staging" in w for w in warnings)


# ── check_config_health integration ──────────────────────────────────────────


class _Log:
    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.criticals: list[str] = []

    def warning(self, msg: str, *args: object) -> None:
        self.warnings.append(msg % args if args else msg)

    def critical(self, msg: str, *args: object) -> None:
        self.criticals.append(msg % args if args else msg)


def _cfg(**kw: object) -> _S:
    base: dict = {
        "ACCESS_TOKEN_ALGORITHM": "HS256",
        "TOKEN_MODE": "stateless",
        "JWKS_CACHE_TTL_SECONDS": 300,
        "STRICT_PRODUCTION_MODE": False,
        "ENVIRONMENT": "local",
        "ALLOWED_HOSTS": ["example.com"],
    }
    base.update(kw)
    return _S(**base)


def test_integration_local_http_no_warning() -> None:
    """Local env with http:// JWKS_URI → check_config_health: no http warning."""
    settings = _cfg(JWKS_URI="http://auth:9000/user/.well-known/jwks.json")
    log = _Log()
    check_config_health(settings, log)
    assert not any("http://" in w for w in log.warnings)
    assert not any("http://" in c for c in log.criticals)


def test_integration_prod_http_warns() -> None:
    """Production env with http:// JWKS_URI (non-strict) → warning emitted."""
    settings = _cfg(
        ENVIRONMENT="production",
        JWKS_URI="http://auth/user/.well-known/jwks.json",
        ALLOWED_ORIGINS=[],
        SET_DOCS=False,
        SET_OPEN_API=False,
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    log = _Log()
    check_config_health(settings, log)
    assert any("JWKS_URI" in w for w in log.warnings)
    assert not any("JWKS_URI" in c for c in log.criticals)


def test_integration_strict_http_fatal() -> None:
    """Strict mode with http:// JWKS_URI → ConfigurationError raised."""
    settings = _cfg(
        ENVIRONMENT="production",
        STRICT_PRODUCTION_MODE=True,
        # consumer role so JWKS_URI is legitimate and the http:// check fires
        AUTH_SERVICE_ROLE="consumer",
        JWKS_URI="http://auth/user/.well-known/jwks.json",
        ALLOWED_ORIGINS=["https://example.com"],
        SESSION_COOKIE_SECURE=True,
        SET_DOCS=False,
        SET_OPEN_API=False,
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    log = _Log()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, log)
    assert any("JWKS_URI" in c and "http://" in c for c in log.criticals)


def test_integration_allow_internal_http_suppresses_fatal() -> None:
    """ALLOW_INTERNAL_HTTP=true prevents ConfigurationError for http:// in strict."""
    settings = _cfg(
        ENVIRONMENT="production",
        STRICT_PRODUCTION_MODE=True,
        AUTH_SERVICE_ROLE="consumer",
        ALLOW_INTERNAL_HTTP=True,
        JWKS_URI="http://auth/user/.well-known/jwks.json",
        ALLOWED_ORIGINS=["https://example.com"],
        SESSION_COOKIE_SECURE=True,
        SET_DOCS=False,
        SET_OPEN_API=False,
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    log = _Log()
    check_config_health(settings, log)
    assert not any("http://" in c for c in log.criticals)
