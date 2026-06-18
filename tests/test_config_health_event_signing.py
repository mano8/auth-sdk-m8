"""Phase 7.x.1 — event-signing rollout flag tests.

Covers:
- _check_event_signing_config(): all rule branches
- check_config_health() integration: event-signing warnings/fatals flow through
"""

from typing import cast

import pytest

from auth_sdk_m8.core.config_health import (
    _check_event_signing_config,
    _SettingsProto,
    check_config_health,
)
from auth_sdk_m8.core.exceptions import ConfigurationError
from tests.conftest import VALID_SETTINGS_KWARGS, IsolatedSettings

# ── CommonSettings event-signing fields ──────────────────────────────────────


def test_event_signing_enabled_defaults_true() -> None:
    """EVENT_SIGNING_ENABLED defaults to True (secure-by-default)."""
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)
    assert s.EVENT_SIGNING_ENABLED is True


def test_event_signing_accept_unsigned_defaults_false() -> None:
    """EVENT_SIGNING_ACCEPT_UNSIGNED defaults to False."""
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)
    assert s.EVENT_SIGNING_ACCEPT_UNSIGNED is False


# ── _check_event_signing_config unit tests ────────────────────────────────────


class _E:
    """Minimal settings stub for _check_event_signing_config tests."""

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


def test_no_event_signing_attr_is_noop() -> None:
    """Settings without EVENT_SIGNING_ENABLED attribute → no-op (backward-compat)."""

    class _NoAttr:
        pass

    fatal, warnings = _check_event_signing_config(
        cast("_SettingsProto", _NoAttr()), "production", True
    )
    assert fatal == []
    assert warnings == []


def test_signing_enabled_no_accept_unsigned_clean() -> None:
    """EVENT_SIGNING_ENABLED=true + ACCEPT_UNSIGNED=false → clean in all envs."""
    s = _E(EVENT_SIGNING_ENABLED=True, EVENT_SIGNING_ACCEPT_UNSIGNED=False)
    for env in ("local", "development", "staging", "production"):
        fatal, warnings = _check_event_signing_config(s, env, False)
        assert fatal == [], env
        assert warnings == [], env


def test_signing_enabled_strict_clean() -> None:
    """EVENT_SIGNING_ENABLED=true + strict → clean."""
    s = _E(EVENT_SIGNING_ENABLED=True, EVENT_SIGNING_ACCEPT_UNSIGNED=False)
    fatal, warnings = _check_event_signing_config(s, "production", True)
    assert fatal == []
    assert warnings == []


# EVENT_SIGNING_ENABLED=false tests


def test_signing_disabled_non_strict_warns() -> None:
    """EVENT_SIGNING_ENABLED=false + non-strict → warning, no fatal."""
    s = _E(EVENT_SIGNING_ENABLED=False, EVENT_SIGNING_ACCEPT_UNSIGNED=False)
    fatal, warnings = _check_event_signing_config(s, "local", False)
    assert fatal == []
    assert any("EVENT_SIGNING_ENABLED=false" in w for w in warnings)


def test_signing_disabled_non_strict_all_envs_warn() -> None:
    """EVENT_SIGNING_ENABLED=false warns in all non-strict environments."""
    s = _E(EVENT_SIGNING_ENABLED=False, EVENT_SIGNING_ACCEPT_UNSIGNED=False)
    for env in ("local", "development", "staging", "production"):
        fatal, warnings = _check_event_signing_config(s, env, False)
        assert fatal == [], env
        assert any("EVENT_SIGNING_ENABLED=false" in w for w in warnings), env


def test_signing_disabled_strict_fatal() -> None:
    """EVENT_SIGNING_ENABLED=false + strict → fatal."""
    s = _E(EVENT_SIGNING_ENABLED=False, EVENT_SIGNING_ACCEPT_UNSIGNED=False)
    fatal, warnings = _check_event_signing_config(s, "production", True)
    assert any("EVENT_SIGNING_ENABLED=false" in f for f in fatal)
    assert warnings == []


def test_signing_disabled_strict_local_fatal() -> None:
    """EVENT_SIGNING_ENABLED=false + strict (local env) → fatal."""
    s = _E(EVENT_SIGNING_ENABLED=False, EVENT_SIGNING_ACCEPT_UNSIGNED=False)
    fatal, warnings = _check_event_signing_config(s, "local", True)
    assert any("EVENT_SIGNING_ENABLED=false" in f for f in fatal)
    assert warnings == []


# EVENT_SIGNING_ACCEPT_UNSIGNED=true tests


def test_accept_unsigned_dev_non_strict_warns() -> None:
    """ACCEPT_UNSIGNED=true in development (non-strict) → warning, no fatal."""
    s = _E(EVENT_SIGNING_ENABLED=True, EVENT_SIGNING_ACCEPT_UNSIGNED=True)
    fatal, warnings = _check_event_signing_config(s, "development", False)
    assert fatal == []
    assert any("EVENT_SIGNING_ACCEPT_UNSIGNED=true" in w for w in warnings)


def test_accept_unsigned_staging_non_strict_warns() -> None:
    """ACCEPT_UNSIGNED=true in staging (non-strict) → warning, no fatal."""
    s = _E(EVENT_SIGNING_ENABLED=True, EVENT_SIGNING_ACCEPT_UNSIGNED=True)
    fatal, warnings = _check_event_signing_config(s, "staging", False)
    assert fatal == []
    assert any("EVENT_SIGNING_ACCEPT_UNSIGNED=true" in w for w in warnings)


def test_accept_unsigned_local_non_strict_warns() -> None:
    """ACCEPT_UNSIGNED=true in local (non-strict) → warning, no fatal."""
    s = _E(EVENT_SIGNING_ENABLED=True, EVENT_SIGNING_ACCEPT_UNSIGNED=True)
    fatal, warnings = _check_event_signing_config(s, "local", False)
    assert fatal == []
    assert any("EVENT_SIGNING_ACCEPT_UNSIGNED=true" in w for w in warnings)


def test_accept_unsigned_production_non_strict_fatal() -> None:
    """ACCEPT_UNSIGNED=true in production (non-strict) → fatal."""
    s = _E(EVENT_SIGNING_ENABLED=True, EVENT_SIGNING_ACCEPT_UNSIGNED=True)
    fatal, warnings = _check_event_signing_config(s, "production", False)
    assert any("EVENT_SIGNING_ACCEPT_UNSIGNED=true" in f for f in fatal)
    assert warnings == []


def test_accept_unsigned_strict_fatal() -> None:
    """ACCEPT_UNSIGNED=true + strict (any env) → fatal."""
    s = _E(EVENT_SIGNING_ENABLED=True, EVENT_SIGNING_ACCEPT_UNSIGNED=True)
    for env in ("local", "development", "staging", "production"):
        fatal, warnings = _check_event_signing_config(s, env, True)
        assert any("EVENT_SIGNING_ACCEPT_UNSIGNED=true" in f for f in fatal), env
        assert warnings == [], env


# Both flags in bad state


def test_both_flags_unsafe_non_strict_two_warnings() -> None:
    """ENABLED=false + ACCEPT_UNSIGNED=true (non-strict, non-prod) → two warnings."""
    s = _E(EVENT_SIGNING_ENABLED=False, EVENT_SIGNING_ACCEPT_UNSIGNED=True)
    fatal, warnings = _check_event_signing_config(s, "staging", False)
    assert fatal == []
    assert len(warnings) == 2


def test_both_flags_unsafe_strict_two_fatals() -> None:
    """ENABLED=false + ACCEPT_UNSIGNED=true (strict) → two fatals."""
    s = _E(EVENT_SIGNING_ENABLED=False, EVENT_SIGNING_ACCEPT_UNSIGNED=True)
    fatal, warnings = _check_event_signing_config(s, "production", True)
    assert len(fatal) == 2
    assert warnings == []


# ── check_config_health integration ──────────────────────────────────────────


class _Log:
    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.criticals: list[str] = []

    def warning(self, msg: str, *args: object) -> None:
        self.warnings.append(msg % args if args else msg)

    def critical(self, msg: str, *args: object) -> None:
        self.criticals.append(msg % args if args else msg)


def _cfg(**kw: object) -> _E:
    base: dict = {
        "ACCESS_TOKEN_ALGORITHM": "HS256",
        "TOKEN_MODE": "stateless",
        "JWKS_CACHE_TTL_SECONDS": 300,
        "STRICT_PRODUCTION_MODE": False,
        "ENVIRONMENT": "local",
        "ALLOWED_HOSTS": ["example.com"],
        "EVENT_SIGNING_ENABLED": True,
        "EVENT_SIGNING_ACCEPT_UNSIGNED": False,
    }
    base.update(kw)
    return _E(**base)


def test_integration_signing_enabled_clean() -> None:
    """Default (signing on, no unsigned acceptance) → no event-signing warnings."""
    settings = _cfg()
    log = _Log()
    check_config_health(settings, log)
    assert not any("EVENT_SIGNING" in w for w in log.warnings)
    assert not any("EVENT_SIGNING" in c for c in log.criticals)


def test_integration_signing_disabled_non_strict_warns() -> None:
    """EVENT_SIGNING_ENABLED=false (non-strict local) → warning emitted."""
    settings = _cfg(EVENT_SIGNING_ENABLED=False)
    log = _Log()
    check_config_health(settings, log)
    assert any("EVENT_SIGNING_ENABLED=false" in w for w in log.warnings)
    assert not any("EVENT_SIGNING_ENABLED=false" in c for c in log.criticals)


def test_integration_signing_disabled_strict_fatal() -> None:
    """EVENT_SIGNING_ENABLED=false + strict → ConfigurationError raised."""
    settings = _cfg(
        ENVIRONMENT="production",
        STRICT_PRODUCTION_MODE=True,
        EVENT_SIGNING_ENABLED=False,
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
    assert any("EVENT_SIGNING_ENABLED=false" in c for c in log.criticals)


def test_integration_accept_unsigned_staging_warns() -> None:
    """ACCEPT_UNSIGNED=true in staging (non-strict) → warning only."""
    settings = _cfg(ENVIRONMENT="staging", EVENT_SIGNING_ACCEPT_UNSIGNED=True)
    log = _Log()
    check_config_health(settings, log)
    assert any("EVENT_SIGNING_ACCEPT_UNSIGNED=true" in w for w in log.warnings)
    assert not any("EVENT_SIGNING_ACCEPT_UNSIGNED=true" in c for c in log.criticals)


def test_integration_accept_unsigned_production_fatal() -> None:
    """ACCEPT_UNSIGNED=true in production (non-strict) → ConfigurationError."""
    settings = _cfg(
        ENVIRONMENT="production",
        EVENT_SIGNING_ACCEPT_UNSIGNED=True,
        ALLOWED_ORIGINS=[],
        SET_DOCS=False,
        SET_OPEN_API=False,
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    log = _Log()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, log)
    assert any("EVENT_SIGNING_ACCEPT_UNSIGNED=true" in c for c in log.criticals)


def test_integration_accept_unsigned_strict_fatal() -> None:
    """ACCEPT_UNSIGNED=true + strict → ConfigurationError raised."""
    settings = _cfg(
        ENVIRONMENT="production",
        STRICT_PRODUCTION_MODE=True,
        EVENT_SIGNING_ACCEPT_UNSIGNED=True,
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
    assert any("EVENT_SIGNING_ACCEPT_UNSIGNED=true" in c for c in log.criticals)
