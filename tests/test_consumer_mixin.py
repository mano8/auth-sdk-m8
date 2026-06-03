"""Tests for auth_sdk_m8.core.consumer.ConsumerAuthMixin."""

import pytest
from pydantic import SecretStr, ValidationError
from pydantic_settings import SettingsConfigDict

from auth_sdk_m8.core.config import CommonSettings
from auth_sdk_m8.core.consumer import ConsumerAuthMixin
from tests.conftest import VALID_SETTINGS_KWARGS


class ConsumerSettings(ConsumerAuthMixin, CommonSettings):
    """Minimal consumer settings for tests."""

    model_config = SettingsConfigDict(env_file=None)


def _make(**overrides) -> ConsumerSettings:
    return ConsumerSettings(**{**VALID_SETTINGS_KWARGS, **overrides})


# ── Basic construction ────────────────────────────────────────────────────────


def test_consumer_mixin_stateless_no_introspection_ok() -> None:
    """Stateless consumer doesn't need INTROSPECTION_URL/PRIVATE_API_SECRET."""
    s = _make(
        AUTH_SERVICE_ROLE="consumer",
        TOKEN_MODE="stateless",
    )
    assert s.INTROSPECTION_URL is None
    assert s.PRIVATE_API_SECRET is None


def test_consumer_mixin_issuer_no_introspection_ok() -> None:
    """Issuer role never needs introspection fields."""
    s = _make(AUTH_SERVICE_ROLE="issuer")
    assert s.INTROSPECTION_URL is None


def test_consumer_mixin_stateful_with_fields_ok() -> None:
    """Stateful consumer with both fields validates cleanly."""
    s = _make(
        AUTH_SERVICE_ROLE="consumer",
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        PRIVATE_API_SECRET="supersecret",
    )
    assert s.INTROSPECTION_URL is not None
    assert isinstance(s.PRIVATE_API_SECRET, SecretStr)


# ── Validation failures ───────────────────────────────────────────────────────


def test_consumer_mixin_stateful_missing_both_raises() -> None:
    """Stateful consumer missing both fields raises ValidationError."""
    with pytest.raises(ValidationError, match="INTROSPECTION_URL"):
        _make(AUTH_SERVICE_ROLE="consumer", TOKEN_MODE="stateful")


def test_consumer_mixin_stateful_missing_secret_raises() -> None:
    """Stateful consumer with only INTROSPECTION_URL raises."""
    with pytest.raises(ValidationError, match="PRIVATE_API_SECRET"):
        _make(
            AUTH_SERVICE_ROLE="consumer",
            TOKEN_MODE="stateful",
            INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        )


def test_consumer_mixin_stateful_missing_url_raises() -> None:
    """Stateful consumer with only PRIVATE_API_SECRET raises."""
    with pytest.raises(ValidationError, match="INTROSPECTION_URL"):
        _make(
            AUTH_SERVICE_ROLE="consumer",
            TOKEN_MODE="stateful",
            PRIVATE_API_SECRET="supersecret",
        )


# ── Export ────────────────────────────────────────────────────────────────────


def test_consumer_auth_mixin_exported_from_core() -> None:
    from auth_sdk_m8.core import ConsumerAuthMixin as _C

    assert _C is ConsumerAuthMixin
