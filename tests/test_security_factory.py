"""Tests for build_access_validator factory function."""

from unittest.mock import MagicMock

import pytest

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.security import (
    TokenValidator,
    ValidationHooks,
    build_access_validator,
)
from tests.conftest import (
    VALID_SETTINGS_KWARGS,
    IsolatedSettings,
    make_access_token,
)

# ── helpers ──────────────────────────────────────────────────────────────────


def _mock_hooks() -> MagicMock:
    return MagicMock(spec=ValidationHooks)


def _hs256_settings(**overrides) -> IsolatedSettings:
    return IsolatedSettings(**{**VALID_SETTINGS_KWARGS, **overrides})


# ── build_access_validator ────────────────────────────────────────────────────


def test_returns_token_validator(valid_settings) -> None:
    assert isinstance(build_access_validator(valid_settings), TokenValidator)


def test_hs256_validates_token(valid_settings) -> None:
    validator = build_access_validator(valid_settings)
    payload = validator.validate_access_token(make_access_token())
    assert payload.sub == "user-123"


def test_hooks_are_wired(valid_settings) -> None:
    hooks = _mock_hooks()
    validator = build_access_validator(valid_settings, hooks=hooks)

    validator.validate_access_token(make_access_token())

    hooks.on_success.assert_called_once_with(
        jti="test-jti-0000", sub="user-123", token_type="access"
    )
    hooks.on_failure.assert_not_called()


def test_hooks_none_does_not_raise(valid_settings) -> None:
    validator = build_access_validator(valid_settings, hooks=None)
    payload = validator.validate_access_token(make_access_token())
    assert payload.sub == "user-123"


def test_hooks_on_failure_called_for_bad_token(valid_settings) -> None:
    hooks = _mock_hooks()
    validator = build_access_validator(valid_settings, hooks=hooks)

    with pytest.raises(InvalidToken):
        validator.validate_access_token(make_access_token(secret="wrong-key"))

    hooks.on_failure.assert_called_once_with(reason="invalid", token_type="access")


def test_issuer_and_audience_not_required_when_unset(valid_settings) -> None:
    # When TOKEN_ISSUER / TOKEN_AUDIENCE are empty the validator must not
    # enforce them — getattr falls back to None which disables the checks.
    validator = build_access_validator(valid_settings)
    payload = validator.validate_access_token(make_access_token())
    assert payload.sub == "user-123"


def test_rs256_uses_public_key_branch() -> None:
    # Verifies the asymmetric code path: ACCESS_PUBLIC_KEY is read instead of
    # ACCESS_SECRET_KEY and the validator is constructed without error.
    settings = MagicMock()
    settings.ACCESS_TOKEN_ALGORITHM = "RS256"
    settings.ACCESS_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\ndummy\n-----END PUBLIC KEY-----"
    settings.ACCESS_SECRET_KEY = None  # should be ignored for asymmetric
    # getattr fallback used by factory.py
    del settings.TOKEN_ISSUER
    del settings.TOKEN_AUDIENCE

    validator = build_access_validator(settings)
    assert isinstance(validator, TokenValidator)
