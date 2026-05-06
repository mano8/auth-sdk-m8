"""Tests for ValidationHooks integration in TokenValidator and TokenPolicy."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security import (
    SessionStore,
    TokenPolicy,
    TokenValidationConfig,
    TokenValidator,
    ValidationHooks,
)
from tests.conftest import VALID_KEY, make_access_token


def _mock_hooks() -> MagicMock:
    return MagicMock(spec=ValidationHooks)


def _make_validator(hooks=None) -> TokenValidator:
    return TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(),
        hooks=hooks,
    )


# ── TokenValidator hook tests ────────────────────────────────────────────────


def test_hooks_on_success_called_for_valid_token() -> None:
    hooks = _mock_hooks()
    validator = _make_validator(hooks=hooks)

    validator.validate_access_token(make_access_token())

    hooks.on_success.assert_called_once_with(
        jti="test-jti-0000", sub="user-123", token_type="access"
    )
    hooks.on_failure.assert_not_called()


def test_hooks_on_failure_called_for_expired_token() -> None:
    hooks = _mock_hooks()
    validator = _make_validator(hooks=hooks)
    past = int((datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp())

    with pytest.raises(InvalidToken):
        validator.validate_access_token(make_access_token(exp=past))

    hooks.on_failure.assert_called_once_with(reason="expired", token_type="access")
    hooks.on_success.assert_not_called()


def test_hooks_on_failure_called_for_invalid_signature() -> None:
    hooks = _mock_hooks()
    validator = _make_validator(hooks=hooks)

    with pytest.raises(InvalidToken):
        validator.validate_access_token(make_access_token(secret="wrong-secret-key"))

    hooks.on_failure.assert_called_once_with(reason="invalid", token_type="access")


def test_hooks_on_failure_called_for_wrong_type() -> None:
    hooks = _mock_hooks()
    validator = _make_validator(hooks=hooks)

    with pytest.raises(InvalidToken, match="Not an access token"):
        validator.validate_access_token(make_access_token(type="refresh"))

    hooks.on_failure.assert_called_once_with(reason="wrong_type", token_type="access")


def test_hooks_on_failure_called_for_invalid_payload() -> None:
    hooks = _mock_hooks()
    validator = _make_validator(hooks=hooks)

    with pytest.raises(InvalidToken):
        validator.validate_access_token(make_access_token(email="not-an-email"))

    hooks.on_failure.assert_called_once_with(
        reason="invalid_payload", token_type="access"
    )


def test_no_hooks_does_not_raise() -> None:
    validator = _make_validator(hooks=None)

    payload = validator.validate_access_token(make_access_token())

    assert payload.sub == "user-123"


# ── TokenPolicy hook tests ───────────────────────────────────────────────────


class _RevocationStore(SessionStore):
    def __init__(self, revoked: bool) -> None:
        from unittest.mock import AsyncMock

        self.is_revoked = AsyncMock(return_value=revoked)


async def test_policy_hooks_on_failure_called_for_revoked_token() -> None:
    hooks = _mock_hooks()
    store = _RevocationStore(revoked=True)
    validator = _make_validator()
    policy = TokenPolicy(validator=validator, store=store, hooks=hooks)

    with pytest.raises(InvalidToken, match="Token revoked"):
        await policy.validate(make_access_token())

    hooks.on_failure.assert_called_once_with(reason="revoked", token_type="access")


async def test_policy_hooks_not_called_for_valid_token() -> None:
    hooks = _mock_hooks()
    store = _RevocationStore(revoked=False)
    validator = _make_validator()
    policy = TokenPolicy(validator=validator, store=store, hooks=hooks)

    payload = await policy.validate(make_access_token())

    assert payload.sub == "user-123"
    hooks.on_failure.assert_not_called()
