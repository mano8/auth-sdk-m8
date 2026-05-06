"""Tests for auth_sdk_m8.security.token_policy."""

from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security import (
    SessionStore,
    TokenPolicy,
    TokenValidationConfig,
    TokenValidator,
)
from tests.conftest import VALID_KEY, make_access_token


class _RevocationStore(SessionStore):
    def __init__(self, revoked: bool) -> None:
        self.is_revoked = AsyncMock(return_value=revoked)


def _make_policy(store: SessionStore | None = None) -> TokenPolicy:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(),
    )
    return TokenPolicy(validator=validator, store=store)


@pytest.mark.asyncio
async def test_token_policy_passes_without_store() -> None:
    payload = await _make_policy().validate(make_access_token())

    assert payload.sub == "user-123"


@pytest.mark.asyncio
async def test_token_policy_rejects_revoked_token() -> None:
    store = _RevocationStore(revoked=True)

    with pytest.raises(InvalidToken, match="Token revoked"):
        await _make_policy(store).validate(make_access_token())

    store.is_revoked.assert_awaited_once_with("test-jti-0000")


@pytest.mark.asyncio
async def test_token_policy_checks_store_and_returns_payload() -> None:
    store = _RevocationStore(revoked=False)

    payload = await _make_policy(store).validate(make_access_token())

    assert payload.jti == "test-jti-0000"
    store.is_revoked.assert_awaited_once_with("test-jti-0000")
