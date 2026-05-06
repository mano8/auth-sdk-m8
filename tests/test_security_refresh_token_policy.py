"""Tests for auth_sdk_m8.security.refresh_token_policy."""

import uuid
from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security import RefreshTokenPolicy, RefreshTokenStore
from tests.conftest import VALID_KEY, make_refresh_token


class _MockStore(RefreshTokenStore):
    def __init__(self, valid: bool = True) -> None:
        self.is_valid = AsyncMock(return_value=valid)
        self.rotate = AsyncMock()
        self.revoke = AsyncMock()


def _make_policy(
    store: RefreshTokenStore | None = None,
    hooks=None,
) -> RefreshTokenPolicy:
    return RefreshTokenPolicy(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        store=store,
        hooks=hooks,
    )


async def test_validate_and_rotate_without_store() -> None:
    policy = _make_policy()
    user_id, old_jti = await policy.validate_and_rotate(
        make_refresh_token(), new_jti="new-jti-0000"
    )

    assert isinstance(user_id, uuid.UUID)
    assert old_jti == "test-jti-0000"


async def test_validate_and_rotate_with_valid_store() -> None:
    store = _MockStore(valid=True)
    policy = _make_policy(store=store)

    user_id, old_jti = await policy.validate_and_rotate(
        make_refresh_token(), new_jti="new-jti-0000"
    )

    store.is_valid.assert_awaited_once_with("test-jti-0000")
    store.rotate.assert_awaited_once_with("test-jti-0000", "new-jti-0000", 86_400)
    assert old_jti == "test-jti-0000"
    assert isinstance(user_id, uuid.UUID)


async def test_validate_and_rotate_rejects_reused_token() -> None:
    store = _MockStore(valid=False)
    policy = _make_policy(store=store)

    with pytest.raises(InvalidToken, match="already used or revoked"):
        await policy.validate_and_rotate(make_refresh_token(), new_jti="new-jti")

    store.is_valid.assert_awaited_once()
    store.rotate.assert_not_awaited()


async def test_validate_and_rotate_custom_ttl() -> None:
    store = _MockStore(valid=True)
    policy = _make_policy(store=store)

    await policy.validate_and_rotate(
        make_refresh_token(), new_jti="new-jti", ttl_seconds=3600
    )

    store.rotate.assert_awaited_once_with("test-jti-0000", "new-jti", 3600)


async def test_validate_and_rotate_rejects_invalid_token() -> None:
    policy = _make_policy()

    with pytest.raises(InvalidToken):
        await policy.validate_and_rotate("not-a-token", new_jti="new-jti")


async def test_validate_and_rotate_rejects_expired_token() -> None:
    policy = _make_policy()
    expired = make_refresh_token(exp=1)

    with pytest.raises(InvalidToken, match="expired"):
        await policy.validate_and_rotate(expired, new_jti="new-jti")


async def test_validate_and_rotate_rejects_wrong_token_type() -> None:
    policy = _make_policy()
    access_token = make_refresh_token(type="access")

    with pytest.raises(InvalidToken, match="Not a refresh token"):
        await policy.validate_and_rotate(access_token, new_jti="new-jti")


async def test_revoke_delegates_to_store() -> None:
    store = _MockStore()
    policy = _make_policy(store=store)

    await policy.revoke("test-jti-0000")

    store.revoke.assert_awaited_once_with("test-jti-0000")


async def test_revoke_without_store_is_noop() -> None:
    policy = _make_policy()

    await policy.revoke("test-jti-0000")  # must not raise


# ── Hook integration ─────────────────────────────────────────────────────────


async def test_hooks_on_success_called_for_valid_rotation() -> None:
    from unittest.mock import MagicMock

    from auth_sdk_m8.security import ValidationHooks

    hooks = MagicMock(spec=ValidationHooks)
    store = _MockStore(valid=True)
    policy = _make_policy(store=store, hooks=hooks)

    user_id, _ = await policy.validate_and_rotate(
        make_refresh_token(), new_jti="new-jti"
    )

    hooks.on_success.assert_called_once_with(
        jti="new-jti", sub=str(user_id), token_type="refresh"
    )
    hooks.on_failure.assert_not_called()


async def test_hooks_on_failure_called_for_reused_token() -> None:
    from unittest.mock import MagicMock

    from auth_sdk_m8.security import ValidationHooks

    hooks = MagicMock(spec=ValidationHooks)
    store = _MockStore(valid=False)
    policy = _make_policy(store=store, hooks=hooks)

    with pytest.raises(InvalidToken):
        await policy.validate_and_rotate(make_refresh_token(), new_jti="new-jti")

    hooks.on_failure.assert_called_once_with(reason="reused", token_type="refresh")


async def test_hooks_on_failure_called_for_invalid_refresh_token() -> None:
    from unittest.mock import MagicMock

    from auth_sdk_m8.security import ValidationHooks

    hooks = MagicMock(spec=ValidationHooks)
    policy = _make_policy(hooks=hooks)

    with pytest.raises(InvalidToken):
        await policy.validate_and_rotate("not-a-token", new_jti="new-jti")

    hooks.on_failure.assert_called_once_with(reason="invalid", token_type="refresh")


# ── Edge-case branches in _decode_refresh ───────────────────────────────────


async def test_validate_and_rotate_rejects_non_uuid_sub() -> None:
    # sub is present but not a valid UUID — hits the UUID parse error branch.
    policy = _make_policy()
    bad_sub_token = make_refresh_token(sub="not-a-uuid")

    with pytest.raises(InvalidToken):
        await policy.validate_and_rotate(bad_sub_token, new_jti="new-jti")


async def test_validate_and_rotate_rejects_empty_jti() -> None:
    # jti is an empty string — passes PyJWT "require" but fails the isinstance check.
    policy = _make_policy()
    empty_jti_token = make_refresh_token(jti="")

    with pytest.raises(InvalidToken):
        await policy.validate_and_rotate(empty_jti_token, new_jti="new-jti")
