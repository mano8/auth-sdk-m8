"""Tests for auth_sdk_m8.security.internal_auth — provider emission side (9.1).

Covers:
- StaticInternalAuth headers / invalidate / close semantics.
- static_internal_auth legacy (token only) and bootstrap (id + token) shapes.
- InternalAuthProvider runtime-checkable Protocol membership.
"""

import pytest

from auth_sdk_m8.security import (
    INTERNAL_CLIENT_HEADER,
    INTERNAL_TOKEN_HEADER,
    InternalAuthProvider,
    StaticInternalAuth,
    static_internal_auth,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# ── StaticInternalAuth ────────────────────────────────────────────────────────


async def test_static_headers_returns_copy() -> None:
    """headers() returns a fresh copy so callers can mutate it safely."""
    provider = StaticInternalAuth({INTERNAL_TOKEN_HEADER: "s3cret"})
    first = await provider.headers()
    first["Last-Event-ID"] = "1-1"
    second = await provider.headers()
    assert second == {INTERNAL_TOKEN_HEADER: "s3cret"}


async def test_static_init_copies_input_mapping() -> None:
    """The provider stores its own copy — later edits to the input don't leak."""
    source = {INTERNAL_TOKEN_HEADER: "s3cret"}
    provider = StaticInternalAuth(source)
    source[INTERNAL_TOKEN_HEADER] = "tampered"
    assert await provider.headers() == {INTERNAL_TOKEN_HEADER: "s3cret"}


async def test_static_invalidate_reports_no_retry() -> None:
    """A static provider has no cached credential, so a 401 is not retryable."""
    provider = StaticInternalAuth({INTERNAL_TOKEN_HEADER: "s3cret"})
    assert await provider.invalidate() is False


async def test_static_close_is_noop() -> None:
    """close() releases nothing and never raises for a static provider."""
    provider = StaticInternalAuth({INTERNAL_TOKEN_HEADER: "s3cret"})
    assert await provider.close() is None


# ── static_internal_auth builder ──────────────────────────────────────────────


async def test_builder_legacy_token_only() -> None:
    """No client id → legacy single X-Internal-Token header."""
    provider = static_internal_auth("s3cret")
    assert await provider.headers() == {INTERNAL_TOKEN_HEADER: "s3cret"}


async def test_builder_bootstrap_client_and_token() -> None:
    """A client id → bootstrap X-Internal-Client + X-Internal-Token pair."""
    provider = static_internal_auth("s3cret", client_id="media-worker")
    assert await provider.headers() == {
        INTERNAL_TOKEN_HEADER: "s3cret",
        INTERNAL_CLIENT_HEADER: "media-worker",
    }


async def test_builder_empty_client_id_is_legacy() -> None:
    """An empty client id is falsy → legacy shape (no X-Internal-Client)."""
    provider = static_internal_auth("s3cret", client_id="")
    assert await provider.headers() == {INTERNAL_TOKEN_HEADER: "s3cret"}


# ── Protocol membership ───────────────────────────────────────────────────────


def test_static_is_internal_auth_provider() -> None:
    """StaticInternalAuth satisfies the runtime-checkable provider Protocol."""
    assert isinstance(StaticInternalAuth({}), InternalAuthProvider)


def test_arbitrary_object_is_not_a_provider() -> None:
    """An object missing the provider methods fails the isinstance check."""
    assert not isinstance(object(), InternalAuthProvider)
