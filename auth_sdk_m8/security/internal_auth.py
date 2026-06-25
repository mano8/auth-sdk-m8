"""Internal-auth header providers for private-call authentication (Phase 9.1).

This is the **emission** side of per-consumer credentials: a small,
framework-agnostic contract that supplies (and refreshes) the HTTP headers a
consumer attaches to a private call against the fa-auth-m8 issuer — the
JTI-status / revocation introspection endpoint and the SSE event stream.

Two header shapes are supported, selected by the *caller* (config-driven in the
consuming framework):

* **bootstrap** — the per-consumer ``X-Internal-Client`` + ``X-Internal-Token``
  pair (blast radius is one consumer; the issuer gates each route by scope);
* **service token** — an ``Authorization: Bearer`` short-TTL JWT obtained by
  exchanging the bootstrap credential. The SDK ships the **static** bootstrap
  shape here; a dynamic exchange provider is supplied by the consuming framework
  (``fastapi-m8``) and only has to satisfy :class:`InternalAuthProvider`.

The legacy single shared ``PRIVATE_API_SECRET`` presented as a bare
``X-Internal-Token`` (no consumer id) has been **retired** — per-consumer
credentials are the only private-API auth path, so every caller is identifiable
and individually revocable.

The *verification* primitives (the issuer side) live in
:mod:`auth_sdk_m8.security.consumer_auth`; this module owns only the emission
side and is deliberately transport-agnostic, so both the SDK's
:class:`~auth_sdk_m8.events.AuthEventStreamClient` and a consumer's revocation
HTTP client can drive one provider contract.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from auth_sdk_m8.security.consumer_auth import (
    INTERNAL_CLIENT_HEADER,
    INTERNAL_TOKEN_HEADER,
)


@runtime_checkable
class InternalAuthProvider(Protocol):
    """Supplies (and refreshes) the auth headers for a private call.

    Concrete providers may be **static** (a fixed header set) or **dynamic**
    (mint a short-TTL service token on demand, refreshing it before expiry). The
    contract is intentionally tiny so any transport — the SSE stream client, a
    consumer's revocation HTTP client — can drive the same provider.
    """

    async def headers(self) -> dict[str, str]:
        """Return the headers to attach to the next private request."""
        ...

    async def invalidate(self) -> bool:
        """Drop any cached credential after a rejected (``401``) call.

        Returns ``True`` when a retry is worthwhile — a fresh credential will be
        minted on the next :meth:`headers` call (service-token mode) — and
        ``False`` for static modes, where a ``401`` means a misconfigured secret
        and retrying cannot help.
        """
        ...

    async def close(self) -> None:
        """Release any owned resources (e.g. an exchange HTTP client)."""
        ...


class StaticInternalAuth:
    """An :class:`InternalAuthProvider` that returns a fixed header set.

    Covers the **bootstrap** (``X-Internal-Client`` + ``X-Internal-Token``)
    mode. It carries no cached credential, so a ``401`` is a configuration error
    and :meth:`invalidate` reports that no retry can help.
    """

    def __init__(self, headers: dict[str, str]) -> None:
        """Store a private copy of the fixed *headers* set."""
        self._headers = dict(headers)

    async def headers(self) -> dict[str, str]:
        """Return a copy of the fixed header set."""
        return dict(self._headers)

    async def invalidate(self) -> bool:
        """Report that no cached credential exists; a ``401`` is a config error."""
        return False

    async def close(self) -> None:
        """Release nothing — a static provider owns no resources."""
        return None


def static_internal_auth(secret: str, *, client_id: str) -> StaticInternalAuth:
    """Build a static provider for the per-consumer **bootstrap** header shape.

    Args:
        secret: This consumer's bootstrap secret, sent as ``X-Internal-Token``.
        client_id: The non-empty ``X-Internal-Client`` value identifying the
            consumer. Required — the legacy token-only shape has been retired,
            so every caller must identify itself.

    Returns:
        A :class:`StaticInternalAuth` carrying the
        ``X-Internal-Client`` + ``X-Internal-Token`` pair.

    Raises:
        ValueError: If *client_id* is empty.
    """
    if not client_id:
        raise ValueError("client_id is required (the legacy token-only shape is retired)")
    return StaticInternalAuth(
        {INTERNAL_TOKEN_HEADER: secret, INTERNAL_CLIENT_HEADER: client_id}
    )
