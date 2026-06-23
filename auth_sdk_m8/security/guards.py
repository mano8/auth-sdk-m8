"""Proxy-independent app-layer guards for ``/metrics`` and deep ``/health``.

Requires ``fastapi`` to be installed — already true for any m8 FastAPI service
(consumer apps via ``fastapi_m8.create_app`` and the issuer ``fa-auth-m8``).
Install ``auth-sdk-m8[fastapi]`` only when pulling this into a context without
FastAPI.

Why this lives in the SDK
-------------------------
The security guarantee for sensitive operational surfaces (``/private``,
``/metrics``, deep ``/health`` detail) must hold **at the application layer**, so
it survives a reverse-proxy swap or misconfiguration (Traefik → nginx → Caddy →
none). Proxy route-hiding stays valuable as defense-in-depth, but it is not the
primary control. ``auth-sdk-m8`` is the only common dependency of both the
issuer (``fa-auth-m8``) and the consumer framework (``fastapi-m8``), so the
shared primitives live here and every service reuses one implementation instead
of each re-deriving its own ``X-Internal-Token`` comparison.

Two distinct shapes
-------------------
The two surfaces want different behaviour, so this module exposes two helpers:

- **Detail gating (a predicate)** — deep ``/health`` answers a *shallow* status
  to everyone and reveals the *detail* body only to authorized callers. The
  endpoint must keep responding either way, so it needs a ``bool`` predicate,
  not a hard gate. Use :func:`make_internal_token_authorizer`.
- **Hard gate (a dependency)** — ``/metrics`` is internal-only and, when it must
  cross a less-trusted boundary, may carry an **optional static scoped scrape
  credential** (a Prometheus ``authorization`` bearer). When that credential is
  configured the request must present it or be rejected outright. Use
  :func:`make_scrape_credential_guard`.

Both build on :func:`compare_secret`, a ``None``-safe constant-time comparison.
"""

from __future__ import annotations

import secrets
from typing import Callable

from fastapi import HTTPException, Request, status

from auth_sdk_m8.security.consumer_auth import (
    INTERNAL_CLIENT_HEADER,
    ConsumerAuthenticationError,
    ConsumerCredential,
    ConsumerCredentialRegistry,
    ConsumerScopeError,
)

#: Default header the m8 trio uses for the inter-service shared secret.
INTERNAL_TOKEN_HEADER = "X-Internal-Token"  # nosec B105 — header name, not a secret value
#: Prefix (case-insensitive) of an ``Authorization: Bearer <token>`` header.
_BEARER_PREFIX = "bearer "


def compare_secret(provided: str | None, expected: str | None) -> bool:
    """Constant-time compare two secrets, treating missing values as no-match.

    Wraps :func:`secrets.compare_digest` with the ``None``/empty handling every
    call site needs: a request that omits the header (``provided is None``) and
    a service that has no secret configured (``expected`` falsy) both yield
    ``False`` rather than raising or — worse — comparing two empty strings to a
    spurious match. The digest comparison itself is timing-safe.

    Args:
        provided: The value presented by the caller (e.g. a request header).
        expected: The service's configured secret.

    Returns:
        ``True`` only when both are non-empty and equal in constant time.
    """
    if not provided or not expected:
        return False
    return secrets.compare_digest(provided, expected)


def extract_bearer_token(request: Request) -> str | None:
    """Return the token from an ``Authorization: Bearer <token>`` header.

    The scheme match is case-insensitive (``Bearer``/``bearer`` both accepted,
    per RFC 7235). Returns ``None`` when the header is absent, uses a different
    scheme, or carries an empty token.
    """
    header = request.headers.get("authorization")
    if not header or len(header) <= len(_BEARER_PREFIX):
        return None
    if header[: len(_BEARER_PREFIX)].lower() != _BEARER_PREFIX:
        return None
    return header[len(_BEARER_PREFIX) :].strip() or None


def make_internal_token_authorizer(
    secret: str | None,
    *,
    header_name: str = INTERNAL_TOKEN_HEADER,
) -> Callable[[Request], bool]:
    """Build a predicate that authorizes by a shared ``X-Internal-Token`` secret.

    Returns a ``(Request) -> bool`` closure suitable for **detail gating**: it
    answers whether the caller is a trusted internal client, without raising, so
    a deep ``/health`` route can return shallow status to everyone and the detail
    body only when the predicate is ``True``.

    Fail-closed: when *secret* is unset (``None`` or empty) the predicate always
    returns ``False`` — a missing configuration never opens the detail body. The
    comparison is constant-time via :func:`compare_secret`.

    Args:
        secret: The configured inter-service secret (``PRIVATE_API_SECRET``).
            Pass the resolved string, e.g. ``settings.PRIVATE_API_SECRET
            .get_secret_value()``.
        header_name: Header carrying the caller's token. Defaults to
            ``X-Internal-Token`` (the m8 trio convention).

    Returns:
        A predicate ``authorizer(request) -> bool``.
    """

    def _authorizer(request: Request) -> bool:
        return compare_secret(request.headers.get(header_name), secret)

    return _authorizer


def make_scrape_credential_guard(
    credential: str | None,
) -> Callable[[Request], None]:
    """Build a hard gate for ``/metrics`` driven by an optional scrape credential.

    Returns a ``(Request) -> None`` closure usable directly as a FastAPI
    dependency. Behaviour intentionally matches the plan's posture — metrics are
    internal-only by default, with an **optional** static scoped credential as
    opt-in hardening for when metrics must cross a less-trusted boundary:

    - *credential unset* (``None``/empty): **no-op** — the route is reachable and
      the network boundary (internal entrypoint) is the control. The guard does
      not invent a gate the operator did not ask for.
    - *credential set*: the request **must** present ``Authorization: Bearer
      <credential>`` (constant-time match) or receive ``401`` with a
      ``WWW-Authenticate: Bearer`` challenge. Maps onto Prometheus
      ``authorization`` in ``scrape_configs`` and is deliberately a long-lived
      static credential — short-TTL tokens are awkward for a scraper.

    Args:
        credential: The configured scrape bearer credential, or ``None`` to
            leave metrics network-gated only.

    Returns:
        A dependency ``guard(request) -> None`` that raises ``HTTPException`` 401
        on mismatch and returns ``None`` when access is allowed.
    """

    def _guard(request: Request) -> None:
        if not credential:
            return
        if not compare_secret(extract_bearer_token(request), credential):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return _guard


def make_consumer_authorizer(
    registry: ConsumerCredentialRegistry,
    *,
    required_scope: object = None,
    client_header: str = INTERNAL_CLIENT_HEADER,
    token_header: str = INTERNAL_TOKEN_HEADER,
) -> Callable[[Request], ConsumerCredential]:
    """Build a hard gate that authenticates a **per-consumer** credential.

    Returns a ``(Request) -> ConsumerCredential`` closure usable directly as a
    FastAPI dependency on a private route. It reads ``X-Internal-Client`` and
    ``X-Internal-Token`` from the request and authorizes the pair against
    *registry* (see :mod:`auth_sdk_m8.security.consumer_auth`):

    - unknown client id **or** wrong secret → ``401`` (the two are
      indistinguishable, so a caller cannot enumerate client ids);
    - authenticated but missing *required_scope* → ``403``;
    - success → the matched :class:`ConsumerCredential` is returned and injected
      into the route, so the handler knows which consumer called and with which
      scopes.

    This is the per-consumer successor to :func:`make_internal_token_authorizer`
    /``make_scrape_credential_guard`` (a single shared secret): it bounds the
    blast radius to one consumer and enforces least privilege via scopes.

    Args:
        registry: The consumer credential registry to authorize against.
        required_scope: Scope the route requires, or ``None`` for
            authentication only.
        client_header: Header carrying the consumer id. Defaults to
            ``X-Internal-Client``.
        token_header: Header carrying the consumer secret. Defaults to
            ``X-Internal-Token``.

    Returns:
        A dependency ``authorize(request) -> ConsumerCredential`` that raises
        ``HTTPException`` 401/403 on failure.
    """

    def _dependency(request: Request) -> ConsumerCredential:
        client_id = request.headers.get(client_header)
        secret = request.headers.get(token_header)
        try:
            return registry.authorize(client_id, secret, required_scope)
        except ConsumerScopeError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            ) from exc
        except ConsumerAuthenticationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized",
            ) from exc

    return _dependency
