"""Response security-header hardening for m8 FastAPI services.

Requires ``fastapi`` to be installed — already true for any m8 FastAPI service
(consumer apps via ``fastapi_m8.create_app`` and the auth provider
``fa-auth-m8``, which builds its own ``FastAPI()`` app). Install
``auth-sdk-m8[fastapi]`` only if pulling this into a context without FastAPI.
This module lives in the platform SDK, not ``fastapi-m8``, so the issuer can use
it without importing the consumer-only package.

Headers are applied in three tiers:

1. **Always-on** (every environment): ``X-Content-Type-Options: nosniff`` and
   ``X-Frame-Options: DENY`` — harmless everywhere, safe to apply
   unconditionally.
2. **Production-gated** (``ENVIRONMENT == "production" or
   STRICT_PRODUCTION_MODE``): ``Referrer-Policy`` and ``Permissions-Policy`` —
   the same gate used for docs hiding and ``TrustedHostMiddleware``.
3. **Express opt-in only** (``HSTS_ENABLED`` / ``CONTENT_SECURITY_POLICY_ENABLED``):
   HSTS and CSP. These are browser-persisted and can hard-break a host (HSTS
   poisons the localhost HTTPS cache for ``max-age`` seconds), so they are
   **never** inferred from the production gate and are **never** emitted when
   ``ENVIRONMENT == "local"`` even if the operator opts in.

The settings fields the layer reads live on
:class:`auth_sdk_m8.core.config.CommonSettings`, so any service that subclasses
it (every m8 service) already exposes them.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from fastapi import FastAPI, Request

_DEFAULT_API_CSP = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


@runtime_checkable
class SecurityHeadersSettings(Protocol):
    """Structural protocol for the settings fields the hardening layer reads.

    Satisfied by :class:`auth_sdk_m8.core.config.CommonSettings` and every
    subclass; declared structurally so the middleware stays decoupled from any
    concrete settings class.
    """

    ENVIRONMENT: str
    STRICT_PRODUCTION_MODE: bool
    SECURITY_HEADERS_ENABLED: bool
    HSTS_ENABLED: bool
    HSTS_MAX_AGE: int
    HSTS_INCLUDE_SUBDOMAINS: bool
    CONTENT_SECURITY_POLICY_ENABLED: bool
    CONTENT_SECURITY_POLICY: str | None
    REFERRER_POLICY: str
    PERMISSIONS_POLICY: str


def build_security_headers(
    settings: SecurityHeadersSettings,
) -> list[tuple[str, str]]:
    """Compute the response-header list to emit for *settings*.

    Resolves all three tiers (see the module docstring):

    - Always: ``X-Content-Type-Options``, ``X-Frame-Options``.
    - Production-gated (``ENVIRONMENT == "production" or STRICT_PRODUCTION_MODE``):
      ``Referrer-Policy``, ``Permissions-Policy``.
    - Express opt-in, never on local: ``Strict-Transport-Security`` (when
      ``HSTS_ENABLED`` and ``HSTS_MAX_AGE > 0``) and ``Content-Security-Policy``
      (when ``CONTENT_SECURITY_POLICY_ENABLED``).
    """
    is_local = settings.ENVIRONMENT == "local"
    is_production = (
        settings.ENVIRONMENT == "production" or settings.STRICT_PRODUCTION_MODE
    )

    # Tier 1 — harmless in every environment.
    headers: list[tuple[str, str]] = [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ]

    # Tier 2 — production hardening that cannot break local tooling.
    if is_production:
        headers.append(("referrer-policy", settings.REFERRER_POLICY))
        headers.append(("permissions-policy", settings.PERMISSIONS_POLICY))

    # Tier 3 — browser-persisted, hard-to-reverse headers. Express opt-in only,
    # decoupled from the production gate, and NEVER on a local stack even if the
    # operator opts in (HSTS would poison the localhost HTTPS cache).
    if not is_local:
        if settings.HSTS_ENABLED and settings.HSTS_MAX_AGE > 0:
            hsts = f"max-age={settings.HSTS_MAX_AGE}"
            if settings.HSTS_INCLUDE_SUBDOMAINS:
                hsts += "; includeSubDomains"
            headers.append(("strict-transport-security", hsts))
        if settings.CONTENT_SECURITY_POLICY_ENABLED:
            csp = settings.CONTENT_SECURITY_POLICY or _DEFAULT_API_CSP
            headers.append(("content-security-policy", csp))

    return headers


def add_security_headers_middleware(
    app: FastAPI, settings: SecurityHeadersSettings
) -> None:
    """Attach response-hardening headers to *app*.

    A no-op when ``SECURITY_HEADERS_ENABLED`` is False. Otherwise emits the
    tiered set computed by :func:`build_security_headers` on every response,
    including error responses raised before the route handler. See the module
    docstring for the tier definitions and the HSTS/CSP opt-in contract.
    """
    if not settings.SECURITY_HEADERS_ENABLED:
        return

    security_headers = build_security_headers(settings)

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        for name, value in security_headers:
            response.headers[name] = value  # replaces any value the app set
        return response
