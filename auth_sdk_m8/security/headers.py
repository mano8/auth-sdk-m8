"""Response security-header hardening for m8 FastAPI services.

Requires the ``fastapi`` extra::

    pip install "auth-sdk-m8[fastapi]"

Shared by every m8 FastAPI app — consumer services (via
``fastapi_m8.create_app``) and the auth provider (``fa-auth-m8``), which builds
its own ``FastAPI()`` app.  The hardening layer is gated on the same
``ENVIRONMENT == "production" or STRICT_PRODUCTION_MODE`` contract used for docs
hiding and ``TrustedHostMiddleware``, so local/dev (and Swagger/ReDoc/HMR) stay
unrestricted.

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
    HSTS_MAX_AGE: int
    HSTS_INCLUDE_SUBDOMAINS: bool
    CONTENT_SECURITY_POLICY: str | None
    REFERRER_POLICY: str
    PERMISSIONS_POLICY: str


def build_security_headers(
    settings: SecurityHeadersSettings,
) -> list[tuple[str, str]]:
    """Compute the static response-header list for the hardening layer.

    Mirrors the docs-gating / TrustedHost ``is_production`` contract: HSTS, CSP,
    ``X-Frame-Options``, ``X-Content-Type-Options``, ``Referrer-Policy`` and
    ``Permissions-Policy``. Swagger/ReDoc are gated off in production, so the
    tight default CSP cannot break them.
    """
    csp = settings.CONTENT_SECURITY_POLICY or _DEFAULT_API_CSP
    headers: list[tuple[str, str]] = [
        ("content-security-policy", csp),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", settings.REFERRER_POLICY),
        ("permissions-policy", settings.PERMISSIONS_POLICY),
    ]
    if settings.HSTS_MAX_AGE > 0:
        hsts = f"max-age={settings.HSTS_MAX_AGE}"
        if settings.HSTS_INCLUDE_SUBDOMAINS:
            hsts += "; includeSubDomains"
        headers.append(("strict-transport-security", hsts))
    return headers


_BASIC_SECURITY_HEADERS: list[tuple[str, str]] = [
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
]


def add_security_headers_middleware(
    app: FastAPI, settings: SecurityHeadersSettings
) -> None:
    """Attach response-hardening headers to *app*.

    Always applies the safe minimal subset (``X-Content-Type-Options``,
    ``X-Frame-Options``) when ``SECURITY_HEADERS_ENABLED`` is True — these
    are harmless in every environment and safe to apply unconditionally.

    The full production set (HSTS, CSP, Referrer-Policy, Permissions-Policy)
    is additionally applied only when ``ENVIRONMENT == "production"`` or
    ``STRICT_PRODUCTION_MODE`` — the same gate used for docs hiding — so
    Swagger/ReDoc/HMR keep working in local/dev.

    A no-op when ``SECURITY_HEADERS_ENABLED`` is False. Implemented as an
    HTTP middleware so headers land on every response, including errors raised
    before the route handler.
    """
    if not settings.SECURITY_HEADERS_ENABLED:
        return

    is_production = (
        settings.ENVIRONMENT == "production" or settings.STRICT_PRODUCTION_MODE
    )
    security_headers = (
        build_security_headers(settings) if is_production else _BASIC_SECURITY_HEADERS
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        for name, value in security_headers:
            response.headers[name] = value  # replaces any value the app set
        return response
