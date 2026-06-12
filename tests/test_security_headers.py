"""Tests for auth_sdk_m8.security.headers — the shared hardening layer."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth_sdk_m8.security.headers import (
    add_security_headers_middleware,
    build_security_headers,
)

from .conftest import PROD_VALID_KEY, VALID_SETTINGS_KWARGS, IsolatedSettings

_HARDENING_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
)


def _settings(**overrides) -> IsolatedSettings:
    kwargs = {**VALID_SETTINGS_KWARGS, **overrides}
    # Production mode rejects VALID_KEY (a known dev placeholder); use prod-safe key.
    if kwargs.get("ENVIRONMENT") == "production" or kwargs.get(
        "STRICT_PRODUCTION_MODE"
    ):
        for field in ("ACCESS_SECRET_KEY", "REFRESH_SECRET_KEY", "EVENT_SIGNING_KEY"):
            if field not in overrides:
                kwargs[field] = PROD_VALID_KEY
    return IsolatedSettings(**kwargs)


def _client(settings) -> TestClient:
    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict:
        return {"ok": True}

    add_security_headers_middleware(app, settings)
    return TestClient(app, raise_server_exceptions=False)


def test_headers_minimal_in_local_even_with_optin() -> None:
    """Local gets only the safe subset — HSTS/CSP are blocked even when opted in."""
    resp = _client(
        _settings(
            ENVIRONMENT="local",
            HSTS_ENABLED=True,
            CONTENT_SECURITY_POLICY_ENABLED=True,
        )
    ).get("/ping")
    # Always-on: harmless in any environment
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    # Never on local — even though both opt-ins are True
    for header in (
        "content-security-policy",
        "strict-transport-security",
        "referrer-policy",
        "permissions-policy",
    ):
        assert header not in resp.headers


@pytest.mark.parametrize(
    "overrides",
    [{"ENVIRONMENT": "production"}, {"STRICT_PRODUCTION_MODE": True}],
)
def test_production_without_optin_omits_hsts_and_csp(overrides: dict) -> None:
    """Production emits the policy headers but NOT HSTS/CSP without express opt-in."""
    resp = _client(_settings(**overrides)).get("/ping")
    # Always-on + production-gated
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "permissions-policy" in resp.headers
    # Express opt-in — off by default even in production
    assert "strict-transport-security" not in resp.headers
    assert "content-security-policy" not in resp.headers


def test_production_with_hsts_and_csp_optin() -> None:
    """Opting in to HSTS and CSP in production emits the full hardening set."""
    resp = _client(
        _settings(
            ENVIRONMENT="production",
            HSTS_ENABLED=True,
            CONTENT_SECURITY_POLICY_ENABLED=True,
        )
    ).get("/ping")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "max-age=31536000" in resp.headers["strict-transport-security"]
    assert "includeSubDomains" in resp.headers["strict-transport-security"]


def test_hsts_csp_optin_decoupled_from_production_gate() -> None:
    """HSTS/CSP apply on a non-local, non-production stack when expressly enabled.

    The policy headers (Referrer/Permissions) stay off since they are
    production-gated — proving the two tiers are independent.
    """
    resp = _client(
        _settings(
            ENVIRONMENT="staging",
            HSTS_ENABLED=True,
            CONTENT_SECURITY_POLICY_ENABLED=True,
        )
    ).get("/ping")
    assert "strict-transport-security" in resp.headers
    assert "content-security-policy" in resp.headers
    # production-gated tier is independent of the opt-in tier
    assert "referrer-policy" not in resp.headers
    assert "permissions-policy" not in resp.headers


def test_opt_out_suppresses_everything() -> None:
    """SECURITY_HEADERS_ENABLED=False suppresses the whole layer, opt-ins included."""
    resp = _client(
        _settings(
            ENVIRONMENT="production",
            SECURITY_HEADERS_ENABLED=False,
            HSTS_ENABLED=True,
            CONTENT_SECURITY_POLICY_ENABLED=True,
        )
    ).get("/ping")
    assert "content-security-policy" not in resp.headers
    assert "x-content-type-options" not in resp.headers


def test_hsts_optin_but_max_age_zero() -> None:
    """HSTS_ENABLED with HSTS_MAX_AGE=0 still drops the Strict-Transport-Security header."""
    resp = _client(
        _settings(ENVIRONMENT="production", HSTS_ENABLED=True, HSTS_MAX_AGE=0)
    ).get("/ping")
    assert "strict-transport-security" not in resp.headers


def test_hsts_without_subdomains() -> None:
    """HSTS_INCLUDE_SUBDOMAINS=False omits the includeSubDomains directive."""
    resp = _client(
        _settings(
            ENVIRONMENT="production",
            HSTS_ENABLED=True,
            HSTS_INCLUDE_SUBDOMAINS=False,
        )
    ).get("/ping")
    assert resp.headers["strict-transport-security"] == "max-age=31536000"


def test_custom_csp_override() -> None:
    """A configured CONTENT_SECURITY_POLICY overrides the tight API default."""
    custom = "default-src 'self'; frame-ancestors 'none'"
    resp = _client(
        _settings(
            ENVIRONMENT="production",
            CONTENT_SECURITY_POLICY_ENABLED=True,
            CONTENT_SECURITY_POLICY=custom,
        )
    ).get("/ping")
    assert resp.headers["content-security-policy"] == custom


def test_build_security_headers_direct() -> None:
    """build_security_headers returns the full set keyed lowercase when fully opted in."""
    headers = dict(
        build_security_headers(
            _settings(
                ENVIRONMENT="production",
                HSTS_ENABLED=True,
                CONTENT_SECURITY_POLICY_ENABLED=True,
            )
        )
    )
    assert set(headers) == set(_HARDENING_HEADERS)


def test_settings_satisfy_protocol() -> None:
    """CommonSettings subclasses structurally satisfy SecurityHeadersSettings."""
    from auth_sdk_m8.security.headers import SecurityHeadersSettings

    assert isinstance(_settings(), SecurityHeadersSettings)
