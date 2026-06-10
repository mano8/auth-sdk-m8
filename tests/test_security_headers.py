"""Tests for auth_sdk_m8.security.headers — the shared hardening layer."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth_sdk_m8.security.headers import (
    add_security_headers_middleware,
    build_security_headers,
)

from .conftest import VALID_SETTINGS_KWARGS, IsolatedSettings

_HARDENING_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
)


def _settings(**overrides) -> IsolatedSettings:
    return IsolatedSettings(**{**VALID_SETTINGS_KWARGS, **overrides})


def _client(settings) -> TestClient:
    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict:
        return {"ok": True}

    add_security_headers_middleware(app, settings)
    return TestClient(app, raise_server_exceptions=False)


def test_headers_absent_in_local() -> None:
    """Local/dev is left unrestricted so Swagger/ReDoc/HMR keep working."""
    resp = _client(_settings(ENVIRONMENT="local")).get("/ping")
    for header in _HARDENING_HEADERS:
        assert header not in resp.headers


@pytest.mark.parametrize(
    "overrides",
    [{"ENVIRONMENT": "production"}, {"STRICT_PRODUCTION_MODE": True}],
)
def test_headers_applied_in_production(overrides: dict) -> None:
    """ENVIRONMENT==production or STRICT_PRODUCTION_MODE emits the hardening set."""
    resp = _client(_settings(**overrides)).get("/ping")
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "max-age=31536000" in resp.headers["strict-transport-security"]
    assert "includeSubDomains" in resp.headers["strict-transport-security"]


def test_opt_out_in_production() -> None:
    """SECURITY_HEADERS_ENABLED=False suppresses the layer even in production."""
    resp = _client(
        _settings(ENVIRONMENT="production", SECURITY_HEADERS_ENABLED=False)
    ).get("/ping")
    assert "content-security-policy" not in resp.headers


def test_hsts_disabled_when_max_age_zero() -> None:
    """HSTS_MAX_AGE=0 drops only the Strict-Transport-Security header."""
    resp = _client(_settings(ENVIRONMENT="production", HSTS_MAX_AGE=0)).get("/ping")
    assert "strict-transport-security" not in resp.headers
    assert "content-security-policy" in resp.headers


def test_hsts_without_subdomains() -> None:
    """HSTS_INCLUDE_SUBDOMAINS=False omits the includeSubDomains directive."""
    resp = _client(
        _settings(ENVIRONMENT="production", HSTS_INCLUDE_SUBDOMAINS=False)
    ).get("/ping")
    assert resp.headers["strict-transport-security"] == "max-age=31536000"


def test_custom_csp_override() -> None:
    """A configured CONTENT_SECURITY_POLICY overrides the tight API default."""
    custom = "default-src 'self'; frame-ancestors 'none'"
    resp = _client(
        _settings(ENVIRONMENT="production", CONTENT_SECURITY_POLICY=custom)
    ).get("/ping")
    assert resp.headers["content-security-policy"] == custom


def test_build_security_headers_direct() -> None:
    """build_security_headers returns the full set keyed lowercase."""
    headers = dict(build_security_headers(_settings(ENVIRONMENT="production")))
    assert set(headers) == set(_HARDENING_HEADERS)


def test_settings_satisfy_protocol() -> None:
    """CommonSettings subclasses structurally satisfy SecurityHeadersSettings."""
    from auth_sdk_m8.security.headers import SecurityHeadersSettings

    assert isinstance(_settings(), SecurityHeadersSettings)
