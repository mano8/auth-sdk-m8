"""Tests for auth_sdk_m8.security.guards — shared app-layer guards.

Covers the proxy-independent guards reused by ``fa-auth-m8`` / ``fastapi-m8``
for deep ``/health`` detail gating (a predicate) and ``/metrics`` protection (a
hard dependency). Requests are exercised through a real ``TestClient`` so the
header parsing runs against genuine ``starlette`` request objects.
"""

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from auth_sdk_m8.security.guards import (
    INTERNAL_TOKEN_HEADER,
    compare_secret,
    extract_bearer_token,
    make_internal_token_authorizer,
    make_scrape_credential_guard,
)

SECRET = "s3cret-internal-token-value"


# ── compare_secret (pure) ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("provided", "expected", "result"),
    [
        (None, SECRET, False),
        (SECRET, None, False),
        ("", SECRET, False),
        (SECRET, "", False),
        ("", "", False),
        ("wrong", SECRET, False),
        (SECRET, SECRET, True),
    ],
)
def test_compare_secret(provided, expected, result) -> None:
    assert compare_secret(provided, expected) is result


# ── extract_bearer_token ─────────────────────────────────────────────────────


def _bearer_app() -> TestClient:
    app = FastAPI()

    @app.get("/echo")
    def echo(request: Request) -> dict[str, str | None]:
        return {"token": extract_bearer_token(request)}

    return TestClient(app)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),  # absent
        ("Bearer tok123", "tok123"),  # canonical
        ("bearer tok123", "tok123"),  # scheme is case-insensitive
        ("BEARER tok123", "tok123"),
        ("Basic abc123", None),  # wrong scheme
        ("Bearer", None),  # no token, too short
        ("Bearer    ", None),  # only whitespace after scheme
        ("Bearer   tok   ", "tok"),  # surrounding whitespace stripped
    ],
)
def test_extract_bearer_token(header, expected) -> None:
    headers = {"Authorization": header} if header is not None else {}
    resp = _bearer_app().get("/echo", headers=headers)
    assert resp.json() == {"token": expected}


# ── make_internal_token_authorizer (predicate / detail gating) ───────────────


def _authorizer_app(secret, **kwargs) -> TestClient:
    app = FastAPI()
    authorize = make_internal_token_authorizer(secret, **kwargs)

    @app.get("/check")
    def check(request: Request) -> dict[str, bool]:
        return {"authorized": authorize(request)}

    return TestClient(app)


def test_authorizer_matches_secret() -> None:
    resp = _authorizer_app(SECRET).get(
        "/check", headers={INTERNAL_TOKEN_HEADER: SECRET}
    )
    assert resp.json() == {"authorized": True}


def test_authorizer_rejects_wrong_secret() -> None:
    resp = _authorizer_app(SECRET).get(
        "/check", headers={INTERNAL_TOKEN_HEADER: "nope"}
    )
    assert resp.json() == {"authorized": False}


def test_authorizer_rejects_missing_header() -> None:
    resp = _authorizer_app(SECRET).get("/check")
    assert resp.json() == {"authorized": False}


def test_authorizer_fails_closed_when_secret_unset() -> None:
    # A service with no configured secret never authorizes — even if the caller
    # sends an empty token that would otherwise "match" an empty secret.
    resp = _authorizer_app(None).get("/check", headers={INTERNAL_TOKEN_HEADER: ""})
    assert resp.json() == {"authorized": False}


def test_authorizer_honours_custom_header_name() -> None:
    client = _authorizer_app(SECRET, header_name="X-Scrape-Token")
    assert client.get("/check", headers={"X-Scrape-Token": SECRET}).json() == {
        "authorized": True
    }
    # The default header no longer counts.
    assert client.get("/check", headers={INTERNAL_TOKEN_HEADER: SECRET}).json() == {
        "authorized": False
    }


# ── make_scrape_credential_guard (hard gate / dependency) ────────────────────


def _guarded_app(credential) -> TestClient:
    app = FastAPI()
    guard = make_scrape_credential_guard(credential)

    @app.get("/metrics", dependencies=[Depends(guard)])
    def metrics() -> dict[str, str]:
        return {"metrics": "ok"}

    return TestClient(app, raise_server_exceptions=False)


def test_guard_noop_when_credential_unset() -> None:
    # Internal-only by default: no credential configured → route is reachable
    # (the network boundary is the control, not the app gate).
    resp = _guarded_app(None).get("/metrics")
    assert resp.status_code == 200
    assert resp.json() == {"metrics": "ok"}


def test_guard_allows_matching_bearer() -> None:
    resp = _guarded_app(SECRET).get(
        "/metrics", headers={"Authorization": f"Bearer {SECRET}"}
    )
    assert resp.status_code == 200
    assert resp.json() == {"metrics": "ok"}


def test_guard_rejects_wrong_bearer() -> None:
    resp = _guarded_app(SECRET).get(
        "/metrics", headers={"Authorization": "Bearer wrong"}
    )
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"


def test_guard_rejects_missing_credential() -> None:
    resp = _guarded_app(SECRET).get("/metrics")
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"
