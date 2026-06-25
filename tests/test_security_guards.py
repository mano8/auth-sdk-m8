"""Tests for auth_sdk_m8.security.guards — shared app-layer guards.

Covers the proxy-independent guards reused by ``fa-auth-m8`` / ``fastapi-m8``
for deep ``/health`` detail gating (a predicate) and ``/metrics`` protection (a
hard dependency). Requests are exercised through a real ``TestClient`` so the
header parsing runs against genuine ``starlette`` request objects.
"""

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from auth_sdk_m8.security.consumer_auth import (
    INTERNAL_CLIENT_HEADER,
    ConsumerCredentialRegistry,
    ConsumerScope,
)
from auth_sdk_m8.security.guards import (
    INTERNAL_TOKEN_HEADER,
    assert_secrets_distinct,
    compare_secret,
    extract_bearer_token,
    make_consumer_authorizer,
    make_internal_token_authorizer,
    make_scrape_credential_guard,
)

SECRET = "s3cret-internal-token-value"
CONSUMER_SECRET = "consumer-a-bootstrap-secret-value-0001"


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


# ── make_consumer_authorizer (per-consumer hard gate / dependency) ───────────


def _consumer_registry() -> ConsumerCredentialRegistry:
    return ConsumerCredentialRegistry.from_secrets(
        {
            "svc-a": (CONSUMER_SECRET, ConsumerScope.INTROSPECTION),
            "svc-b": (
                "other-secret-value-000000000000000002",
                ConsumerScope.USER_CREATE,
            ),
        }
    )


def _consumer_app(**kwargs) -> TestClient:
    app = FastAPI()
    authorize = make_consumer_authorizer(_consumer_registry(), **kwargs)

    @app.get("/private")
    def private(cred=Depends(authorize)) -> dict[str, object]:
        return {"client_id": cred.client_id, "scopes": sorted(cred.scopes)}

    return TestClient(app, raise_server_exceptions=False)


def _consumer_headers(client_id: str, secret: str) -> dict[str, str]:
    return {INTERNAL_CLIENT_HEADER: client_id, INTERNAL_TOKEN_HEADER: secret}


def test_consumer_authorizer_allows_valid_pair() -> None:
    resp = _consumer_app().get(
        "/private", headers=_consumer_headers("svc-a", CONSUMER_SECRET)
    )
    assert resp.status_code == 200
    assert resp.json() == {"client_id": "svc-a", "scopes": ["introspection"]}


def test_consumer_authorizer_rejects_wrong_secret() -> None:
    resp = _consumer_app().get("/private", headers=_consumer_headers("svc-a", "wrong"))
    assert resp.status_code == 401


def test_consumer_authorizer_rejects_cross_consumer_secret() -> None:
    # svc-b's secret presented as svc-a must be rejected (no blast-radius reuse).
    resp = _consumer_app().get(
        "/private",
        headers=_consumer_headers("svc-a", "other-secret-value-000000000000000002"),
    )
    assert resp.status_code == 401


def test_consumer_authorizer_rejects_missing_headers() -> None:
    resp = _consumer_app().get("/private")
    assert resp.status_code == 401


def test_consumer_authorizer_enforces_scope() -> None:
    # svc-a is introspection-only → denied on a user-create route (403, not 401).
    resp = _consumer_app(required_scope=ConsumerScope.USER_CREATE).get(
        "/private", headers=_consumer_headers("svc-a", CONSUMER_SECRET)
    )
    assert resp.status_code == 403


def test_consumer_authorizer_allows_matching_scope() -> None:
    resp = _consumer_app(required_scope=ConsumerScope.INTROSPECTION).get(
        "/private", headers=_consumer_headers("svc-a", CONSUMER_SECRET)
    )
    assert resp.status_code == 200


def test_consumer_authorizer_honours_custom_headers() -> None:
    client = _consumer_app(client_header="X-Client", token_header="X-Token")
    ok = client.get(
        "/private", headers={"X-Client": "svc-a", "X-Token": CONSUMER_SECRET}
    )
    assert ok.status_code == 200
    # The default headers no longer authenticate.
    miss = client.get("/private", headers=_consumer_headers("svc-a", CONSUMER_SECRET))
    assert miss.status_code == 401


# ── assert_secrets_distinct ──────────────────────────────────────────────────


def test_assert_secrets_distinct_passes_when_all_different() -> None:
    assert_secrets_distinct(
        SECRET,
        health_detail_credential="health-token-aaa",
        metrics_scrape_credential="metrics-token-bbb",
    )


def test_assert_secrets_distinct_raises_on_single_reuse() -> None:
    with pytest.raises(ValueError, match="health_detail_credential"):
        assert_secrets_distinct(
            SECRET,
            health_detail_credential=SECRET,
            metrics_scrape_credential="metrics-token-bbb",
        )


def test_assert_secrets_distinct_raises_naming_all_offenders() -> None:
    with pytest.raises(ValueError) as exc_info:
        assert_secrets_distinct(
            SECRET,
            health_detail_credential=SECRET,
            metrics_scrape_credential=SECRET,
        )
    msg = str(exc_info.value)
    assert "health_detail_credential" in msg
    assert "metrics_scrape_credential" in msg


def test_assert_secrets_distinct_noop_when_reference_none() -> None:
    # No reference secret → nothing to protect, so unset is fine.
    assert_secrets_distinct(None, health_detail_credential=SECRET)


def test_assert_secrets_distinct_noop_when_reference_empty() -> None:
    assert_secrets_distinct("", health_detail_credential=SECRET)


def test_assert_secrets_distinct_skips_unset_operational_secrets() -> None:
    # An unset operational credential is not a reuse — skip it.
    assert_secrets_distinct(SECRET, health_detail_credential=None)
    assert_secrets_distinct(SECRET, health_detail_credential="")


def test_assert_secrets_distinct_noop_with_no_named_args() -> None:
    assert_secrets_distinct(SECRET)


def test_assert_secrets_distinct_accessible_via_security_package() -> None:
    from auth_sdk_m8.security import assert_secrets_distinct as fn

    assert callable(fn)
