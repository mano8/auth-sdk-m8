"""Tests for the shared ServiceMeta schema and /meta + /ping routes."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from auth_sdk_m8.controllers.meta import (
    META_CACHE_CONTROL,
    PING_RESPONSE,
    mount_service_meta,
)
from auth_sdk_m8.schemas.meta import ServiceContract, ServiceMeta


def _make_meta() -> ServiceMeta:
    return ServiceMeta(
        service="media-service-m8",
        version="1.0.0",
        api_version="v1",
        contract=ServiceContract(
            name="media-service-m8",
            version="1.0",
            range=">=1.0.0 <2.0.0",
        ),
    )


def _client(prefix: str = "") -> TestClient:
    app = FastAPI()
    mount_service_meta(app, _make_meta(), prefix=prefix)
    return TestClient(app)


# ── Schema ─────────────────────────────────────────────────────────────────


def test_service_meta_round_trip() -> None:
    meta = _make_meta()
    assert meta.contract.range == ">=1.0.0 <2.0.0"


@pytest.mark.parametrize("field", ["service", "version", "api_version"])
def test_service_meta_rejects_empty_field(field: str) -> None:
    values = {
        "service": "svc",
        "version": "1.0.0",
        "api_version": "v1",
        "contract": ServiceContract(name="svc", version="1.0", range=">=1.0.0"),
    }
    values[field] = ""
    with pytest.raises(ValidationError):
        ServiceMeta(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["name", "version", "range"])
def test_service_contract_rejects_empty_field(field: str) -> None:
    values = {"name": "svc", "version": "1.0", "range": ">=1.0.0"}
    values[field] = ""
    with pytest.raises(ValidationError):
        ServiceContract(**values)


# ── /meta route ──────────────────────────────────────────────────────────────


def test_meta_route_returns_payload() -> None:
    resp = _client().get("/meta")
    assert resp.status_code == 200
    assert resp.json() == _make_meta().model_dump()


def test_meta_route_sets_cache_control() -> None:
    resp = _client().get("/meta")
    assert resp.headers["Cache-Control"] == META_CACHE_CONTROL


def test_meta_route_honours_prefix() -> None:
    client = _client(prefix="/media")
    assert client.get("/media/meta").status_code == 200
    assert client.get("/meta").status_code == 404


# ── /ping route ──────────────────────────────────────────────────────────────


def test_ping_route_returns_ok_at_root_without_prefix() -> None:
    # No prefix: /ping mounts at the root.
    resp = _client().get("/ping")
    assert resp.status_code == 200
    assert resp.json() == PING_RESPONSE


def test_root_ping_disabled_when_prefix_set() -> None:
    # With a prefix the root /ping is NOT mounted — only the prefixed copy
    # exists, so liveness is routed exclusively through the proxy prefix
    # (matching how container healthchecks already hit {prefix}/health).
    assert _client(prefix="/media").get("/ping").status_code == 404


def test_ping_served_under_prefix() -> None:
    # Reachable through a prefix-routing proxy (Traefik forwards PathPrefix).
    resp = _client(prefix="/media").get("/media/ping")
    assert resp.status_code == 200
    assert resp.json() == PING_RESPONSE


def test_prefixed_ping_is_published_in_schema() -> None:
    # Exactly one ping operation exists, mounted at the prefix, and it is
    # published in the OpenAPI document (no hidden duplicate).
    schema = _client(prefix="/media").get("/openapi.json").json()
    ping_paths = [p for p in schema["paths"] if p.endswith("/ping")]
    assert ping_paths == ["/media/ping"]


def test_root_ping_published_in_schema_without_prefix() -> None:
    # Empty prefix publishes the single root ping operation.
    schema = _client().get("/openapi.json").json()
    ping_paths = [p for p in schema["paths"] if p.endswith("/ping")]
    assert ping_paths == ["/ping"]
