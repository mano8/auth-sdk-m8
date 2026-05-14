"""Tests for auth_sdk_m8.observability — metrics, middleware, and settings."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from prometheus_client import CollectorRegistry

import auth_sdk_m8.observability.metrics as _mod
from auth_sdk_m8.observability.metrics import (
    _ALL_GROUPS,
    GROUP_AUTH,
    GROUP_HEALTH,
    GROUP_PERFORMANCE,
    GROUP_RELIABILITY,
    GROUP_TRAFFIC,
    _norm_prefix,
    _resolve_groups,
    get,
    render,
    setup,
)
from auth_sdk_m8.observability.middleware import MetricsMiddleware
from auth_sdk_m8.observability.settings import ObservabilitySettingsMixin

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch):
    """Each test gets a fresh registry and a reset _m singleton."""
    fresh = CollectorRegistry(auto_describe=False)
    monkeypatch.setattr(_mod, "REGISTRY", fresh)
    monkeypatch.setattr(_mod, "_m", None)
    yield
    monkeypatch.setattr(_mod, "_m", None)


def _sv(name: str, labels: dict) -> float:
    """Return a sample value from the test registry, defaulting to 0.0."""
    return _mod.REGISTRY.get_sample_value(name, labels) or 0.0


# ── _resolve_groups ───────────────────────────────────────────────────────────


def test_resolve_groups_all_returns_all_groups() -> None:
    assert _resolve_groups("all") == set(_ALL_GROUPS)


def test_resolve_groups_case_insensitive() -> None:
    assert _resolve_groups("ALL") == set(_ALL_GROUPS)
    assert _resolve_groups("Traffic") == {GROUP_TRAFFIC}


def test_resolve_groups_specific_subset() -> None:
    assert _resolve_groups("traffic,performance") == {GROUP_TRAFFIC, GROUP_PERFORMANCE}


def test_resolve_groups_single() -> None:
    assert _resolve_groups("auth") == {GROUP_AUTH}
    assert _resolve_groups("health") == {GROUP_HEALTH}
    assert _resolve_groups("reliability") == {GROUP_RELIABILITY}


def test_resolve_groups_unknown_names_ignored() -> None:
    assert _resolve_groups("unknown,traffic") == {GROUP_TRAFFIC}


def test_resolve_groups_all_unknown_returns_empty() -> None:
    assert _resolve_groups("foo,bar") == set()


def test_resolve_groups_whitespace_stripped() -> None:
    assert _resolve_groups("traffic, performance") == {GROUP_TRAFFIC, GROUP_PERFORMANCE}


# ── _norm_prefix ──────────────────────────────────────────────────────────────


def test_norm_prefix_simple_path() -> None:
    assert _norm_prefix("/user") == "user_"


def test_norm_prefix_nested_path() -> None:
    assert _norm_prefix("/api/v1") == "api_v1_"


def test_norm_prefix_hyphen_to_underscore() -> None:
    assert _norm_prefix("/my-service") == "my_service_"


def test_norm_prefix_empty_string() -> None:
    assert _norm_prefix("") == ""


def test_norm_prefix_root_slash() -> None:
    assert _norm_prefix("/") == ""


# ── setup / get ───────────────────────────────────────────────────────────────


def test_setup_disabled_get_returns_none() -> None:
    setup(enabled=False, groups_str="all", api_prefix="/svc")
    assert get() is None


def test_setup_enabled_all_groups_populates_all_metrics() -> None:
    setup(enabled=True, groups_str="all", api_prefix="/svc")
    m = get()
    assert m is not None
    assert m.requests_total is not None
    assert m.request_duration_seconds is not None
    assert m.errors_total is not None
    assert m.status_total is not None
    assert m.login_attempts_total is not None
    assert m.token_refresh_total is not None
    assert m.logout_total is not None
    assert m.token_validation_failures_total is not None
    assert m.oauth_attempts_total is not None


def test_setup_traffic_only_leaves_others_none() -> None:
    setup(enabled=True, groups_str="traffic", api_prefix="/svc")
    m = get()
    assert m is not None
    assert m.requests_total is not None
    assert m.request_duration_seconds is None
    assert m.errors_total is None
    assert m.status_total is None
    assert m.login_attempts_total is None


def test_setup_performance_only() -> None:
    setup(enabled=True, groups_str="performance", api_prefix="/svc")
    m = get()
    assert m is not None
    assert m.request_duration_seconds is not None
    assert m.requests_total is None


def test_setup_reliability_only() -> None:
    setup(enabled=True, groups_str="reliability", api_prefix="/svc")
    m = get()
    assert m is not None
    assert m.errors_total is not None
    assert m.requests_total is None
    assert m.status_total is None


def test_setup_health_only() -> None:
    setup(enabled=True, groups_str="health", api_prefix="/svc")
    m = get()
    assert m is not None
    assert m.status_total is not None
    assert m.requests_total is None
    assert m.login_attempts_total is None


def test_setup_auth_only_sets_all_auth_metrics() -> None:
    setup(enabled=True, groups_str="auth", api_prefix="/svc")
    m = get()
    assert m is not None
    assert m.login_attempts_total is not None
    assert m.token_refresh_total is not None
    assert m.logout_total is not None
    assert m.token_validation_failures_total is not None
    assert m.oauth_attempts_total is not None
    assert m.requests_total is None
    assert m.request_duration_seconds is None


def test_setup_unknown_groups_sets_no_metrics() -> None:
    setup(enabled=True, groups_str="bogus", api_prefix="/svc")
    m = get()
    assert m is not None
    assert m.requests_total is None
    assert m.login_attempts_total is None


def test_setup_disabled_after_enabled_resets_to_none() -> None:
    setup(enabled=True, groups_str="all", api_prefix="/svc")
    assert get() is not None
    setup(enabled=False, groups_str="all", api_prefix="/svc")
    assert get() is None


def test_setup_prefixes_metric_names() -> None:
    setup(enabled=True, groups_str="traffic", api_prefix="/myapp")
    content, _ = render()
    assert b"myapp_http_requests_total" in content


# ── render ────────────────────────────────────────────────────────────────────


def test_render_returns_bytes_and_content_type() -> None:
    setup(enabled=True, groups_str="traffic", api_prefix="/svc")
    content, content_type = render()
    assert isinstance(content, bytes)
    assert "text/plain" in content_type


def test_render_output_contains_registered_metric() -> None:
    setup(enabled=True, groups_str="traffic", api_prefix="/svc")
    content, _ = render()
    assert b"svc_http_requests_total" in content


def test_render_empty_when_disabled() -> None:
    setup(enabled=False, groups_str="all", api_prefix="/svc")
    content, _ = render()
    assert b"http_requests_total" not in content


# ── MetricsMiddleware ─────────────────────────────────────────────────────────


def _make_request(method: str = "GET", path: str = "/test") -> MagicMock:
    req = MagicMock()
    req.method = method
    req.url.path = path
    return req


def _make_response(status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    return resp


async def test_middleware_passthrough_when_disabled() -> None:
    setup(enabled=False, groups_str="all", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    response = _make_response(200)
    call_next = AsyncMock(return_value=response)
    result = await middleware.dispatch(_make_request(), call_next)
    assert result is response
    call_next.assert_awaited_once()


async def test_middleware_increments_requests_total() -> None:
    setup(enabled=True, groups_str="traffic", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    call_next = AsyncMock(return_value=_make_response(200))
    await middleware.dispatch(_make_request("GET", "/test"), call_next)
    assert (
        _sv(
            "svc_http_requests_total",
            {"method": "GET", "endpoint": "/test", "status_code": "200"},
        )
        == 1.0
    )


async def test_middleware_records_duration() -> None:
    setup(enabled=True, groups_str="performance", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    call_next = AsyncMock(return_value=_make_response(200))
    await middleware.dispatch(_make_request("POST", "/login"), call_next)
    assert (
        _sv(
            "svc_http_request_duration_seconds_count",
            {"method": "POST", "endpoint": "/login"},
        )
        == 1.0
    )


async def test_middleware_increments_errors_for_4xx() -> None:
    setup(enabled=True, groups_str="reliability", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    call_next = AsyncMock(return_value=_make_response(404))
    await middleware.dispatch(_make_request(), call_next)
    assert (
        _sv(
            "svc_http_errors_total",
            {"method": "GET", "endpoint": "/test", "status_class": "4xx"},
        )
        == 1.0
    )


async def test_middleware_increments_errors_for_5xx() -> None:
    setup(enabled=True, groups_str="reliability", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    call_next = AsyncMock(return_value=_make_response(500))
    await middleware.dispatch(_make_request(), call_next)
    assert (
        _sv(
            "svc_http_errors_total",
            {"method": "GET", "endpoint": "/test", "status_class": "5xx"},
        )
        == 1.0
    )


async def test_middleware_no_error_increment_for_2xx() -> None:
    setup(enabled=True, groups_str="reliability", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    call_next = AsyncMock(return_value=_make_response(200))
    await middleware.dispatch(_make_request(), call_next)
    assert (
        _sv(
            "svc_http_errors_total",
            {"method": "GET", "endpoint": "/test", "status_class": "2xx"},
        )
        == 0.0
    )


async def test_middleware_increments_status_total() -> None:
    setup(enabled=True, groups_str="health", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    call_next = AsyncMock(return_value=_make_response(201))
    await middleware.dispatch(_make_request("POST", "/items"), call_next)
    assert _sv("svc_http_status_total", {"status_code": "201"}) == 1.0


async def test_middleware_normalizes_uuid_in_path() -> None:
    setup(enabled=True, groups_str="traffic", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    call_next = AsyncMock(return_value=_make_response(200))
    await middleware.dispatch(
        _make_request("GET", "/items/550e8400-e29b-41d4-a716-446655440000"),
        call_next,
    )
    assert (
        _sv(
            "svc_http_requests_total",
            {"method": "GET", "endpoint": "/items/{id}", "status_code": "200"},
        )
        == 1.0
    )


async def test_middleware_normalizes_integer_id_in_path() -> None:
    setup(enabled=True, groups_str="traffic", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    call_next = AsyncMock(return_value=_make_response(200))
    await middleware.dispatch(_make_request("GET", "/users/42"), call_next)
    assert (
        _sv(
            "svc_http_requests_total",
            {"method": "GET", "endpoint": "/users/{id}", "status_code": "200"},
        )
        == 1.0
    )


async def test_middleware_all_groups_combined() -> None:
    setup(enabled=True, groups_str="all", api_prefix="/svc")
    middleware = MetricsMiddleware(app=AsyncMock())
    call_next = AsyncMock(return_value=_make_response(200))
    await middleware.dispatch(_make_request("GET", "/health"), call_next)
    assert (
        _sv(
            "svc_http_requests_total",
            {"method": "GET", "endpoint": "/health", "status_code": "200"},
        )
        == 1.0
    )
    assert (
        _sv(
            "svc_http_request_duration_seconds_count",
            {"method": "GET", "endpoint": "/health"},
        )
        == 1.0
    )
    assert _sv("svc_http_status_total", {"status_code": "200"}) == 1.0


# ── ObservabilitySettingsMixin ────────────────────────────────────────────────


def test_settings_mixin_defaults() -> None:
    mixin = ObservabilitySettingsMixin()
    assert mixin.METRICS_ENABLED is False
    assert mixin.METRICS_GROUPS == "all"


def test_settings_mixin_custom_values() -> None:
    mixin = ObservabilitySettingsMixin(
        METRICS_ENABLED=True, METRICS_GROUPS="traffic,auth"
    )
    assert mixin.METRICS_ENABLED is True
    assert mixin.METRICS_GROUPS == "traffic,auth"


def test_settings_mixin_enabled_false_explicit() -> None:
    mixin = ObservabilitySettingsMixin(METRICS_ENABLED=False)
    assert mixin.METRICS_ENABLED is False
