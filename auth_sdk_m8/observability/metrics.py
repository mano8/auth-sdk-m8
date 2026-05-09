"""
Prometheus metrics registry and setup.

Metric groups (set via METRICS_GROUPS, comma-separated):
  all          — enable every group below
  traffic      — http_requests_total (method, endpoint, status_code)
  performance  — http_request_duration_seconds histogram (method, endpoint)
  reliability  — http_errors_total for 4xx/5xx (method, endpoint, status_class)
  health       — http_status_total by exact status code
  auth         — auth_login_attempts_total, auth_token_refresh_total,
                 auth_logout_total, auth_token_validation_failures_total,
                 auth_oauth_attempts_total
                 (only meaningful in services that have auth routes)

Requires: pip install auth-sdk-m8[observability]

When METRICS_ENABLED=false (default) this module has zero runtime cost:
get() returns None and the middleware is never registered.
"""

from typing import Optional

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

REGISTRY = CollectorRegistry(auto_describe=False)

GROUP_ALL = "all"
GROUP_TRAFFIC = "traffic"
GROUP_PERFORMANCE = "performance"
GROUP_RELIABILITY = "reliability"
GROUP_HEALTH = "health"
GROUP_AUTH = "auth"

_ALL_GROUPS = frozenset(
    {GROUP_TRAFFIC, GROUP_PERFORMANCE, GROUP_RELIABILITY, GROUP_HEALTH, GROUP_AUTH}
)

_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class _Metrics:
    """Container for all metric objects; None means the group is disabled."""

    # traffic
    requests_total: Optional[Counter] = None
    # performance
    request_duration_seconds: Optional[Histogram] = None
    # reliability
    errors_total: Optional[Counter] = None
    # health
    status_total: Optional[Counter] = None
    # auth
    login_attempts_total: Optional[Counter] = None
    token_refresh_total: Optional[Counter] = None
    logout_total: Optional[Counter] = None
    token_validation_failures_total: Optional[Counter] = None
    oauth_attempts_total: Optional[Counter] = None


_m: Optional[_Metrics] = None


def _resolve_groups(groups_str: str) -> set[str]:
    raw = {g.strip().lower() for g in groups_str.split(",")}
    if GROUP_ALL in raw:
        return set(_ALL_GROUPS)
    return raw & _ALL_GROUPS


def _norm_prefix(api_prefix: str) -> str:
    """Derive a valid Prometheus metric name prefix from the API prefix."""
    p = api_prefix.strip().lstrip("/").replace("-", "_").replace("/", "_")
    return f"{p}_" if p else ""


def setup(enabled: bool, groups_str: str, api_prefix: str) -> None:
    """Initialize metrics registry. Call once at application startup.

    Args:
        enabled: Master switch — when False nothing is registered.
        groups_str: Comma-separated group names or ``"all"``.
        api_prefix: Service API prefix (e.g. ``"/user"``), used as metric
            name prefix to avoid collisions between services.
    """
    global _m
    if not enabled:
        _m = None
        return

    groups = _resolve_groups(groups_str)
    pfx = _norm_prefix(api_prefix)
    m = _Metrics()

    if GROUP_TRAFFIC in groups:
        m.requests_total = Counter(
            f"{pfx}http_requests_total",
            "Total HTTP requests",
            ["method", "endpoint", "status_code"],
            registry=REGISTRY,
        )

    if GROUP_PERFORMANCE in groups:
        m.request_duration_seconds = Histogram(
            f"{pfx}http_request_duration_seconds",
            "HTTP request latency in seconds",
            ["method", "endpoint"],
            buckets=_LATENCY_BUCKETS,
            registry=REGISTRY,
        )

    if GROUP_RELIABILITY in groups:
        m.errors_total = Counter(
            f"{pfx}http_errors_total",
            "Total 4xx and 5xx HTTP responses",
            ["method", "endpoint", "status_class"],
            registry=REGISTRY,
        )

    if GROUP_HEALTH in groups:
        m.status_total = Counter(
            f"{pfx}http_status_total",
            "HTTP responses by exact status code",
            ["status_code"],
            registry=REGISTRY,
        )

    if GROUP_AUTH in groups:
        m.login_attempts_total = Counter(
            f"{pfx}auth_login_attempts_total",
            "Login attempts (result: success | wrong_credentials | inactive_user | rate_limited)",
            ["result"],
            registry=REGISTRY,
        )
        m.token_refresh_total = Counter(
            f"{pfx}auth_token_refresh_total",
            "Token refresh attempts (result: success | invalid | revoked)",
            ["result"],
            registry=REGISTRY,
        )
        m.logout_total = Counter(
            f"{pfx}auth_logout_total",
            "Logout requests",
            registry=REGISTRY,
        )
        m.token_validation_failures_total = Counter(
            f"{pfx}auth_token_validation_failures_total",
            "Access token validation failures (reason: invalid | revoked | inactive)",
            ["reason"],
            registry=REGISTRY,
        )
        m.oauth_attempts_total = Counter(
            f"{pfx}auth_oauth_attempts_total",
            "OAuth callback attempts (provider: google, result: success | failed)",
            ["provider", "result"],
            registry=REGISTRY,
        )

    _m = m


def get() -> Optional[_Metrics]:
    """Return the metrics container, or None when observability is disabled."""
    return _m


def render() -> tuple[bytes, str]:
    """Return Prometheus text exposition and content-type header value."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
