"""HTTP metrics middleware — covers traffic, performance, reliability, and health groups."""

import re
import time
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from auth_sdk_m8.observability.metrics import get

_UUID_RE = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_INT_ID_RE = re.compile(r"/\d+")


def _endpoint_label(path: str) -> str:
    """Normalise dynamic path segments to avoid high-cardinality label values."""
    path = _UUID_RE.sub("/{id}", path)
    path = _INT_ID_RE.sub("/{id}", path)
    return path


class MetricsMiddleware(BaseHTTPMiddleware):
    """Collect per-request HTTP metrics for all enabled groups.

    Register via ``app.add_middleware(MetricsMiddleware)`` after calling
    ``auth_sdk_m8.observability.metrics.setup()``.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Record request duration and delegate to the next middleware."""
        m = get()
        if m is None:
            return await call_next(request)

        method = request.method
        endpoint = _endpoint_label(request.url.path)

        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start

        status_code = str(response.status_code)

        if m.requests_total is not None:
            m.requests_total.labels(
                method=method, endpoint=endpoint, status_code=status_code
            ).inc()

        if m.request_duration_seconds is not None:
            m.request_duration_seconds.labels(method=method, endpoint=endpoint).observe(
                duration
            )

        if m.errors_total is not None and response.status_code >= 400:
            status_class = f"{response.status_code // 100}xx"
            m.errors_total.labels(
                method=method, endpoint=endpoint, status_class=status_class
            ).inc()

        if m.status_total is not None:
            m.status_total.labels(status_code=status_code).inc()

        return response
