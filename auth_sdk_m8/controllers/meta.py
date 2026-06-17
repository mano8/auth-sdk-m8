"""Mountable ``/meta`` + ``/ping`` routes for the standard m8 service triad.

Requires the ``fastapi`` extra:  pip install "auth-sdk-m8[fastapi]"

- ``{prefix}/meta`` — static service/version/contract identity for client
  compatibility checks (cacheable, no dependency I/O).
- ``/ping`` + ``{prefix}/ping`` — dependency-free liveness probe, mounted at
  **both** the root (so direct container/sidecar probes never depend on app
  routing/prefix config) and under ``{prefix}`` (so it stays reachable through a
  prefix-routing reverse proxy such as Traefik, which only forwards
  ``PathPrefix({prefix})`` — a root-only ``/ping`` 404s at the gateway).

The shared building block lives here because auth-sdk-m8 is the only common
dependency of both the issuer (fa-auth-m8) and the consumer framework
(fastapi-m8). ``mount_service_meta`` takes ``meta`` as a **required** argument,
so a service literally cannot mount the routes without supplying valid values —
provide-or-fail enforced at the call site.
"""

from fastapi import APIRouter, FastAPI, Response

from auth_sdk_m8.schemas.meta import ServiceMeta

#: Static liveness response body for ``/ping``.
PING_RESPONSE: dict[str, str] = {"status": "ok"}
#: ``Cache-Control`` for ``/meta`` — effectively static per deploy.
META_CACHE_CONTROL = "public, max-age=300"


def _build_meta_router(meta: ServiceMeta, prefix: str) -> APIRouter:
    """Build the ``{prefix}/meta`` router bound to *meta*."""
    router = APIRouter(prefix=prefix, tags=["meta"])

    @router.get("/meta", response_model=ServiceMeta)
    def get_meta(response: Response) -> ServiceMeta:
        """Return static service/version/contract metadata."""
        response.headers["Cache-Control"] = META_CACHE_CONTROL
        return meta

    return router


def _build_ping_router(prefix: str = "", *, in_schema: bool = True) -> APIRouter:
    """Build a ``{prefix}/ping`` liveness router (root when *prefix* is empty)."""
    router = APIRouter(prefix=prefix, tags=["meta"])

    @router.get("/ping", include_in_schema=in_schema)
    def get_ping() -> dict[str, str]:
        """Return a dependency-free liveness response."""
        return PING_RESPONSE

    return router


def mount_service_meta(
    app: FastAPI,
    meta: ServiceMeta,
    *,
    prefix: str = "",
) -> None:
    """Mount the standard ``/meta`` and ``/ping`` routes onto *app*.

    Args:
        app: The FastAPI application to mount the routes on.
        meta: Required service metadata served at ``{prefix}/meta``. Supplying it
            is mandatory — a service cannot mount the routes without valid values
            (provide-or-fail at the call site; empty fields fail ``ServiceMeta``
            validation).
        prefix: Optional API prefix for ``/meta`` and the proxy-routable copy of
            ``/ping``. ``/ping`` is always mounted at the root for direct
            liveness probes; when *prefix* is non-empty it is **also** mounted at
            ``{prefix}/ping`` (hidden from the schema to avoid a duplicate
            operation) so it remains reachable behind a prefix-routing proxy.
    """
    app.include_router(_build_meta_router(meta, prefix))
    app.include_router(_build_ping_router())
    if prefix:
        app.include_router(_build_ping_router(prefix, in_schema=False))
