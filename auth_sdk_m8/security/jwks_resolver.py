"""JWKS-backed KeyResolver with in-memory caching and fetch hardening."""

import json
import logging
import threading
import time
import urllib.request
from typing import Optional

from pydantic import SecretStr

from auth_sdk_m8.schemas.auth import TokenSecret

_logger = logging.getLogger(__name__)

# Minimum seconds between JWKS fetch attempts.  Acts as a negative-cache TTL:
# when the auth server is down or a kid is simply absent, concurrent requests
# all hit this gate and back off together instead of hammering the endpoint.
_MIN_REFRESH_INTERVAL: float = 10.0


class JwksKeyResolver:
    """Resolve RS256/ES256 signing keys from a remote JWKS endpoint.

    Keys are cached in memory for *cache_ttl* seconds.  When an unknown
    ``kid`` is encountered the cache is refreshed once before raising
    ``LookupError`` — this supports zero-downtime key rotation without
    requiring a service restart.

    Fetch hardening:

    * **Throttling** — at most one fetch per ``_MIN_REFRESH_INTERVAL`` seconds,
      even under concurrent load.  A ``threading.Lock`` serialises callers so
      only the first thread fetches; the rest reuse the result.
    * **Negative cache** — failed fetches are rate-limited by the same
      interval, preventing a storm of retries when the auth server is down.
    * **Stale-cache fallback** — if a fetch fails but cached keys exist, the
      stale cache is served and a warning is logged.  Requests only fail when
      there is no cache at all.

    Args:
        jwks_uri: Full URL of the JWKS endpoint
            (e.g. ``https://auth.example.com/user/.well-known/jwks.json``).
        algorithm: JWT algorithm expected for every key in this set.
        cache_ttl: Seconds before the cache is considered stale.
    """

    def __init__(
        self,
        jwks_uri: str,
        algorithm: str = "RS256",
        cache_ttl: int = 300,
    ) -> None:
        self._jwks_uri = jwks_uri
        self._algorithm = algorithm
        self._cache_ttl = cache_ttl
        self._cache: dict[Optional[str], TokenSecret] = {}
        self._cache_expires_at: float = 0.0
        self._lock = threading.Lock()
        self._last_refresh_attempt: float = 0.0

    # ── KeyResolver protocol ──────────────────────────────────────────────────

    def resolve(self, kid: Optional[str]) -> TokenSecret:
        """Return the ``TokenSecret`` for *kid*, refreshing the cache if needed.

        Raises:
            LookupError: No matching key after a cache refresh.
        """
        now = time.monotonic()
        if now >= self._cache_expires_at:
            self._guarded_refresh()
            return self._get_or_raise(kid)

        if kid not in self._cache:
            # Unknown kid — try a one-shot refresh before failing.
            self._guarded_refresh()

        return self._get_or_raise(kid)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _guarded_refresh(self) -> None:
        """Throttled, lock-serialised refresh — at most one fetch per interval.

        Fast path: if another thread refreshed within ``_MIN_REFRESH_INTERVAL``
        seconds, skip the fetch entirely and let the caller use the current
        cache (which may be stale but is always better than a request storm).
        """
        now = time.monotonic()
        if now - self._last_refresh_attempt < _MIN_REFRESH_INTERVAL:
            return  # Rate-limited — reuse existing cache.

        with self._lock:
            # Re-check under the lock: a concurrent thread may have fetched
            # while we were waiting to acquire it.
            now = time.monotonic()
            if now - self._last_refresh_attempt < _MIN_REFRESH_INTERVAL:
                return
            self._last_refresh_attempt = now
            self._refresh()

    def _get_or_raise(self, kid: Optional[str]) -> TokenSecret:
        try:
            return self._cache[kid]
        except KeyError:
            raise LookupError(
                f"No key with kid={kid!r} found in JWKS at {self._jwks_uri}"
            )

    def _refresh(self) -> None:
        """Fetch the JWKS endpoint and rebuild the in-memory cache.

        On fetch failure, serves the existing stale cache when available so
        that a transient auth-server outage does not immediately break
        validation.  Raises when there is no cached data at all.
        """
        try:
            keys = self._fetch_jwks()
        except Exception as exc:
            if self._cache:
                _logger.warning(
                    "JWKS refresh failed (%s); serving stale cache "
                    "until next attempt in %.0fs.",
                    exc,
                    _MIN_REFRESH_INTERVAL,
                )
                return
            raise

        new_cache: dict[Optional[str], TokenSecret] = {}
        for jwk in keys:
            if jwk.get("use", "sig") != "sig":
                continue
            pem = self._jwk_to_pem(jwk)
            new_cache[jwk.get("kid")] = TokenSecret(
                secret_key=SecretStr(pem),
                algorithm=self._algorithm,
            )
        self._cache = new_cache
        self._cache_expires_at = time.monotonic() + self._cache_ttl

    def _fetch_jwks(self) -> list[dict]:
        """Download and parse the JWKS JSON document."""
        with urllib.request.urlopen(self._jwks_uri, timeout=5) as resp:  # noqa: S310
            body = json.loads(resp.read())
        return body.get("keys", [])

    @staticmethod
    def _jwk_to_pem(jwk: dict) -> str:
        """Convert a JWK dict to a PEM-encoded public key string."""
        from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
            Encoding,
            PublicFormat,
        )
        from jwt.algorithms import ECAlgorithm, RSAAlgorithm  # noqa: PLC0415

        kty = jwk.get("kty", "RSA")
        alg_cls = ECAlgorithm if kty == "EC" else RSAAlgorithm
        key_obj = alg_cls.from_jwk(json.dumps(jwk))
        return key_obj.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
