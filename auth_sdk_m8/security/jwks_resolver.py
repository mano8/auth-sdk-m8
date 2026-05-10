"""JWKS-backed KeyResolver with in-memory caching."""

import json
import time
import urllib.request
from typing import Optional

from pydantic import SecretStr

from auth_sdk_m8.schemas.auth import TokenSecret


class JwksKeyResolver:
    """Resolve RS256/ES256 signing keys from a remote JWKS endpoint.

    Keys are cached in memory for *cache_ttl* seconds.  When an unknown
    ``kid`` is encountered the cache is refreshed once before raising
    ``LookupError`` — this supports zero-downtime key rotation without
    requiring a service restart.

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

    # ── KeyResolver protocol ──────────────────────────────────────────────────

    def resolve(self, kid: Optional[str]) -> TokenSecret:
        """Return the ``TokenSecret`` for *kid*, refreshing the cache if needed.

        Raises:
            LookupError: No matching key after a cache refresh.
        """
        now = time.monotonic()
        if now >= self._cache_expires_at:
            self._refresh()
            return self._get_or_raise(kid)

        if kid not in self._cache:
            # Unknown kid — try a one-shot refresh before failing.
            self._refresh()

        return self._get_or_raise(kid)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_or_raise(self, kid: Optional[str]) -> TokenSecret:
        try:
            return self._cache[kid]
        except KeyError:
            raise LookupError(
                f"No key with kid={kid!r} found in JWKS at {self._jwks_uri}"
            )

    def _refresh(self) -> None:
        """Fetch the JWKS endpoint and rebuild the in-memory cache."""
        keys = self._fetch_jwks()
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
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        from jwt.algorithms import ECAlgorithm, RSAAlgorithm

        kty = jwk.get("kty", "RSA")
        alg_cls = ECAlgorithm if kty == "EC" else RSAAlgorithm
        key_obj = alg_cls.from_jwk(json.dumps(jwk))
        return key_obj.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
