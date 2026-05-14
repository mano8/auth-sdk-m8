"""Factory for building a TokenValidator from service settings."""

from typing import Any, Optional

from pydantic import SecretStr

from auth_sdk_m8.schemas.auth import ASYMMETRIC_ALGORITHMS, TokenSecret
from auth_sdk_m8.security.hooks import ValidationHooks
from auth_sdk_m8.security.token_validator import TokenValidator
from auth_sdk_m8.security.validation import TokenValidationConfig


def build_access_validator(
    settings: Any,
    hooks: Optional[ValidationHooks] = None,
) -> TokenValidator:
    """Create a TokenValidator wired to CommonSettings (or any subclass).

    Reads ``ACCESS_TOKEN_ALGORITHM``, ``ACCESS_SECRET_KEY`` /
    ``ACCESS_PUBLIC_KEY``, ``TOKEN_ISSUER``, ``TOKEN_AUDIENCE``, and
    optionally ``JWKS_URI`` / ``JWKS_CACHE_TTL_SECONDS`` from *settings*.

    When ``JWKS_URI`` is set and the algorithm is asymmetric, a
    ``JwksKeyResolver`` is used instead of a static public key — enabling
    zero-downtime key rotation without redeploying consumer services.

    The ``AUTH_SERVICE_ROLE`` field (``"issuer"`` or ``"consumer"``) is not
    read here; it drives startup enforcement in ``check_config_health()``.
    By the time this factory runs, settings have already been validated.

    Args:
        settings: A CommonSettings (or compatible) instance.
        hooks: Optional ValidationHooks for logging / metrics callbacks.

    Returns:
        A module-level–safe TokenValidator ready for request-time use.
    """
    algo = settings.ACCESS_TOKEN_ALGORITHM
    issuer: Optional[str] = getattr(settings, "TOKEN_ISSUER", None) or None
    audience: Optional[str] = getattr(settings, "TOKEN_AUDIENCE", None) or None
    config = TokenValidationConfig(
        allowed_algorithms=[algo],
        issuer=issuer,
        audience=audience,
        require_iss=bool(issuer),
        require_aud=bool(audience),
    )

    jwks_uri: Optional[str] = getattr(settings, "JWKS_URI", None) or None
    if jwks_uri and algo in ASYMMETRIC_ALGORITHMS:
        from auth_sdk_m8.security.jwks_resolver import JwksKeyResolver

        cache_ttl: int = getattr(settings, "JWKS_CACHE_TTL_SECONDS", 300)
        return TokenValidator(
            secrets=None,
            config=config,
            key_resolver=JwksKeyResolver(jwks_uri, algorithm=algo, cache_ttl=cache_ttl),
            hooks=hooks,
        )

    if algo in ASYMMETRIC_ALGORITHMS:
        secret = TokenSecret(
            secret_key=SecretStr(settings.ACCESS_PUBLIC_KEY or ""),
            algorithm=algo,
        )
    else:
        secret = TokenSecret(
            secret_key=settings.ACCESS_SECRET_KEY,
            algorithm=algo,
        )

    return TokenValidator(secrets=secret, config=config, hooks=hooks)
