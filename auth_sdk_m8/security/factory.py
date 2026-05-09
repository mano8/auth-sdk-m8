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
    ``ACCESS_PUBLIC_KEY``, ``TOKEN_ISSUER``, and ``TOKEN_AUDIENCE`` from
    *settings*.  This eliminates the duplicated validator-construction
    boilerplate that would otherwise appear in every microservice.

    Args:
        settings: A CommonSettings (or compatible) instance.
        hooks: Optional ValidationHooks for logging / metrics callbacks.

    Returns:
        A module-level–safe TokenValidator ready for request-time use.
    """
    algo = settings.ACCESS_TOKEN_ALGORITHM
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

    issuer: Optional[str] = getattr(settings, "TOKEN_ISSUER", None) or None
    audience: Optional[str] = getattr(settings, "TOKEN_AUDIENCE", None) or None

    return TokenValidator(
        secrets=secret,
        config=TokenValidationConfig(
            allowed_algorithms=[algo],
            issuer=issuer,
            audience=audience,
            require_iss=bool(issuer),
            require_aud=bool(audience),
        ),
        hooks=hooks,
    )
