"""Startup configuration health checks for CommonSettings."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from auth_sdk_m8.core.exceptions import ConfigurationError

if TYPE_CHECKING:
    from auth_sdk_m8.core.config import CommonSettings


def _check_jwt_config(
    algo: str,
    pub_key: str | None,
    jwks_uri: str | None,
    cache_ttl: int,
) -> tuple[list[str], list[str]]:
    fatal: list[str] = []
    warnings: list[str] = []
    if algo != "HS256" and not pub_key and not jwks_uri:  # nosec B105
        fatal.append(
            f"CONFIG: ACCESS_TOKEN_ALGORITHM={algo} but neither "
            "ACCESS_PUBLIC_KEY_FILE nor JWKS_URI is set — "
            "token validation will fail at runtime"
        )
    if jwks_uri and algo == "HS256":  # nosec B105
        warnings.append(
            "CONFIG: JWKS_URI is set but ACCESS_TOKEN_ALGORITHM=HS256 — "
            "JWKS is only meaningful for asymmetric algorithms "
            "(RS256, ES256). Remove JWKS_URI or switch the algorithm."
        )
    if jwks_uri and cache_ttl < 30:
        warnings.append(
            f"CONFIG: JWKS_CACHE_TTL_SECONDS={cache_ttl} is very low — "
            "the JWKS endpoint will be fetched on nearly every request. "
            "Recommended minimum: 30 s; default: 300 s."
        )
    return fatal, warnings


def _check_role_config(
    algo: str,
    role: str,
    priv_key_file: str | None,
    jwks_uri: str | None,
    settings: CommonSettings,
    strict: bool,
) -> tuple[list[str], list[str]]:
    fatal: list[str] = []
    warnings: list[str] = []
    if role == "consumer" and priv_key_file:
        fatal.append(
            "CONFIG: AUTH_SERVICE_ROLE=consumer services must not hold a "
            "signing private key. Remove ACCESS_PRIVATE_KEY_FILE — consumers "
            "validate tokens via JWKS or a static public key only."
        )
    if role == "issuer" and algo != "HS256" and not priv_key_file:  # nosec B105
        fatal.append(
            f"CONFIG: AUTH_SERVICE_ROLE=issuer with {algo} requires "
            "ACCESS_PRIVATE_KEY_FILE — issuers must hold the signing key "
            "to issue tokens."
        )
    if role == "issuer" and jwks_uri:
        msg = (
            "CONFIG: AUTH_SERVICE_ROLE=issuer has JWKS_URI set — issuers "
            "validate tokens using their own key material, not a remote JWKS. "
            "Remove JWKS_URI unless this service also consumes tokens from "
            "another issuer."
        )
        (fatal if strict else warnings).append(msg)
    if role == "consumer" and settings.is_stateless:
        db_host: str = getattr(settings, "DB_HOST", "") or ""
        if db_host:
            warnings.append(
                "CONFIG: AUTH_SERVICE_ROLE=consumer with TOKEN_MODE=stateless "
                f"but DB_HOST={db_host!r} is set — "
                "consumer services in stateless mode typically do not require a "
                "database. Remove DB_* settings if this service does not use the "
                "database directly."
            )
    return fatal, warnings


def _check_redis_config(settings: CommonSettings) -> list[str]:
    if not settings.requires_redis:
        return []
    redis_host: str = getattr(settings, "REDIS_HOST", "") or ""
    redis_pass = getattr(settings, "REDIS_PASSWORD", None)
    if redis_host and redis_pass:
        return []
    return [
        f"CONFIG: TOKEN_MODE={settings.TOKEN_MODE} requires Redis for token revocation "
        "but REDIS_HOST or REDIS_PASSWORD is not configured — "
        "refresh token rotation and blacklisting are disabled"
    ]


def _check_production_env(
    settings: CommonSettings,
    environment: str,
    strict: bool,
) -> tuple[list[str], list[str]]:
    if environment != "production":
        return [], []
    fatal: list[str] = []
    warnings: list[str] = []
    allowed_origins: list[str] = getattr(settings, "ALLOWED_ORIGINS", []) or []
    local_origins = [o for o in allowed_origins if "localhost" in o or "127.0.0.1" in o]
    if local_origins:
        fatal.append(
            f"CONFIG: ENVIRONMENT=production but ALLOWED_ORIGINS contains "
            f"localhost entries {local_origins} — "
            "remove all localhost/127.0.0.1 origins before deploying to production."
        )
    for attr, label, flag in [
        ("SET_DOCS", "Swagger UI", "SET_DOCS=false"),
        ("SET_OPEN_API", "OpenAPI schema endpoint", "SET_OPEN_API=false"),
    ]:
        if getattr(settings, attr, True):
            msg = (
                f"CONFIG: ENVIRONMENT=production with {attr}=true — "
                f"{label} is publicly accessible. "
                f"Set {flag} to disable it in production."
            )
            (fatal if strict else warnings).append(msg)
    return fatal, warnings


def _check_strict_mode(settings: CommonSettings, environment: str) -> list[str]:
    if not getattr(settings, "STRICT_PRODUCTION_MODE", False):
        return []
    fatal: list[str] = []
    allowed_origins: list[str] = getattr(settings, "ALLOWED_ORIGINS", []) or []
    if "*" in allowed_origins:
        fatal.append(
            "CONFIG: STRICT_PRODUCTION_MODE=true but ALLOWED_ORIGINS contains "
            "a wildcard ('*') origin — specify explicit origins instead."
        )
    if environment not in {"local"}:
        cookie_secure: bool = getattr(settings, "SESSION_COOKIE_SECURE", True)
        if not cookie_secure:
            fatal.append(
                f"CONFIG: STRICT_PRODUCTION_MODE=true but "
                f"SESSION_COOKIE_SECURE=false in ENVIRONMENT={environment!r} — "
                "set SESSION_COOKIE_SECURE=true to enforce the Secure cookie flag."
            )
    return fatal


def check_config_health(
    settings: CommonSettings,
    logger: logging.Logger,
) -> None:
    """Validate critical application configuration at startup.

    Logs warnings for suspicious configuration and raises
    ``ConfigurationError`` for fatal misconfigurations.  Call this inside
    the FastAPI lifespan so operators see problems before the first request.

    Checks performed:
    - RS256/ES256 algorithm without any public-key source (fatal)
    - JWKS_URI set but ACCESS_TOKEN_ALGORITHM is HS256 (warning)
    - JWKS_CACHE_TTL_SECONDS below 30 s (warning)
    - AUTH_SERVICE_ROLE=consumer with ACCESS_PRIVATE_KEY_FILE (fatal)
    - AUTH_SERVICE_ROLE=issuer with asymmetric algorithm but no private key (fatal)
    - AUTH_SERVICE_ROLE=issuer with JWKS_URI set (warning / fatal under STRICT)
    - AUTH_SERVICE_ROLE=consumer + TOKEN_MODE=stateless + DB_HOST set (warning)
    - TOKEN_MODE=stateful/hybrid without Redis credentials (fatal)
    - ENVIRONMENT=production with localhost origins in ALLOWED_ORIGINS (fatal)
    - ENVIRONMENT=production with SET_DOCS/SET_OPEN_API enabled (warning / fatal under STRICT)
    - STRICT_PRODUCTION_MODE: wildcard in ALLOWED_ORIGINS (fatal)
    - STRICT_PRODUCTION_MODE: SESSION_COOKIE_SECURE=false outside local (fatal)
    """
    strict: bool = getattr(settings, "STRICT_PRODUCTION_MODE", False)
    algo = settings.ACCESS_TOKEN_ALGORITHM
    jwks_uri: str | None = getattr(settings, "JWKS_URI", None) or None
    pub_key: str | None = getattr(settings, "ACCESS_PUBLIC_KEY", None) or None
    priv_key_file: str | None = (
        getattr(settings, "ACCESS_PRIVATE_KEY_FILE", None) or None
    )
    cache_ttl: int = getattr(settings, "JWKS_CACHE_TTL_SECONDS", 300)
    role: str = getattr(settings, "AUTH_SERVICE_ROLE", "issuer")
    environment: str = getattr(settings, "ENVIRONMENT", "local")

    f1, w1 = _check_jwt_config(algo, pub_key, jwks_uri, cache_ttl)
    f2, w2 = _check_role_config(algo, role, priv_key_file, jwks_uri, settings, strict)
    f3 = _check_redis_config(settings)
    f4, w4 = _check_production_env(settings, environment, strict)
    f5 = _check_strict_mode(settings, environment)

    warnings = w1 + w2 + w4
    fatal_errors = f1 + f2 + f3 + f4 + f5

    for warning in warnings:
        logger.warning(warning)
    if fatal_errors:
        for error in fatal_errors:
            logger.critical(error)
        raise ConfigurationError("Fatal configuration errors detected during startup.")
