"""Startup configuration health checks for CommonSettings."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from auth_sdk_m8.core.exceptions import ConfigurationError


@runtime_checkable
class _SettingsProto(Protocol):
    """Structural protocol covering what check_config_health reads from settings."""

    ACCESS_TOKEN_ALGORITHM: str
    TOKEN_MODE: str

    @property
    def is_stateless(self) -> bool: ...

    @property
    def requires_redis(self) -> bool: ...


class _LoggerProto(Protocol):
    """Structural protocol for the logger accepted by check_config_health."""

    def warning(self, msg: str, *args: object) -> None: ...

    def critical(self, msg: str, *args: object) -> None: ...


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
    settings: _SettingsProto,
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


def _check_redis_config(settings: _SettingsProto) -> list[str]:
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
    settings: _SettingsProto,
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
    if getattr(settings, "SERVE_DOCS_IN_PRODUCTION", False):
        # Explicit opt-in: allowed and never fatal (even under STRICT), but never
        # silent — always warn so the operator is reminded of the exposed-console risk.
        if any(
            getattr(settings, a, True)
            for a in ("SET_DOCS", "SET_OPEN_API", "SET_REDOC")
        ):
            warnings.append(
                "CONFIG: ENVIRONMENT=production with SERVE_DOCS_IN_PRODUCTION=true — "
                "interactive API docs (Swagger/ReDoc/OpenAPI) are intentionally published "
                "in production. This exposes a live docs console wired to the production "
                "server; confirm the exposed surface is acceptable."
            )
    else:
        for attr, label, flag in [
            ("SET_DOCS", "Swagger UI", "SET_DOCS=false"),
            ("SET_OPEN_API", "OpenAPI schema endpoint", "SET_OPEN_API=false"),
        ]:
            if getattr(settings, attr, True):
                msg = (
                    f"CONFIG: ENVIRONMENT=production with {attr}=true — "
                    f"{label} is publicly accessible. "
                    f"Set {flag} to disable it, or set "
                    f"SERVE_DOCS_IN_PRODUCTION=true to publish docs intentionally."
                )
                (fatal if strict else warnings).append(msg)
    return fatal, warnings


def _check_strict_mode(settings: _SettingsProto, environment: str) -> list[str]:
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


_RATE_LIMIT_WARNING_RPM: dict[str, float] = {
    "login": 5.0,
    "refresh": 20.0,
}


def _check_token_boundary_config(
    settings: _SettingsProto,
    environment: str,
    strict: bool,
) -> tuple[list[str], list[str]]:
    """Warn when TOKEN_ISSUER or TOKEN_AUDIENCE are unset in production.

    Without these claims, tokens issued in dev are accepted in production
    (same key, no boundary check) and a token for one service can be
    replayed against another.
    """
    if environment != "production":
        return [], []
    fatal: list[str] = []
    warnings: list[str] = []
    issuer: str | None = getattr(settings, "TOKEN_ISSUER", None) or None
    audience: str | None = getattr(settings, "TOKEN_AUDIENCE", None) or None
    if not issuer:
        msg = (
            "CONFIG: ENVIRONMENT=production but TOKEN_ISSUER is not set — "
            "tokens have no issuer boundary; a dev-environment token signed "
            "with the same key is valid in production. "
            "Set TOKEN_ISSUER to a unique service identifier (e.g. "
            "'https://auth.example.com')."
        )
        (fatal if strict else warnings).append(msg)
    if not audience:
        msg = (
            "CONFIG: ENVIRONMENT=production but TOKEN_AUDIENCE is not set — "
            "tokens have no audience boundary; a token issued for one service "
            "can be replayed against another. "
            "Set TOKEN_AUDIENCE to the consuming service's URL or identifier."
        )
        (fatal if strict else warnings).append(msg)
    return fatal, warnings


_internal_url_fields: tuple[str, ...] = ("JWKS_URI", "INTROSPECTION_URL")


def _check_internal_url_config(
    settings: _SettingsProto,
    environment: str,
    strict: bool,
) -> tuple[list[str], list[str]]:
    """Warn or fail when inter-service URLs use plain http:// in production.

    Rules (applied to JWKS_URI and INTROSPECTION_URL):
    - local/development → always allowed (internal Docker bridge, no-op).
    - ALLOW_INTERNAL_HTTP=true → break-glass opt-in; allowed in any env.
    - staging/production + http:// → warning.
    - staging/production + http:// + strict → fatal.
    - https:// or field not set → always passes.
    """
    if environment not in {"staging", "production"}:
        return [], []
    if getattr(settings, "ALLOW_INTERNAL_HTTP", False):
        return [], []
    fatal: list[str] = []
    warnings: list[str] = []
    for field in _internal_url_fields:
        val = getattr(settings, field, None)
        if not val:
            continue
        url_str = str(val)
        if not url_str.startswith("http://"):
            continue
        msg = (
            f"CONFIG: {field}={url_str!r} uses plain http:// in "
            f"ENVIRONMENT={environment!r} — use https:// for inter-service "
            "calls, or set ALLOW_INTERNAL_HTTP=true if all traffic is "
            "confined to a trusted internal Docker network."
        )
        (fatal if strict else warnings).append(msg)
    return fatal, warnings


def _check_allowed_hosts_config(
    settings: _SettingsProto,
    environment: str,
    strict: bool,
) -> tuple[list[str], list[str]]:
    """Gate ALLOWED_HOSTS for production/strict environments.

    Rules:
    - Settings type without the attribute → no-op (backward-compatible).
    - local + not strict → no-op regardless of value.
    - prod + empty/None → warning (operator should restrict Host headers).
    - strict + empty/None → fatal.
    - strict + ``"*"`` in list → fatal (wildcard defeats the control).
    """
    if not hasattr(settings, "ALLOWED_HOSTS"):
        return [], []
    hosts: list[str] = getattr(settings, "ALLOWED_HOSTS") or []
    fatal: list[str] = []
    warnings: list[str] = []
    is_prod = environment == "production"
    if strict and "*" in hosts:
        fatal.append(
            "CONFIG: ALLOWED_HOSTS contains a wildcard ('*') under "
            "STRICT_PRODUCTION_MODE — specify explicit host names instead."
        )
    if not hosts and (strict or is_prod):
        msg = (
            "CONFIG: ALLOWED_HOSTS is not configured — "
            "set ALLOWED_HOSTS to restrict accepted Host headers in production."
        )
        (fatal if strict else warnings).append(msg)
    return fatal, warnings


def _check_rate_limit_config(settings: _SettingsProto) -> list[str]:
    warnings: list[str] = []
    for control, threshold in _RATE_LIMIT_WARNING_RPM.items():
        if control == "refresh" and settings.is_stateless:
            continue  # stateless mode — no refresh tokens issued
        prefix = control.upper()
        requests: int = getattr(settings, f"{prefix}_RATE_LIMIT_REQUESTS", 5)
        window: int = getattr(settings, f"{prefix}_RATE_LIMIT_WINDOW_MINUTES", 15)
        rate: float = requests / float(window)
        if rate > threshold:
            warnings.append(
                f"CONFIG: {prefix}_RATE_LIMIT_REQUESTS={requests} / "
                f"{prefix}_RATE_LIMIT_WINDOW_MINUTES={window} "
                f"→ {rate:.1f} req/min — rate limit is highly permissive "
                "and may weaken abuse protection."
            )
    return warnings


def check_config_health(
    settings: _SettingsProto,
    logger: _LoggerProto,
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
    - ENVIRONMENT=production with SET_DOCS/SET_OPEN_API enabled (warning / fatal under STRICT),
      unless SERVE_DOCS_IN_PRODUCTION=true opts in
    - ENVIRONMENT=production with TOKEN_ISSUER or TOKEN_AUDIENCE unset (warning / fatal under STRICT)
    - STRICT_PRODUCTION_MODE: wildcard in ALLOWED_ORIGINS (fatal)
    - STRICT_PRODUCTION_MODE: SESSION_COOKIE_SECURE=false outside local (fatal)
    - ALLOWED_HOSTS empty/unset in production (warning) or strict mode (fatal)
    - ALLOWED_HOSTS wildcard '*' under strict mode (fatal)
    - JWKS_URI / INTROSPECTION_URL using http:// in prod/strict (warning/fatal)
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
    w6 = _check_rate_limit_config(settings)
    f7, w7 = _check_token_boundary_config(settings, environment, strict)
    f8, w8 = _check_allowed_hosts_config(settings, environment, strict)
    f9, w9 = _check_internal_url_config(settings, environment, strict)

    warnings: list[str] = []
    warnings.extend(w1)
    warnings.extend(w2)
    warnings.extend(w4)
    warnings.extend(w6)
    warnings.extend(w7)
    warnings.extend(w8)
    warnings.extend(w9)
    fatal_errors = f1 + f2 + f3 + f4 + f5 + f7 + f8 + f9

    for warning in warnings:
        logger.warning(warning)
    if fatal_errors:
        for error in fatal_errors:
            logger.critical(error)
        raise ConfigurationError("Fatal configuration errors detected during startup.")
