# Changelog

All notable changes to `auth-sdk-m8` will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **`_validate_key_material` now accepts `JWKS_URI` as an alternative to `ACCESS_PUBLIC_KEY`**
  (`auth_sdk_m8/core/config.py`): consumer services using `JWKS_URI` for dynamic key resolution
  no longer fail startup validation with "ACCESS_PUBLIC_KEY is required".  Either
  `ACCESS_PUBLIC_KEY` (static key) or `JWKS_URI` (dynamic JWKS endpoint) satisfies the check for
  asymmetric algorithms — both remain valid configurations.

### Added

- **`check_config_health(settings, logger)` utility** (`auth_sdk_m8/core/config.py`): call this
  inside FastAPI's lifespan (or any startup hook) to surface env-var misconfigurations in logs
  before the first request.  Detects: RS256/ES256 with neither `ACCESS_PUBLIC_KEY` nor `JWKS_URI`;
  `JWKS_URI` set but algorithm is `HS256` (endpoint serves nothing useful); `ACCESS_PRIVATE_KEY`
  present without a corresponding public key (signing-only service warning); `TOKEN_MODE` is
  `stateful`/`hybrid` but Redis credentials are absent; `JWKS_CACHE_TTL_SECONDS` below 30 s.

---

## [0.4.2] - 2026-05-09

### Security

- **`AccessTokenBlacklist`** (`auth_sdk_m8/security/blacklist.py`): read-only Redis JTI
  blacklist check.  Consumer services use this to verify that an access token has not been
  revoked by the auth service, using the same `"jwt:blacklist:"` key prefix written by
  `RedisSessionManager.blacklist_jti()`.  Exported from `auth_sdk_m8.security`.

### Added

- **`build_access_validator(settings, hooks=None) -> TokenValidator`** (`auth_sdk_m8/security/factory.py`):
  factory function that constructs a `TokenValidator` from any `CommonSettings` (or compatible)
  instance.  Handles algorithm selection, asymmetric vs symmetric key choice, and `iss`/`aud`
  enforcement wiring in one canonical place.  Exported from `auth_sdk_m8.security`.
- **`TOKEN_ISSUER: Optional[str] = None`** and **`TOKEN_AUDIENCE: Optional[str] = None`** added to
  `CommonSettings`.  When set, `build_access_validator` embeds them in `TokenValidationConfig`
  with `require_iss=True` / `require_aud=True` automatically.  Services no longer need to declare
  these fields locally.

---

## [0.4.0] - 2026-05-08

### Added

- **`auth_sdk_m8.observability` package** (`pip install auth-sdk-m8[observability]`): optional
  Prometheus metrics layer with zero cost when disabled.
  - **`metrics.setup(enabled, groups_str, api_prefix)`**: initializes an isolated
    `CollectorRegistry` at startup.  When `enabled=False` no collectors are registered and
    `get()` returns `None` — the middleware skips all instrumentation in O(1).
  - **`metrics.get() → Optional[_Metrics]`**: returns the metrics container or `None`.
  - **`metrics.render() → (bytes, str)`**: returns Prometheus text exposition and content-type.
  - **Five metric groups** controlled by `METRICS_GROUPS` (comma-separated or `"all"`):
    - `traffic` — `http_requests_total` (method, endpoint, status_code)
    - `performance` — `http_request_duration_seconds` histogram (method, endpoint)
    - `reliability` — `http_errors_total` for 4xx/5xx (method, endpoint, status_class)
    - `health` — `http_status_total` by exact status code
    - `auth` — `auth_login_attempts_total`, `auth_token_refresh_total`, `auth_logout_total`,
      `auth_token_validation_failures_total`, `auth_oauth_attempts_total`
      (auth-specific; only meaningful in services with auth routes)
  - **`MetricsMiddleware`** (`auth_sdk_m8.observability.middleware`): Starlette
    `BaseHTTPMiddleware` that instruments every request.  UUID and integer path segments
    are normalized to `/{id}` to prevent label cardinality explosion.
  - **`ObservabilitySettingsMixin`** (`auth_sdk_m8.observability.settings`): pydantic
    `BaseModel` mixin that adds `METRICS_ENABLED: bool = False` and
    `METRICS_GROUPS: str = "all"` to any pydantic-settings `Settings` class via MRO-safe
    multiple inheritance.
- New `[observability]` optional extra: installs `prometheus-client>=0.21.0` and `fastapi>=0.115.7`.
- `prometheus-client>=0.21.0` added to the `[all]` extra.

## [0.3.0] - 2026-05-07

### Added

- **`TOKEN_MODE: Literal["stateless", "hybrid", "stateful"] = "stateful"`** in `CommonSettings`:
  signals to consuming services whether Redis is required and whether JTI revocation is active.
- **`ACCESS_TOKEN_ALGORITHM: str`** and **`REFRESH_TOKEN_ALGORITHM: str`** in `CommonSettings`:
  replace the single `TOKEN_ALGORITHM` with per-token-type algorithm fields.  `TOKEN_ALGORITHM`
  is kept as a backward-compat fallback — a non-default value propagates to the per-type fields
  via the `_sync_token_algorithms` model validator.
- **`ACCESS_PRIVATE_KEY: Optional[SecretStr]`**: PEM private key for RS256/ES256 signing in the
  auth service.  Added to `secret_fields` (bypasses the symmetric-key strength regex).
- **`ACCESS_PUBLIC_KEY: Optional[str]`**: PEM public key distributed to all consuming services
  for RS256/ES256 access token verification.
- **`_validate_key_material` model validator**: enforces that HS256 deployments provide
  `ACCESS_SECRET_KEY` and that RS256/ES256 deployments provide `ACCESS_PUBLIC_KEY`.  Raises
  `ValueError` at startup so misconfigured containers fail immediately.

### Changed

- **`ACCESS_SECRET_KEY`** changed from required `SecretStr` to `Optional[SecretStr] = None`.
  Removed from `secret_keys` (symmetric-key strength regex) — still listed in `secret_fields`.
  Required only when `ACCESS_TOKEN_ALGORITHM == "HS256"` (enforced by `_validate_key_material`).
- **`SECRET_KEY`** changed to `Optional[SecretStr] = None` and removed from `secret_fields`,
  `secret_keys`, and `REQUIRE_UPDATE_FIELDS`.  No longer used in the token signing flow.

## [0.2.0] - 2026-05-06

### Added

- **`ValidationHooks` protocol** (`auth_sdk_m8.security.hooks`): plug structured logging, metrics, or tracing into validation events.  `on_success` and `on_failure` callbacks are invoked by `TokenValidator`, `TokenPolicy`, and `RefreshTokenPolicy` with non-sensitive identifiers only.
- **`RefreshTokenStore` protocol** (`auth_sdk_m8.security.refresh_token_store`): backend-agnostic interface for refresh-token rotation tracking with `is_valid`, `rotate`, and `revoke` operations.
- **`RefreshTokenPolicy`** (`auth_sdk_m8.security.refresh_token_policy`): stateful refresh-token handler that enforces one-time use and atomic JTI rotation.  Stolen refresh tokens are detected on reuse; callers receive `(user_id, old_jti)` on success and can treat a reuse event as a compromise signal.  Degrades gracefully to pure JWT validation when no store is provided.
- `ES256` added to `TokenAlgorithm` — all three common algorithm families are now supported: `HS256` (symmetric), `RS256` and `ES256` (asymmetric).
- `ValidationHooks` and `RefreshTokenStore` / `RefreshTokenPolicy` are re-exported from `auth_sdk_m8.security`.

### Changed

- **`TokenSecret.validate_secret_key`** now skips the symmetric-key strength regex for asymmetric algorithms (`RS256`, `ES256`).  PEM-encoded public keys are accepted as-is, enabling asymmetric verification without a separate key type.
- **`TokenValidator`** accepts an optional `hooks: ValidationHooks` parameter.  Failure reasons (`"expired"`, `"invalid"`, `"wrong_type"`, `"invalid_payload"`) are surfaced to the hooks object before raising `InvalidToken`.
- **`TokenPolicy`** accepts an optional `hooks: ValidationHooks` parameter.  Fires `on_failure(reason="revoked")` when the session store rejects a token.
- **`core/security.py`** now imports `TokenValidator` and `TokenValidationConfig` directly from their submodules (`security.token_validator`, `security.validation`) instead of from `security.__init__`, eliminating the circular import that would have occurred once `RefreshTokenPolicy` was added to the public API.
- **`decode_refresh_token`** hardened: PyJWT is now instructed to `require` all four essential claims (`exp`, `sub`, `jti`, `type`) at the decode level; an algorithm whitelist is checked before decoding; `ExpiredSignatureError` is caught and translated to a clear `"Refresh token expired"` message; `sub` parsing is isolated from the general except clause for clearer error attribution.
- PostgreSQL support: set `SELECTED_DB=Postgres` to switch `SQLALCHEMY_DATABASE_URI` to `postgresql+psycopg2://...`
- New `[mysql]` optional extra installs `pymysql>=1.1.0`
- New `[postgres]` optional extra installs `psycopg2-binary>=2.9.0`
- `parse_integrity_error` now handles PostgreSQL error formats for unique, foreign key, and not-null violations alongside the existing MySQL patterns
- `ComSecurityHelper.decode_access_token()` now routes through the new `TokenValidator` and emits a `DeprecationWarning` while preserving legacy-compatible validation behavior
- `TokenValidationConfig.strict()` now includes hardened claim requirements including `iat` and `nbf`
- `TokenValidator` now supports either a static `TokenSecret` or dynamic `kid`-based key resolution while keeping verification local
- Test suite coverage was expanded substantially around the new security layer and deterministic path/config behavior

### Fixed

- `TokenSecret` no longer rejects PEM-formatted public keys for `RS256`/`ES256` — the symmetric-strength regex is skipped for asymmetric algorithms.
- Refresh token decoding now rejects missing or empty `jti` values
- Refresh token decoding now normalizes malformed `sub` values to `InvalidToken` instead of leaking internal exceptions
- `ResponseErrorBase.errors` is now a homogeneous `list[ResponseError]` instead of an optional mixed `str | ResponseError` list
- `parse_integrity_error()` and `parse_pydantic_errors()` now return typed `ResponseError` objects rather than raw dicts
- Filesystem-dependent tests were rewritten to avoid environment-specific temporary-directory failures on Windows

## [0.1.1] - 2026-05-02

### Fixed

- `parse_integrity_error`: error response no longer echoes PII (e.g. the user's email address) back to the caller; now returns a generic "Duplicate entry already exists." message
- Refresh token validation: tokens without an `exp` claim are now rejected with `InvalidToken` instead of being silently accepted as valid forever
- Access token validation: a `None` guard prevents an unhandled `TypeError` when `exp` is absent from the JWT payload

## [0.1.0] - 2026-05-01

### Added

- `schemas/auth` - JWT token schemas (`TokenUserData`, `TokenAccessData`, `TokenSecret`, `ExternalTokensData`, etc.)
- `schemas/base` - shared enums (`AuthProviderType`, `RoleType`, `Period`) and response models
- `schemas/user` - `UserModel`, `SessionModel`
- `schemas/shared` - `ValidationConstants` (regex patterns for passwords, secret keys, hosts, paths)
- `schemas/redis_events` - `EventBase`
- `schemas/user_events` - `UserDeletedEvent`
- `core/exceptions` - `InvalidToken`
- `core/security` - `ComSecurityHelper`: JWT decode, token hashing, PKCE helpers
- `core/config` - `CommonSettings` base class (extends `pydantic-settings`)
- `redis_events/` - `EventBus`, `EventPublisher`, `EventSubscriber`
- `controllers/base` - `BaseController` with unified exception handling
- `models/shared` - `TimestampMixin`, `Message`, `Token`, `TokenPayload`
- `utils/errors_parser` - `parse_integrity_error`, `parse_pydantic_errors`
- `utils/paths` - `find_dotenv`
