# Changelog

All notable changes to `auth-sdk-m8` will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

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
