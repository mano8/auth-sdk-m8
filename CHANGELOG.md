# Changelog

All notable changes to `auth-sdk-m8` will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- PostgreSQL support: set `SELECTED_DB=Postgres` to switch `SQLALCHEMY_DATABASE_URI` to `postgresql+psycopg2://...`
- New `[mysql]` optional extra installs `pymysql>=1.1.0`
- New `[postgres]` optional extra installs `psycopg2-binary>=2.9.0`
- `parse_integrity_error` now handles PostgreSQL error formats for unique, foreign key, and not-null violations alongside the existing MySQL patterns
- New `auth_sdk_m8.security` package with:
  - `TokenValidator` for pure JWT validation
  - `TokenPolicy` for optional async revocation checks
  - `SessionStore` protocol for pluggable stateful validation backends
  - `TokenValidationConfig` with permissive defaults and a stricter preset for new integrations
- README documentation for stateless versus stateful validation, plus validator/policy integration examples

### Changed

- `ComSecurityHelper.decode_access_token()` now routes through the new `TokenValidator` and emits a `DeprecationWarning` while preserving legacy-compatible validation behavior
- `TokenValidationConfig.strict()` now includes hardened claim requirements including `iat` and `nbf`
- Test suite coverage was expanded substantially around the new security layer and deterministic path/config behavior

### Fixed

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
