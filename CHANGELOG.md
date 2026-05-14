# Changelog

All notable changes to `auth-sdk-m8` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [0.6.4] — 2026-05-14 · RS256/ES256 round-trip tests

- Added `tests/test_asymmetric_tokens.py`: comprehensive RS256 and ES256 key generation,
  token signing, and validation round-trip tests covering both issuer and consumer paths.
- No API changes; test-only release to lock in asymmetric coverage.

---

## [0.6.3] — 2026-05-14 · `STRICT_PRODUCTION_MODE`

- **`STRICT_PRODUCTION_MODE: bool = False`** added to `CommonSettings`.
  When `True`, `check_config_health` escalates the following from *warnings* to *fatal errors*:
  - `SET_DOCS=true` or `SET_OPEN_API=true` in production
  - `AUTH_SERVICE_ROLE=issuer` with `JWKS_URI` set
- **New strict-mode-only checks:**
  - Wildcard (`*`) origin in `ALLOWED_ORIGINS` → fatal
  - `SESSION_COOKIE_SECURE=false` outside `ENVIRONMENT=local` → fatal
- Recommended for staging/production CI gates where misconfigurations should abort deployment.

---

## [0.6.2] — 2026-05-14 · Production deployment enforcement

- **`check_config_health`** now validates production-specific configuration:
  - `ENVIRONMENT=production` with `localhost`/`127.0.0.1` in `ALLOWED_ORIGINS` → **fatal**
  - `ENVIRONMENT=production` with `SET_DOCS=true` or `SET_OPEN_API=true` → warning
    (fatal under `STRICT_PRODUCTION_MODE`)
  - `AUTH_SERVICE_ROLE=consumer` + `TOKEN_MODE=stateless` + `DB_HOST` set → warning
    (stateless consumers typically do not need a database)

---

## [0.6.1] — 2026-05-14 · Key-strength validation, JWKS hardening, `AUTH_SERVICE_ROLE`

- **`_assert_key_strength(pem, algo, *, is_private)`** — new module-level helper that
  enforces cryptographic minimums: RS256 requires ≥ 2048-bit RSA keys; ES256 requires
  P-256 (secp256r1) EC keys.  Called automatically by `_validate_key_strength`.
- **`_validate_key_strength`** model validator added to `CommonSettings`: runs at startup
  and rejects under-strength private or public key files before the service starts serving
  requests.
- **JWKS fetch hardening** in `JwksKeyResolver`:
  - *Throttling* — at most one remote fetch per `_MIN_REFRESH_INTERVAL` (10 s), serialised
    by a `threading.Lock` so concurrent requests share a single in-flight fetch.
  - *Negative cache* — failed fetches are rate-limited by the same interval, preventing
    retry storms when the auth server is down.
  - *Stale-cache fallback* — if a refresh fails but keys are already cached, the stale
    cache is served and a warning is logged; only raises when the cache is entirely empty.
- **`AUTH_SERVICE_ROLE: Literal["issuer", "consumer"] = "issuer"`** added to
  `CommonSettings`.  Used by `check_config_health` to enforce role-aware rules:
  - `consumer` must not hold `ACCESS_PRIVATE_KEY_FILE` (fatal).
  - `issuer` with an asymmetric algorithm must hold `ACCESS_PRIVATE_KEY_FILE` (fatal).
  - `issuer` with `JWKS_URI` set emits a warning (unusual configuration).

---

## [0.6.0] — 2026-05-14 · Cleanup and foundation for 0.6.x

- **Removed** `UUIDChar` type decorator and all associated tests (not an auth SDK concern).
- Fixed RS256 key injection in the `examples/fastapi_service` docker-compose template.
- Added JWKS consumer example to `examples/`.

---

## [0.5.x] — 2026-05-14 · **Breaking: file-backed PEM loading**

- **`ACCESS_PRIVATE_KEY` / `ACCESS_PUBLIC_KEY` removed as env-var fields.**
  Both are now internal `PrivateAttr`s exposed as read-only properties.
  The only supported input path is `ACCESS_PRIVATE_KEY_FILE` / `ACCESS_PUBLIC_KEY_FILE`
  pointing to volume-mounted PEM files — inline PEM strings in `.env` are no longer accepted.
- `_load_pem_files` validator is now deterministic: always reads the file when a `_FILE` path is
  set; no silent fallback to an inline value.
- `check_config_health()` updated: warns when `ACCESS_PRIVATE_KEY_FILE` is present alongside
  `JWKS_URI` (signing key on a consumer service).
- `ACCESS_PRIVATE_KEY` removed from `secret_fields` (was never a valid secret-strength target).

---

## [0.4.x] — 2026-05-09 · JWKS resolver, validator factory, startup health checks

- **`JwksKeyResolver`** — caches RS256/ES256 public keys from a JWKS endpoint; refreshes once
  on unknown `kid` for zero-downtime rotation.
- **`build_access_validator(settings)`** — one-call factory: reads algorithm, keys, issuer,
  audience from `CommonSettings`; auto-selects `JwksKeyResolver` when `JWKS_URI` is set.
- **`AccessTokenBlacklist`** — read-only Redis JTI check for consumer-side revocation.
- **`check_config_health(settings, logger)`** — call in FastAPI lifespan; fails fast on fatal
  misconfigurations (RS256 without key source, stateful/hybrid without Redis).
- **`TOKEN_ISSUER`, `TOKEN_AUDIENCE`, `ACCESS_KEY_ID`, `JWKS_URI`, `JWKS_CACHE_TTL_SECONDS`**
  added to `CommonSettings`.
- `_validate_key_material` now accepts `JWKS_URI` as a valid key source for consumers.
- `ConfigurationError(RuntimeError)` added to `core.exceptions`.
- Removed `CategoryType`, `PromptBlockType`, `LLMProviderType` from `schemas/base` (not auth SDK
  concerns).

---

## [0.3.x] — 2026-05-07 · Per-token-type algorithms + asymmetric key fields

- **`ACCESS_TOKEN_ALGORITHM`** and **`REFRESH_TOKEN_ALGORITHM`** replace the single
  `TOKEN_ALGORITHM`. Old field kept as a backward-compat fallback via `_sync_token_algorithms`.
- **`TOKEN_MODE: Literal["stateless", "hybrid", "stateful"]`** signals Redis dependency to
  consumers.
- `_validate_key_material` validator enforces correct key material at startup.
- `ACCESS_SECRET_KEY` made optional (only required when `ACCESS_TOKEN_ALGORITHM=HS256`).

---

## [0.2.x] — 2026-05-06 · Refresh token rotation + validation hooks + PostgreSQL

- **`RefreshTokenPolicy`** — one-time-use refresh token rotation with reuse detection.
- **`RefreshTokenStore` protocol** — backend-agnostic interface (Redis, DB, …).
- **`ValidationHooks` protocol** — attach logging, metrics, or tracing to validation events.
- `ES256` added to `TokenAlgorithm`.
- PostgreSQL support: `SELECTED_DB=Postgres` → `postgresql+psycopg2://…`.
- `parse_integrity_error` handles PostgreSQL error formats.
- `TokenValidator` accepts optional `key_resolver` for dynamic `kid`-based key lookup.

---

## [0.1.x] — 2026-05-01 · Initial release

- Core schemas: `TokenUserData`, `TokenAccessData`, `TokenSecret`, `UserModel`, `SessionModel`.
- `CommonSettings` base class (`pydantic-settings`), `find_dotenv`, `ValidationConstants`.
- `TokenValidator` + `TokenPolicy` for stateless and stateful JWT validation.
- `ComSecurityHelper` (legacy): JWT decode, token hashing, PKCE helpers.
- `EventBus`, `EventPublisher`, `EventSubscriber` for Redis pub/sub.
- `BaseController`, `TimestampMixin`, `parse_integrity_error`, `parse_pydantic_errors`.
