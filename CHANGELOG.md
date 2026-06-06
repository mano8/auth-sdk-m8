# Changelog

All notable changes to `auth-sdk-m8` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [Unreleased]

---

## [1.0.0] — 2026-06-06 · Secure-by-default signing & binding (F1, F2, F3) · **BREAKING**

The most secure design is now the **default**; operators opt out via config. Three architectural
defaults change at once — they share the same config/validation/test surface and ship as one
coherent secure-by-default release.

### ⚠️ BREAKING CHANGES

- **F2 — RS256 is the default access-token algorithm.** `TOKEN_ALGORITHM` and
  `ACCESS_TOKEN_ALGORITHM` now default to **`RS256`** (asymmetric / JWKS) instead of `HS256`. A
  service that previously relied on the implicit `HS256` default now fails at boot
  (`ACCESS_TOKEN_ALGORITHM=RS256 requires a public key source`) until it either provides RS256 key
  material or **explicitly opts back into HS256**. Refresh tokens remain `HS256` always (internal,
  symmetric) — `TOKEN_ALGORITHM` is no longer propagated to `REFRESH_TOKEN_ALGORITHM`.
- **F1 — Strict `iss`/`aud` binding is on by default.** New `TOKEN_STRICT_VALIDATION` defaults to
  **`True`**: `build_access_validator()` enforces both issuer and audience, and startup **requires
  `TOKEN_ISSUER` and `TOKEN_AUDIENCE`** to be set (fail-closed at boot). Tokens with a wrong/missing
  `iss` or `aud` are rejected. A service with no issuer/audience configured now fails to start until
  it sets them or opts out.
- **F3 — Event-bus payloads are HMAC-signed by default.** New `EVENT_SIGNING_ENABLED` defaults to
  **`True`** and **requires `EVENT_SIGNING_KEY`** at boot. `EventBus` / `EventPublisher` /
  `EventSubscriber` accept a `signing_key`; consumers configured with a key **reject unsigned or
  forged events** (handler is never invoked) unless transitional acceptance is enabled.

### Added

- **`TOKEN_STRICT_VALIDATION: bool = True`** — master switch for strict `iss`/`aud` binding (F1).
- **`TokenValidationConfig.strict(..., allowed_algorithms=...)`** — the strict profile is now
  algorithm-aware and defaults to `["RS256"]` (was pinned to `["HS256"]`).
- **`EVENT_SIGNING_ENABLED: bool = True`**, **`EVENT_SIGNING_KEY: SecretStr | None`**,
  **`EVENT_SIGNING_ACCEPT_UNSIGNED: bool = False`** — event-bus signing config (F3), with boot-time
  key-strength validation consistent with `_enforce_redis_for_issuers`.
- **`auth_sdk_m8.redis_events._signing`** — canonical-JSON HMAC-SHA256 sign/verify helper.
  `EventBus` / `EventPublisher` / `EventSubscriber` gain `signing_key` (and `accept_unsigned` on the
  consume side) keyword arguments.

### Security

- Wrong/missing `aud`/`iss` ⇒ rejected; strict-without-issuer/audience ⇒ startup raises (F1).
- RS256 sign → JWKS/public-key verify round-trip is the default; alg-confusion (e.g. an HS256 token
  presented to an RS256 validator) is still rejected; public-key-only consumers cannot sign (F2).
- Tampered / wrong-key / unsigned event payloads are dropped before deserialization and never reach
  the handler; signature verification uses `hmac.compare_digest` over a canonical serialization (F3).

### Migration / opt-out

Every new default has a documented opt-out so existing deployments can stage their migration:

| Want the previous behaviour | Set |
| --- | --- |
| Keep `HS256` access tokens | `ACCESS_TOKEN_ALGORITHM=HS256` (+ `ACCESS_SECRET_KEY`) |
| No `iss`/`aud` binding (single-service/dev) | `TOKEN_STRICT_VALIDATION=false` |
| Disable event signing | `EVENT_SIGNING_ENABLED=false` |
| Mixed signed/unsigned fleet during rollout | `EVENT_SIGNING_ACCEPT_UNSIGNED=true` (still rejects forged sigs) |

To adopt the secure posture: generate an RS256 keypair and mount it via
`ACCESS_PRIVATE_KEY_FILE` / `ACCESS_PUBLIC_KEY_FILE` (issuer) or set `JWKS_URI` +
`AUTH_SERVICE_ROLE=consumer` (consumer); set `TOKEN_ISSUER` / `TOKEN_AUDIENCE` on every service; and
distribute a shared `EVENT_SIGNING_KEY` to all event-bus publishers and subscribers. See the README
"Secure-by-default (1.0.0)" section for the full guide.

### Tests

- `tests/test_secure_defaults.py` — RS256 default, HS256 opt-out, strict accept/reject + boot
  requirement, strict opt-out, and event-signing key boot enforcement (required / weak / disabled).
- `tests/test_redis_events_signing.py` — signing helper branches and signed/tampered/unsigned/
  transitional publish-and-consume paths for `EventBus`, `EventPublisher`, `EventSubscriber`.
- Existing suite re-pinned to the documented HS256 + permissive opt-out via the shared fixture.

---

## [0.7.3] — 2026-06-06 · Production docs opt-in (`SERVE_DOCS_IN_PRODUCTION`)

### Added

- **`SERVE_DOCS_IN_PRODUCTION` setting (default `False`).** Turns the production docs gate from a
  hard block into a genuine secure-by-default **opt-out**: deployments that *intentionally* publish
  docs (e.g. public / open-source APIs) set this `True` to lift the gate, after which
  `effective_set_open_api` / `effective_set_docs` / `effective_set_redoc` follow the raw `SET_*`
  flags even in production. Rationale is **not** security-through-obscurity (the repo is
  open-source); gating avoids serving a live interactive Swagger/ReDoc console wired to the
  production server, leaking deployment-specific runtime info, and presenting a scanner/fingerprint
  target.

### Security

- **The opt-in is never silent.** `check_config_health` **always logs a warning** while
  `SERVE_DOCS_IN_PRODUCTION=true` (interactive docs are exposed in production), but it is **never
  escalated to fatal** — even under `STRICT_PRODUCTION_MODE` — because it is an explicit operator
  decision. When the opt-in is *not* set, leaving raw `SET_DOCS`/`SET_OPEN_API` `true` in production
  still warns (fatal under strict), nudging operators to disable them.

### Tests

- `effective_*` opt-in coverage: serves docs in production, respects raw flags per-endpoint,
  overrides strict mode, no-op when all docs flags are off; `SERVE_DOCS_IN_PRODUCTION` defaults
  `False`.
- `check_config_health` opt-in coverage: warns-not-fatal under strict, warns in normal mode, and
  emits no warning when the opt-in serves nothing.

---

## [0.7.2] — 2026-06-06 · Docs/OpenAPI gated off in production by default (F5)

### Security

- **Docs/OpenAPI are now gated off in production by default** (`core/config.py`). Three new
  computed properties — `effective_set_open_api`, `effective_set_docs`, `effective_set_redoc` —
  give the *effective* flag as the configured `SET_*` value **and not** production, where
  production is `ENVIRONMENT == "production"` **or** `STRICT_PRODUCTION_MODE == true`. Consumers
  mount their OpenAPI/Swagger/ReDoc endpoints from these single-source properties so the schema and
  interactive docs are never exposed in production, regardless of the raw `SET_*` flags.
  - The raw `SET_OPEN_API` / `SET_DOCS` / `SET_REDOC` defaults are **unchanged** (`True`) so local
    and CI developer experience is preserved.
  - **Opt back on:** the effective flags equal the raw flags in any non-production environment
    (`local`, `development`, `staging`); to expose docs, run outside production by setting
    `ENVIRONMENT` to a non-production value and leaving `STRICT_PRODUCTION_MODE` unset/false.

### Tests

- Added coverage for the three effective-docs properties: production-by-`ENVIRONMENT`,
  `STRICT_PRODUCTION_MODE=true`, dev with `SET_*=true`/`false`, staging (non-production), and the
  raw-flags-unchanged invariant.

### Internal

- Typed `check_config_health` against structural `Protocol`s for its settings and logger arguments,
  resolving pre-existing `mypy` findings across the config-health call sites and test suite.

---

## [0.7.1] — 2026-06-03 · Secure-by-default revocation + lazy Redis import

### Security

- **`ACCESS_REVOCATION_FAILURE_MODE` default changed `fail_open` → `fail_closed`** (`core/config.py`).
  Any outage that prevents verifying token revocation now returns HTTP 503 rather than accepting
  a potentially-revoked token. This is a security-motivated default change flagged prominently here
  as 0.x SemVer permits it; the behaviour remains 100% env-selectable:
  - **Availability-first stacks:** set `ACCESS_REVOCATION_FAILURE_MODE=fail_open`
  - **High-security stacks:** set `AUTH_STRICT_MODE=true` (forces all controls closed)
  - Mixed postures are supported — each control is its own env var, set independently.

### Fixed

- **Lazy `redis` import in `auth_sdk_m8/security/blacklist.py`**: `Redis` was imported at module
  level but is only used as a type annotation in `__init__(self, client: Redis)`. Changed to a
  `TYPE_CHECKING`-only import so `import auth_sdk_m8.security` works under
  `pip install auth-sdk-m8[security]` without the `redis` package installed. Consumers and
  `fastapi-m8` can now drop the `[redis]` extra from their install.

### Tests

- Updated `test_effective_failure_mode_defaults` to assert `access_revocation == "fail_closed"`.

---

## [0.6.19] — 2026-06-02 · Security regression tests and cross-service contract

### Tests

- **Algorithm pinning and malformed-token regression tests** (`test_security_token_validator.py`):
  `alg: none` attack, algorithm confusion (HS256 vs RS256-only allowlist), missing `sub`,
  `jti`, and `exp` individually, future `nbf`, clock-skew leeway boundary (accepts within
  window, rejects beyond it).

- **Cross-service JWT contract test** (`test_jwt_contract.py`): issues a token with the
  exact claim structure from `auth_user_service` and validates it with `build_access_validator`.
  Asserts all claims round-trip correctly into `TokenUserData` and construct a valid
  `UserModel`. Any SDK change that silently renames a claim or changes a type will fail
  this test immediately.

---

## [0.6.18] — 2026-06-02 · Production boundary enforcement + mypy CI gate

### Added

- **Production boundary warning for `TOKEN_ISSUER` / `TOKEN_AUDIENCE`** — `check_config_health()`
  now warns (or raises `ConfigurationError` under `STRICT_PRODUCTION_MODE=true`) when
  `ENVIRONMENT=production` and either claim is unset. Without these claims a token signed with
  the same key in dev is valid in production, and a token for one service can be replayed
  against another. Two new `_check_token_boundary_config` tests cover the warning and fatal
  code paths. The `_strict_base()` test fixture updated to include both claims in the
  "properly hardened production" baseline.

- **mypy type-checking in CI** — new `typecheck` job in `.github/workflows/CI.yaml` runs
  `mypy auth_sdk_m8 --ignore-missing-imports` on Python 3.14. Mirrors the gate already
  in `fa-auth-m8`.

---

## [0.6.17] — 2026-06-01 · Email normalisation helper

### Added

- **`auth_sdk_m8/utils/email.py`** — new `normalize_email(email: str) -> str` helper that
  strips whitespace and lowercases the address. Exported from `auth_sdk_m8.utils`.

- **`UserModel.normalise_email` validator** (`schemas/user.py`): `@field_validator("email",
  mode="before")` calls `normalize_email()` so every `UserModel` instance stores a canonical
  email regardless of input casing or surrounding whitespace. Consumer services (`fastapi_service`)
  inherit this automatically via the SDK.

### Tests

- `tests/test_utils_email.py` — 6 tests covering lowercase, strip, combined, already-normalised,
  plus-tags, and dot-separated local parts.
- `tests/test_schemas_user.py` — 2 new tests: `UserModel` normalises mixed-case email and
  strips whitespace on construction.

---

## [0.7.0] — 2026-05-26 · REDIS_* optional; role-aware requires_redis; issuer enforcement

### Breaking changes

- **`REDIS_*` fields are now `Optional` with `None` defaults.**  Consumer
  services (`AUTH_SERVICE_ROLE=consumer`) no longer need Redis credentials in
  their env files.  Any consumer env file that sets REDIS fields will raise a
  Pydantic validation error at startup (`extra="forbid"`).

- **`requires_redis` is now role-aware.**  Returns `True` only for
  `AUTH_SERVICE_ROLE=issuer` with `TOKEN_MODE` ≠ `stateless`.  Always `False`
  for consumer and observer roles.  Code that evaluated `requires_redis` to
  decide whether to create a Redis pool must be updated (consumer services
  should use HTTP introspection instead — see `fa-auth-m8` v0.11.0).

### Added

- **`ConsumerAuthMixin`** (`core/consumer.py`, exported from `auth_sdk_m8.core`): new Pydantic
  mixin for consumer microservice settings. Adds `INTROSPECTION_URL: AnyHttpUrl | None` and
  `PRIVATE_API_SECRET: SecretStr | None` fields. A `_require_introspection_for_stateful_consumer`
  validator enforces that both fields are set when `TOKEN_MODE` is `stateful` or `hybrid`.
  `fastapi-m8`'s `ConsumerServiceSettings` already inherits this mixin; manual use is only
  needed when building a consumer without fastapi-m8.

- **`_enforce_redis_for_issuers` model validator** (`core/config.py`): ensures
  that issuers in `hybrid` or `stateful` mode provide all four `REDIS_*` fields
  (`REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD`).  Uses
  `.get_secret_value()` to avoid the `SecretStr("")` truthy-object trap.

### Tests

- **11 new tests** in `tests/test_core_config.py` covering the `requires_redis`
  role matrix (6 scenarios: 3 roles × 2 relevant token modes) and
  `_enforce_redis_for_issuers` validator (missing fields, empty password,
  valid pass-through, non-issuer short-circuit).
- **7 tests** in `tests/test_consumer_mixin.py` covering `ConsumerAuthMixin` field defaults,
  stateless/issuer no-introspection pass-through, stateful with both fields, and missing-field
  validation errors.

---

## [0.6.14] — 2026-05-23 · Remove STATIC/TEMPLATES paths; unify secret-key regex

### Breaking changes

- **`STATIC_BASE_PATH` and `TEMPLATES_BASE_PATH` removed from `CommonSettings`.**
  Services that set or read these fields will raise a Pydantic validation error at
  startup. Remove both keys from your env files and any code that references them.

### Changed

- **`SECRET_KEY_REGEX`** unified with `PASSWORD_REGEX` character-class rules: now
  requires at least one character outside `[a-zA-Z0-9]` (previously restricted to
  `[-_]`). Minimum length remains 32 characters. Existing secret keys that already
  contain a hyphen or underscore continue to pass without change.

### Tests

- Removed `"STATIC_BASE_PATH": "/static/path"` from `VALID_SETTINGS_KWARGS` fixture.

---

## [0.6.13] — 2026-05-22 · Chrome extension OAuth support

### Added (0.6.13)

- **`OAUTH_ALLOWED_REDIRECT_SCHEMES`** (`core/config.py`): list of URI schemes
  accepted as `redirect_target` at `/google-api/login-url/`.  Defaults to
  `["chrome-extension://"]`.  `http://` and `https://` are hard-rejected by
  the route handler regardless of this setting.

- **`OAUTH_ALLOWED_REDIRECT_PREFIXES`** (`core/config.py`): optional list of
  full URI prefixes that restrict `redirect_target` to specific extension IDs
  (empty by default — open public-client model).  URI-aware matching prevents
  crafted-netloc bypasses.

- **`CORS_ALLOWED_ORIGIN_SCHEMES`** (`core/config.py`): list of URI schemes
  allowed as `Origin` for CORS purposes.  Used by `auth_user_service` to build
  a `CORSMiddleware`-compatible `allow_origin_regex` that accepts
  `chrome-extension://{32-char-id}` origins.  Defaults to empty (no extension
  CORS).

- **`auth_code_exchange_total` counter** (`observability/metrics.py`): new
  Prometheus counter in the `auth` group tracking OAuth native-app code
  exchange results.  Labels: `result` (`success | expired_or_invalid |
  pkce_failed | redis_unavailable`).

### Tests (0.6.13)

- **100% branch coverage** — 388 tests, 1245 statements, 314 branches, 0
  missing.

- **`tests/test_core_config.py`** — 9 new tests covering previously-missed
  branches in `core/config.py` and `core/config_health.py`:
  `_assert_key_strength` HS256 no-op and valid ES256 P-256 paths; string
  env-value parsing for the three new list validators
  (`parse_redirect_schemes`, `parse_redirect_prefixes`,
  `parse_cors_origin_schemes`); `_sync_token_algorithms` when both
  `ACCESS_TOKEN_ALGORITHM` and `REFRESH_TOKEN_ALGORITHM` are pre-set to
  non-HS256; `_validate_key_strength` JWKS-consumer no-local-key path;
  `settings_customise_sources` vault mode without `VAULT_ADDR`; consumer +
  stateless with no `DB_HOST` set.

### Removed (0.6.13)

- **`EXTENSION_ID`** (`core/config.py`): deleted.  `fa-auth-m8` is a generic
  auth provider and must work with any client without per-client backend
  configuration.  Extension identity is not verified by the backend; the
  `redirect_target` is a delivery channel, not an identity binding mechanism.
  Operators who need to restrict to known extension IDs can configure
  `OAUTH_ALLOWED_REDIRECT_PREFIXES`.

---

## [0.6.12] — 2026-05-20 · Python 3.13/3.14 compatibility, Redis mTLS, rate-limit health checks

### Added

- **Python 3.13 and 3.14 support**: verified locally (379 tests, 100% coverage on Python 3.14.4);
  added classifiers; `ruff` `target-version` updated to `py314`.

- **CI hardening**:
  - Extended test matrix from `["3.11", "3.12"]` to `["3.11", "3.12", "3.13", "3.14"]`
  - Added `security` job running `bandit` at grade-A threshold with artifact upload
  - Added `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true` — eliminates Node 20 warnings ahead of the June 2026 forced migration
  - Lint and security jobs now run on Python 3.14 to match the widest tested version
  - Coverage uploads to Codecov/Codacy guarded with `github.actor != 'dependabot[bot]'`
    to prevent false failures (Dependabot PRs cannot access repository secrets)

- **Dependabot**: added `.github/dependabot.yml` with monthly updates for `github-actions` and `pip`

- **Auth degradation policy** (`core/config.py`): five new `CommonSettings` fields control how each Redis-dependent security control behaves when Redis is unavailable:
  - `AUTH_STRICT_MODE: bool = False` — overrides all per-control modes to `fail_closed`
  - `REFRESH_VALIDATION_FAILURE_MODE: "fail_open" | "fail_closed"` (default `fail_closed`)
  - `SESSION_WRITE_FAILURE_MODE: "fail_open" | "fail_closed"` (default `fail_closed`)
  - `RATE_LIMIT_FAILURE_MODE: "fail_open" | "fail_closed"` (default `fail_open`)
  - `ACCESS_REVOCATION_FAILURE_MODE: "fail_open" | "fail_closed"` (default `fail_open`)
  New `effective_failure_mode(control)` method resolves the active mode for a given control, with `AUTH_STRICT_MODE=true` overriding all controls to `fail_closed`.

- **`auth_revocation_failure_total` counter** (`observability/metrics.py`): new Prometheus counter in the `auth` group tracking token revocation failures by operation (`access_blacklist | refresh_allowlist | db_session`).

- **`auth_degraded_decision_total` counter** (`observability/metrics.py`): new Prometheus counter in the `auth` group emitted on every degraded-mode decision — i.e. each time a Redis-dependent security control is consulted while Redis is unavailable. Labels: `control` (`rate_limit | refresh_validation | session_write | access_revocation`), `mode` (`fail_open | fail_closed`), `reason` (`redis_unavailable | revocation_failed`). Enables alerting on degraded-mode frequency and mode distribution without waiting for HTTP 503 responses.

- **`auth_redis_circuit_breaker_open` gauge** (`observability/metrics.py`): new Prometheus gauge in the `auth` group indicating Redis circuit breaker state — `1` when open (Redis unavailable, requests short-circuited), `0` when closed (Redis healthy). Updated on every successful or failed ping attempt in `get_redis_client()`. Enable `alert when auth_redis_circuit_breaker_open == 1`.

- **`auth_degradation_mode_active` gauge** (`observability/metrics.py`): new Prometheus gauge in the `auth` group exposing the configured degradation mode per security control. Labels: `control` (`rate_limit | refresh_validation | session_write | access_revocation`), `mode` (`fail_open | fail_closed`). Value is always `1` for the active mode. Set once at service startup from settings. Allows querying configured posture: e.g. `count(auth_degradation_mode_active{mode="fail_closed"} == 1)` to see how many controls are hardened.

- **`auth_session_integrity_denial_total` counter** (`observability/metrics.py`): new Prometheus counter in the `auth` group tracking forced-churn events — token reuse attacks where the Lua rotation script detects a consumed JTI, triggering full session chain invalidation. Label: `trigger` (`reuse_detected`). Enables alerting on any reuse-attack detection with zero false-positive risk.

- **`REFRESH_SECRET_KEY_OLD: Optional[SecretStr] = None`** (`core/config.py`): new `CommonSettings` field enabling zero-downtime refresh key rotation. When set, `SecurityHelper.decode_refresh_token` and `RefreshTokenPolicy` retry validation against the old key after the current key fails with a signature error. Expired tokens are never retried. A `WARNING` is logged on every old-key acceptance so operators can track when legacy tokens have fully expired and the old key can be removed. `RefreshTokenPolicy` accepts `old_secrets` as a constructor parameter to wire the same fallback into the stateful rotation path.

- **Configurable rate limit settings** (`core/config.py`): four new `CommonSettings` fields with Pydantic bounds validation (`ge=1`) expose the previously hardcoded `LoginRateLimiter` and `RefreshRateLimiter` limits as operator-controlled configuration:
  - `LOGIN_RATE_LIMIT_REQUESTS: int = Field(5, ge=1, le=1000)`
  - `LOGIN_RATE_LIMIT_WINDOW_MINUTES: int = Field(15, ge=1, le=1440)`
  - `REFRESH_RATE_LIMIT_REQUESTS: int = Field(10, ge=1, le=1000)`
  - `REFRESH_RATE_LIMIT_WINDOW_MINUTES: int = Field(5, ge=1, le=1440)`

- **`_check_rate_limit_config()` startup health check** (`core/config_health.py`): warns at startup when the configured effective rate (requests ÷ window\_minutes) exceeds per-control thresholds — login > 5 req/min, refresh > 20 req/min — indicating a highly permissive configuration that may weaken abuse protection. Refresh check is skipped in stateless mode (no refresh tokens). Integrated into `check_config_health()` via the `.extend()` assembly pattern.

- **`REDIS_SSL: bool = False`** (`core/config.py`): new `CommonSettings` field controlling whether the Redis `ConnectionPool` uses TLS. Defaults to `False` (plain TCP) for backward compatibility with local/dev stacks. Set `REDIS_SSL=true` in production when Redis is reached over a network boundary. Exposed in all `auth.env.example` files as a commented default.

- **`REDIS_SSL_CA`, `REDIS_SSL_CERT`, `REDIS_SSL_KEY`** (`core/config.py`): three new optional `CommonSettings` fields for Redis TLS/mTLS configuration:
  - `REDIS_SSL_CA: str | None` — path to the CA certificate used to verify the Redis server cert. **Required when `REDIS_SSL=true`**; validated at startup via `_validate_redis_ssl`.
  - `REDIS_SSL_CERT: str | None` — path to the client certificate for mTLS. Must be set together with `REDIS_SSL_KEY`.
  - `REDIS_SSL_KEY: str | None` — path to the client private key for mTLS. Must be set together with `REDIS_SSL_CERT`.
  All three fields are validated at startup: file existence is checked when the field is set; `REDIS_SSL_CA` is required when `REDIS_SSL=true`; `REDIS_SSL_CERT` and `REDIS_SSL_KEY` must both be set or both unset (XOR constraint).

### Changed

- **`token_refresh_total` label values** (`observability/metrics.py`): description now explicitly documents the `rate_limited` result label alongside `success` and `failure`.

### Security

- **`_sync_token_algorithms` hardened** (`core/config.py`): added `ValueError` assertion after algorithm propagation — `REFRESH_TOKEN_ALGORITHM` must always remain `HS256`. Refresh tokens are internal-only and must use symmetric signing; previously `TOKEN_ALGORITHM=RS256` was silently propagated to `REFRESH_TOKEN_ALGORITHM` without validating the existence of refresh key material, creating a silent startup trap that produced a runtime error only when a refresh was first attempted.

### Fixed

- **Self-referential `dev` extra removed** (`pyproject.toml`): `auth-sdk-m8[all]` in the `dev`
  extras caused pip to resolve `CommonSettings` from PyPI (0.6.11) instead of the local editable
  install on fresh CI environments, making `REDIS_SSL_CA/CERT/KEY` appear as unknown fields.
  The CI now installs with `pip install -e ".[all,dev]"`.

### Tests

- **Redis SSL validation** (`tests/test_core_config.py`): 10 new tests covering `REDIS_SSL_CA`
  required when SSL enabled, file-not-found errors for CA/cert/key, XOR rule (cert and key must
  both be set or both unset), TLS-only mode, mTLS mode, and default-None when SSL disabled.
- **Rate-limit health checks** (`tests/test_core_config.py`): 5 new tests covering default values
  (no warning), permissive login/refresh rates (warns), stateless mode (skips refresh check),
  and exact-threshold boundary (`>` not `>=`).

---

## [0.6.6] — 2026-05-17 · Test quality and coverage

- **Fix `_vault_source` callable signature**: both the inline closure in `settings_customise_sources` and the `_build_vault_source` helper now accept an optional `_settings` argument, matching how pydantic-settings calls custom sources (passing the settings instance). This resolves a `TypeError` in tests and aligns the signature with the pydantic-settings contract.
- **100% test coverage**: added targeted tests for previously uncovered branches:
  - `_build_vault_source` return value invocation
  - `CommonSettings.settings_customise_sources` without Vault, with Vault env token, and with Vault file token
  - `JwksKeyResolver.__init__` rejection of non-http/https URI schemes
  - `TokenValidator._resolve_secrets` defensive `RuntimeError` when both `_key_resolver` and `_default_secrets` are `None`

---

## [Unreleased] — Vault injection classmethod fix

- **`CommonSettings.settings_customise_sources` classmethod**: pydantic-settings 2.x calls `settings_customise_sources` as a classmethod with 5 args `(cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings)` and calls each source with no arguments. The previous standalone function passed via `model_config` was silently ignored by pydantic-settings 2.x, so Vault injection never activated. Fixed by overriding `settings_customise_sources` as a proper `@classmethod` on `CommonSettings`; the Vault source callable now takes no arguments.
- **`_build_vault_source` helper**: extracted to build the Vault callable source cleanly.
- The deprecated standalone `settings_customise_sources` function is retained for backward compatibility but marked deprecated in its docstring.

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
