# Changelog

All notable changes to `auth-sdk-m8` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [Unreleased]

---

## [1.4.0] — 2026-06-16 · Standard `/meta` + `/ping` service routes

Adds the shared building blocks for the standard m8 service triad so clients can
assert compatibility (`/meta`) and orchestrators can probe liveness (`/ping`)
with an identical shape across the issuer and every consumer. auth-sdk-m8 owns
these because it is the only common dependency of both fa-auth-m8 (issuer) and
fastapi-m8 (consumer framework).

- **`ServiceMeta` / `ServiceContract`** (`schemas/meta.py`) — pure-Pydantic,
  minimal public identity: `service`, `version`, `api_version`, and a nested
  `contract` (`name`/`version`/`range`). Every field is non-empty
  (`min_length=1`). No FastAPI import, so non-web SDK users can build/validate
  meta without the `fastapi` extra.
- **`mount_service_meta(app, meta, *, prefix="")`** (`controllers/meta.py`,
  `[fastapi]` extra) — mounts `{prefix}/meta` (cacheable via `Cache-Control`,
  no dependency I/O) and a prefix-independent `/ping` liveness route
  (`{"status": "ok"}`). `meta` is a **required** argument: a service cannot
  mount the routes without supplying valid values (provide-or-fail at the call
  site; empty fields fail validation).

**Backward compatibility:** purely additive — new modules and a new optional
helper; no existing schema, route, or signature changes.

---

## [1.3.0] — 2026-06-13 · Optional `tenant_id` claim through the auth chain

Backward-compatible feature: a nullable `tenant_id` claim now flows through the shared token
schemas so consuming services can read `current_user.tenant_id`. The base of the M8 auth chain —
fa-auth issues it and fastapi-m8 forwards it untouched.

- **`UserPayloadData`** (`schemas/auth.py`, inherited by `TokenAccessData` and `TokenUserData`)
  gains `tenant_id: Optional[str] = None`. Kept a **string**, not `uuid.UUID`, so the claim stays
  JSON-serialisable through `model_dump()` → `jwt.encode`.
- **`UserModel`** (`schemas/user.py`) gains `tenant_id: Optional[uuid.UUID] = None`; Pydantic
  coerces the token's string claim to a `UUID` on construction.

**Backward compatibility:** the field is optional with a `None` default — old tokens parse
unchanged (absent claim → `None`), and old consumers ignore the extra claim. Only *exposing*
`UserModel.tenant_id` requires upgrading to 1.3.0.

---

## [1.2.1] — 2026-06-12 · Tiered security headers; HSTS/CSP express opt-in

`add_security_headers_middleware` now applies headers in three tiers instead of the previous
all-or-nothing production gate:

- **Always-on** (every environment, when `SECURITY_HEADERS_ENABLED` is `True`):
  `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` — harmless everywhere.
- **Production-gated** (`ENVIRONMENT == "production"` or `STRICT_PRODUCTION_MODE`):
  `Referrer-Policy`, `Permissions-Policy`.
- **Express opt-in only**: `Strict-Transport-Security` (new **`HSTS_ENABLED`**, default `False`)
  and `Content-Security-Policy` (new **`CONTENT_SECURITY_POLICY_ENABLED`**, default `False`).
  These browser-persisted headers are **no longer inferred from the production gate** and are
  **never emitted when `ENVIRONMENT == "local"`** even when opted in — preventing HSTS from
  poisoning the localhost HTTPS cache when a production-configured build is run locally. Otherwise
  they apply independently of `ENVIRONMENT` (a TLS-terminated `staging` stack can opt in).

**Behaviour change:** HSTS and CSP, which were emitted automatically in production in 1.1.0–1.2.0,
are now **off until explicitly enabled**. Set `HSTS_ENABLED=true` and/or
`CONTENT_SECURITY_POLICY_ENABLED=true` to restore them.

- **`CommonSettings`** gains `HSTS_ENABLED` and `CONTENT_SECURITY_POLICY_ENABLED` (both default
  `False`).
- README: added the **Response security headers** section documenting the three tiers, the
  opt-in rationale, and all settings.

---

## [1.2.0] — 2026-06-11 · fa-auth SSE bridge client (SA)

- **`auth_sdk_m8.events.AuthEventStreamClient`** — httpx-based SSE client for the fa-auth
  event-stream bridge (`GET /private/v1/events/stream`). Authenticates via `X-Internal-Token`
  (reuses `PRIVATE_API_SECRET`); auto-reconnects with jittered backoff; `Last-Event-ID` resume;
  verifies every `data` frame via the existing HMAC-SHA256 `deserialize`; fires `on_event` /
  `on_gap` callbacks; never raises into the host application. Install with `events` extra.
- **`SessionRevokedEvent`** added to `schemas/user_events.py` (`event_type="session.revoked"`,
  fields: `user_id`, optional `jti`). `UserDeletedEvent` is unchanged.
- **`derive_stream_url(introspection_url)`** helper — derives the SSE URL from
  `INTROSPECTION_URL` (strips `/jti-status`, appends `/events/stream`).
- **Production placeholder guard** — `CommonSettings._guard_production_placeholder_keys`
  validator rejects any key in `secret_keys` or `EVENT_SIGNING_KEY` that matches a
  well-known published dev/test value when `ENVIRONMENT=="production"` or
  `STRICT_PRODUCTION_MODE=True`.
- **Redis transport deprecated** — `EventBus`, `EventPublisher`, `EventSubscriber` now emit
  `DeprecationWarning` on construction; these classes will be removed in 2.0.0.
  `_signing.py` is exempt (the SSE bridge reuses it). `EVENT_SIGNING_*` config stays
  (reused by the stream).
- README reconciliation: corrected Prometheus metric names, documented new `events/` layout.

---

## [1.1.0] — 2026-06-10 · Shared response security-header layer (N2)

- **`auth_sdk_m8.security.headers`** — response hardening (HSTS, CSP, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) shared by every m8 FastAPI app:
  `add_security_headers_middleware(app, settings)`, `build_security_headers(settings)`, and the
  `SecurityHeadersSettings` protocol. Full set gated on `ENVIRONMENT == "production" or STRICT_PRODUCTION_MODE`;
  requires the `fastapi` extra. *(Superseded by the tiered model in 1.2.1.)*
- **`CommonSettings`** gains six header knobs (`SECURITY_HEADERS_ENABLED`, `HSTS_MAX_AGE`,
  `HSTS_INCLUDE_SUBDOMAINS`, `CONTENT_SECURITY_POLICY`, `REFERRER_POLICY`, `PERMISSIONS_POLICY`), moved
  up from `fastapi_m8.ConsumerServiceSettings`. Defaults unchanged — no migration needed.

---

## [1.0.0] — 2026-06-06 · Secure-by-default signing & binding (F1, F2, F3) · **BREAKING**

The most secure design is now the default; operators opt out via config.

- **F2 — RS256 is the default access-token algorithm.** `TOKEN_ALGORITHM` / `ACCESS_TOKEN_ALGORITHM`
  default to `RS256`; HS256 is now opt-in (`ACCESS_TOKEN_ALGORITHM=HS256` + `ACCESS_SECRET_KEY`).
  `REFRESH_TOKEN_ALGORITHM` stays `HS256` and is never seeded from `TOKEN_ALGORITHM`.
  `TokenValidationConfig.strict()` is algorithm-aware, defaulting to `["RS256"]`.
- **F1 — Strict `iss`/`aud` binding on by default.** `TOKEN_STRICT_VALIDATION` defaults `True`:
  `build_access_validator()` enforces issuer + audience and startup requires `TOKEN_ISSUER` /
  `TOKEN_AUDIENCE` (fail-closed at boot). Opt out with `TOKEN_STRICT_VALIDATION=false`.
- **F3 — Event-bus payloads HMAC-signed by default.** `EVENT_SIGNING_ENABLED` defaults `True` and
  requires `EVENT_SIGNING_KEY` at boot; `EventBus` / `EventPublisher` / `EventSubscriber` accept
  `signing_key` (+ `accept_unsigned`). New `auth_sdk_m8.redis_events._signing` (canonical-JSON
  HMAC-SHA256). Opt out with `EVENT_SIGNING_ENABLED=false`; stage rollout with
  `EVENT_SIGNING_ACCEPT_UNSIGNED=true` (forged signatures still rejected).

See the README "Secure-by-default (1.0.0)" section for the full migration guide.

---

## [0.7.3] — 2026-06-06 · Production docs opt-in (`SERVE_DOCS_IN_PRODUCTION`)

- **`SERVE_DOCS_IN_PRODUCTION`** (default `False`) lifts the production docs gate so `effective_set_*`
  follow the raw `SET_*` flags. `check_config_health` always warns while it is on (never fatal, even
  under strict mode); leaving `SET_DOCS`/`SET_OPEN_API` on in production without it still warns (fatal
  under strict).

---

## [0.7.2] — 2026-06-06 · Docs/OpenAPI gated off in production by default (F5)

- Computed `effective_set_open_api` / `effective_set_docs` / `effective_set_redoc` = raw `SET_*` **and
  not** production (`ENVIRONMENT == "production"` or `STRICT_PRODUCTION_MODE`). Raw `SET_*` defaults
  unchanged (`True`). `check_config_health` typed against structural `Protocol`s.

---

## [0.7.1] — 2026-06-03 · Secure-by-default revocation + lazy Redis import

- **`ACCESS_REVOCATION_FAILURE_MODE` default `fail_open` → `fail_closed`** — outages that prevent
  verifying revocation now return HTTP 503 instead of accepting a possibly-revoked token.
- **Lazy `redis` import** in `security/blacklist.py` (`TYPE_CHECKING` only) so `import
  auth_sdk_m8.security` works without the `redis` package.

---

## [0.7.0] — 2026-05-26 · REDIS_* optional; role-aware requires_redis · **BREAKING**

- **`REDIS_*` fields now optional** (`None` default) — consumers need no Redis creds; setting them
  raises under `extra="forbid"`.
- **`requires_redis` is role-aware** — `True` only for `AUTH_SERVICE_ROLE=issuer` with `TOKEN_MODE` ≠
  `stateless`.
- **`ConsumerAuthMixin`** (`core/consumer.py`) — adds `INTROSPECTION_URL` and `PRIVATE_API_SECRET`,
  both required when `TOKEN_MODE` is `stateful`/`hybrid`.
- **`_enforce_redis_for_issuers`** — issuers in hybrid/stateful mode must set all four `REDIS_*` fields.

---

## [0.6.19] — 2026-06-02 · Security regression tests and cross-service contract

- Algorithm-pinning / malformed-token regression tests (`alg: none`, HS256↔RS256 confusion, missing
  `sub`/`jti`/`exp`, future `nbf`, clock-skew leeway) and a cross-service JWT contract test against the
  `auth_user_service` claim structure.

---

## [0.6.18] — 2026-06-02 · Production boundary enforcement + mypy CI gate

- `check_config_health` warns (fatal under `STRICT_PRODUCTION_MODE`) when `ENVIRONMENT=production` and
  `TOKEN_ISSUER` / `TOKEN_AUDIENCE` are unset.
- mypy type-checking CI job on Python 3.14.

---

## [0.6.17] — 2026-06-01 · Email normalisation helper

- **`utils/email.py` `normalize_email()`** (strip + lowercase), exported from `auth_sdk_m8.utils`.
- **`UserModel.normalise_email`** before-validator canonicalises `email` on construction.

---

## [0.6.14] — 2026-05-23 · Remove STATIC/TEMPLATES paths; unify secret-key regex · **BREAKING**

- Removed `STATIC_BASE_PATH` / `TEMPLATES_BASE_PATH` from `CommonSettings`.
- `SECRET_KEY_REGEX` aligned with `PASSWORD_REGEX` — requires ≥ 1 non-alphanumeric char (min 32).

---

## [0.6.13] — 2026-05-22 · Chrome extension OAuth support

- **`OAUTH_ALLOWED_REDIRECT_SCHEMES`** (default `["chrome-extension://"]`; `http(s)://` hard-rejected),
  **`OAUTH_ALLOWED_REDIRECT_PREFIXES`** (URI-aware allowlist; empty = open public-client model),
  **`CORS_ALLOWED_ORIGIN_SCHEMES`**.
- **`auth_code_exchange_total`** counter (result: `success | expired_or_invalid | pkce_failed |
  redis_unavailable`).
- Removed **`EXTENSION_ID`** — the backend does not bind to a specific extension.

---

## [0.6.12] — 2026-05-20 · Python 3.13/3.14, Redis mTLS, rate-limit health checks

- Python 3.13/3.14 support; CI matrix / security (`bandit`) / lint hardening; Dependabot.
- **Auth degradation policy** — `AUTH_STRICT_MODE`, `REFRESH_VALIDATION_FAILURE_MODE`,
  `SESSION_WRITE_FAILURE_MODE`, `RATE_LIMIT_FAILURE_MODE`, `ACCESS_REVOCATION_FAILURE_MODE`, and
  `effective_failure_mode(control)`.
- New Prometheus metrics: `auth_revocation_failure_total`, `auth_degraded_decision_total`,
  `auth_redis_circuit_breaker_open`, `auth_degradation_mode_active`,
  `auth_session_integrity_denial_total`.
- **`REFRESH_SECRET_KEY_OLD`** zero-downtime refresh-key rotation (expired tokens never retried; warns
  on old-key use); `RefreshTokenPolicy` gains `old_secrets`.
- Configurable rate limits (`LOGIN_/REFRESH_RATE_LIMIT_REQUESTS` and `_WINDOW_MINUTES`) with bounds +
  `_check_rate_limit_config()` startup warning (skipped in stateless).
- Redis TLS/mTLS: `REDIS_SSL`, `REDIS_SSL_CA` (required when SSL on), `REDIS_SSL_CERT` / `REDIS_SSL_KEY`
  (XOR), all validated at startup.
- **Security:** `_sync_token_algorithms` asserts `REFRESH_TOKEN_ALGORITHM` stays `HS256`.

---

## [0.6.6] — 2026-05-17 · Test quality and coverage

- `_vault_source` / `_build_vault_source` accept the optional `_settings` arg pydantic-settings passes;
  restored 100% branch coverage.

---

## [0.6.5] — 2026-05-15 · Vault injection classmethod fix

- `CommonSettings.settings_customise_sources` overridden as a proper `@classmethod` so Vault injection
  activates under pydantic-settings 2.x; `_build_vault_source` helper extracted. The standalone
  `settings_customise_sources` function is retained but deprecated.

---

## [0.6.4] — 2026-05-14 · RS256/ES256 round-trip tests

- Added `tests/test_asymmetric_tokens.py`; test-only release (no API changes).

---

## [0.6.3] — 2026-05-14 · `STRICT_PRODUCTION_MODE`

- **`STRICT_PRODUCTION_MODE`** (default `False`) escalates docs-in-production and issuer-with-`JWKS_URI`
  warnings to fatal, and adds fatal checks for wildcard `ALLOWED_ORIGINS` and `SESSION_COOKIE_SECURE=false`
  outside `ENVIRONMENT=local`.

---

## [0.6.2] — 2026-05-14 · Production deployment enforcement

- `check_config_health`: `localhost`/`127.0.0.1` in `ALLOWED_ORIGINS` (production) → fatal; docs-in-prod
  → warning; `consumer` + `stateless` + `DB_HOST` → warning.

---

## [0.6.1] — 2026-05-14 · Key-strength validation, JWKS hardening, `AUTH_SERVICE_ROLE`

- **`_assert_key_strength` / `_validate_key_strength`** — RS256 ≥ 2048-bit, ES256 P-256 enforced at
  startup for private and public keys.
- **`JwksKeyResolver` hardening** — throttled fetch (one per 10 s, lock-serialised), negative cache, and
  stale-cache fallback.
- **`AUTH_SERVICE_ROLE`** (`issuer` / `consumer`) with role-aware key checks in `check_config_health`.

---

## [0.6.0] — 2026-05-14 · Cleanup and foundation for 0.6.x

- Removed `UUIDChar`; fixed RS256 key injection in the example docker-compose; added a JWKS consumer
  example.

---

## [0.5.x] — 2026-05-14 · **Breaking: file-backed PEM loading**

- `ACCESS_PRIVATE_KEY` / `ACCESS_PUBLIC_KEY` removed as env fields → read-only properties; only
  `ACCESS_PRIVATE_KEY_FILE` / `ACCESS_PUBLIC_KEY_FILE` paths accepted. `check_config_health` warns on a
  private key alongside `JWKS_URI`.

---

## [0.4.x] — 2026-05-09 · JWKS resolver, validator factory, startup health checks

- **`JwksKeyResolver`**, **`build_access_validator(settings)`**, **`AccessTokenBlacklist`**,
  **`check_config_health(settings, logger)`**; added `TOKEN_ISSUER`, `TOKEN_AUDIENCE`, `ACCESS_KEY_ID`,
  `JWKS_URI`, `JWKS_CACHE_TTL_SECONDS`; `ConfigurationError`. Removed non-auth schema types.

---

## [0.3.x] — 2026-05-07 · Per-token-type algorithms + asymmetric key fields

- **`ACCESS_TOKEN_ALGORITHM`** / **`REFRESH_TOKEN_ALGORITHM`** (with `TOKEN_ALGORITHM` fallback);
  **`TOKEN_MODE`**; `_validate_key_material`; `ACCESS_SECRET_KEY` optional (HS256 only).

---

## [0.2.x] — 2026-05-06 · Refresh token rotation + validation hooks + PostgreSQL

- **`RefreshTokenPolicy`**, **`RefreshTokenStore`** / **`ValidationHooks`** protocols, `ES256`,
  PostgreSQL support (`parse_integrity_error`), `TokenValidator` optional `key_resolver`.

---

## [0.1.x] — 2026-05-01 · Initial release

- Core schemas (`TokenUserData`, `TokenAccessData`, `TokenSecret`, `UserModel`, `SessionModel`),
  `CommonSettings`, `find_dotenv`, `ValidationConstants`, `TokenValidator` / `TokenPolicy`,
  `ComSecurityHelper`, `EventBus` / `EventPublisher` / `EventSubscriber`, `BaseController`,
  `TimestampMixin`, `parse_integrity_error`, `parse_pydantic_errors`.
