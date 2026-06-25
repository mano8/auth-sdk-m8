# Changelog

All notable changes to `auth-sdk-m8` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [2.1.0] - 2026-06-25 · Per-consumer / service-token auth for the SSE event stream (9.1)

### Added

- **`AuthEventStreamClient` accepts an `auth_provider`** so a consumer in
  per-consumer mode can authenticate the SSE event stream, closing the Phase 9.1
  event-stream gap. The client previously hard-coded a single `X-Internal-Token`
  header, so a consumer whose issuer runs a `PRIVATE_API_CONSUMERS` registry
  could authenticate only the introspection call, not the stream. The new
  parameter is mutually exclusive with `private_api_secret` (exactly one is
  required); legacy callers passing `private_api_secret` are unchanged.
  - The provider's `headers()` is called once **per connection attempt**, so a
    dynamic provider refreshes its credential on every reconnect; a `401` on
    connect `invalidate()`s the provider so the next reconnect mints a fresh
    credential. The client takes ownership of the provider and closes it on
    `stop()`.
- **`auth_sdk_m8.security.internal_auth`** — a framework-agnostic emission-side
  contract for private-call auth headers (the issuer-side verification
  primitives already live in `consumer_auth`):
  - `InternalAuthProvider` — a `runtime_checkable` `Protocol`
    (`headers()` / `invalidate()` / `close()`) any transport can drive (the SSE
    client here, a consumer's revocation HTTP client). `fastapi-m8`'s dynamic
    service-token provider already satisfies it structurally.
  - `StaticInternalAuth` + `static_internal_auth(secret, client_id=None)` — the
    static **legacy** (`X-Internal-Token` only) and **bootstrap**
    (`X-Internal-Client` + `X-Internal-Token`) header shapes.
- Exported `InternalAuthProvider`, `StaticInternalAuth`, `static_internal_auth`,
  and `INTERNAL_TOKEN_HEADER` from `auth_sdk_m8.security`.

### Changed

- `INTERNAL_TOKEN_HEADER` is now defined in the framework-agnostic
  `security.consumer_auth` (next to `INTERNAL_CLIENT_HEADER`) and re-exported
  from `security.guards`; the importable name `security.guards.INTERNAL_TOKEN_HEADER`
  is unchanged, so existing consumers (e.g. `fastapi-m8`) are unaffected.

> **Backward compatible / minor.** All additions are opt-in and the legacy
> `private_api_secret` path is preserved. Per the post-1.0 semver note, the
> published `2.0.x` line is not yet consumed by any live stack, so 9.1 lands as a
> `2.x` **minor**. The matching `fastapi-m8` follow-on
> (route `build_event_stream_client` through `build_internal_auth`) is SDK-first
> and ships after this is published.

## [2.0.1] - 2026-06-23

### Changed

- Raise the `[config]` (and `[all]`) `pydantic-settings` floor from `>=2.14.1`
  to `>=2.14.2`. 2.14.2 is a patch release whose only functional change hardens
  the nested-secrets source against symlink escape/loop traversal; `CommonSettings`
  does not use that source, so the bump is non-breaking and pulls in the security
  fix for any consumer that does. Reproducible-build constraints regenerated.

## [2.0.0] - 2026-06-23

### Removed — deprecated APIs dropped for 2.0.0 · **BREAKING**

The 2.0.0 major removes every previously-deprecated surface:

- **Redis Pub/Sub event bus** — the `auth_sdk_m8.redis_events` package
  (`EventBus`, `EventPublisher`, `EventSubscriber`) is gone. Deprecated in
  1.2.0; superseded by the fa-auth SSE bridge
  (`auth_sdk_m8.events.AuthEventStreamClient`). The HMAC-SHA256 signing helpers
  (`serialize`/`deserialize`, formerly `redis_events/_signing.py`) were **not**
  deprecated and are retained — relocated to `auth_sdk_m8.events._signing`
  (the SSE bridge reuses them; `EVENT_SIGNING_KEY` is unchanged). The `[redis]`
  extra stays — it now installs the client used by the JTI blacklist
  (`AccessTokenBlacklist`).
- **`ComSecurityHelper.decode_access_token`** — removed. Use `TokenValidator`
  (via `build_access_validator`). The internal
  `LEGACY_ACCESS_TOKEN_VALIDATION_CONFIG` constant is removed with it.
- **`TOKEN_ALGORITHM` settings knob** — removed. Set `ACCESS_TOKEN_ALGORITHM`
  directly (refresh tokens remain HS256-only, still enforced). The seeding
  validator is gone.
- **Module-level `settings_customise_sources()`** in `auth_sdk_m8.core.config`
  — removed. Vault/`_FILE` source ordering is handled automatically by the
  `CommonSettings.settings_customise_sources` classmethod; subclasses must drop
  the `settings_customise_sources=...` entry from their `model_config`.

**Migration:** raise the floor to `auth-sdk-m8>=2.0.0,<3.0.0`. Replace any
`decode_access_token` call with a `TokenValidator`, rename `TOKEN_ALGORITHM` →
`ACCESS_TOKEN_ALGORITHM`, drop the module-level `settings_customise_sources`
import/`model_config` override, and switch any remaining Redis-bus code to the
SSE bridge.

### Added — per-consumer credential verification primitives (Phase 9.1, near-term)

New `auth_sdk_m8.security.consumer_auth` module: the framework-agnostic building
blocks for replacing the single shared `PRIVATE_API_SECRET` (one secret every
consumer presents, rarely rotated, fleet-wide blast radius) with a **map of
consumer ids → hashed, scoped per-consumer secrets**. Callers present
`X-Internal-Client` + `X-Internal-Token`; the issuer authorizes a private
operation only when the matched credential carries the required scope.

- **`ConsumerScope`** (`StrEnum`) — well-known scopes (`introspection`,
  `event-stream`, `user-create`); custom scope strings are also accepted.
- **`ConsumerCredential`** — a client id, a salted SHA-256 digest
  (`sha256$<salt_hex>$<digest_hex>`, never plaintext), and a granted-scope set.
  `create()` hashes a plaintext secret; `from_encoded()` is the load path;
  `verify_secret()` is a constant-time check; scopes are **deny-by-default**.
- **`ConsumerCredentialRegistry`** — id → credential lookup (`from_secrets` /
  `from_encoded`). `verify()` reports unknown-client and wrong-secret
  **identically** and runs a constant-time digest comparison in both branches
  (no client-enumeration oracle); `authorize()` adds scope enforcement, raising
  `ConsumerAuthenticationError` (401-shaped) or `ConsumerScopeError`
  (403-shaped).
- **`make_consumer_authorizer`** (in `security.guards`) — a FastAPI dependency
  that reads the two headers, authorizes against a registry, and injects the
  matched `ConsumerCredential` into the route (`401` on bad/unknown credential,
  `403` on scope violation). The per-consumer successor to
  `make_internal_token_authorizer` / `make_scrape_credential_guard`.

This is the SDK's verification half of 9.1; issuing/persisting the credential
map and the medium-term bootstrap-secret → short-TTL scoped service-token
exchange remain the issuer's (`fa-auth-m8`) concern. `/metrics` keeps its static
scrape credential (no token model). Additive — no existing behaviour changes.

### Added — service-identity and mTLS guidance (Phase 9.2)

`SECURITY.md` gains a new **"Service identity and mTLS"** section that answers
the "internal HTTPS?" question once and for all:

- **Single-host baseline** — plain `http://` on Docker container-DNS is
  acceptable; `check_config_health` warns in production (item 1.3) but lets
  operators opt in via `ALLOW_INTERNAL_HTTP=true`. App-layer guards are
  the primary control regardless.
- **Multi-host: when mTLS applies** — when services span physical or virtual
  hosts, mTLS is the correct network-layer control. Reference Traefik
  file-provider configuration covers: CA/cert generation, the internal
  entrypoint with `RequireAndVerifyClientCert` (TLS 1.3 floor), router and
  service wiring in `dynamic_conf.yml`, and container cert mounts.
- **Migration path** — run token + mTLS together during rollout
  (`X-Internal-Token` / `X-Internal-Client` + mTLS at proxy). The app-layer
  guard remains the primary control; mTLS is defense-in-depth. The shared
  `PRIVATE_API_SECRET` can be retired once mTLS is proven and the per-consumer
  credential model (item 9.1 issuer side) is deployed.
- **Service-mesh alternative** — for Kubernetes/Istio/Linkerd/Consul Connect,
  delegate mTLS to the sidecar/CNI; app-layer guards are unchanged.

No code change — this is a deployer-guidance document.

### Changed — single-mount `{prefix}/ping` · **BREAKING** (2.0.0)

`mount_service_meta` now registers **exactly one** `/ping` route, at the
effective prefix:

- **Prefix set** (e.g. `API_PREFIX=/media`): `/ping` is served **only** at
  `{prefix}/ping` (`/media/ping`) and is **published in the OpenAPI schema**. The
  root `/ping` is **no longer mounted**.
- **No prefix**: `/ping` stays at the root, as before.

Previously the root `/ping` was always mounted *plus* a hidden
(`include_in_schema=False`) `{prefix}/ping` copy. That produced an
invisible-in-`/docs` liveness route and a duplicate operation. The new behaviour
makes the published path match the proxy-routable path and removes the
duplicate. The internal `_build_ping_router` `in_schema` parameter is removed.

**Migration:** services fronted by a prefix-routing proxy (Traefik
`PathPrefix({prefix})`) are unaffected — they already probe `{prefix}/ping`. Any
liveness/healthcheck that hits the **root** `/ping` of a *prefixed* service must
switch to `{prefix}/ping`. Services with no `API_PREFIX` are unaffected.

This breaking change is why the next release is **2.0.0** (the deferred
auth-sdk-m8 major). Consumers must raise their floor to
`auth-sdk-m8>=2.0.0,<3.0.0` and update any tests asserting the old dual-mount.

### Security hardening — startup config health checks (Phases 1.0, 1.2, 1.3)

#### Phase 1.0 — baseline security-validator regression tests

Codifies the existing security invariants in `CommonSettings` as an explicit
regression suite (`tests/test_validator_baselines.py`) so they cannot silently
regress across future changes:

- All `secret_fields` reject the literal `changethis` placeholder at validation
  time.
- Password fields (`DB_PASSWORD`, `REDIS_PASSWORD`) enforce `PASSWORD_REGEX`
  (8+ chars, upper, lower, digit, special, no spaces).
- Secret-key fields (`ACCESS_SECRET_KEY`, `REFRESH_SECRET_KEY`) enforce
  `SECRET_KEY_REGEX` (32+ chars, upper, lower, digit, non-alphanumeric).
- `EVENT_SIGNING_ENABLED=true` requires a strong `EVENT_SIGNING_KEY` at boot.
- `TOKEN_STRICT_VALIDATION=true` requires both `TOKEN_ISSUER` and
  `TOKEN_AUDIENCE` at boot (fail-closed; missing either raises at model
  validation time).
- Error messages are operator-actionable: they name the failing field and state
  the fix.

No production code changes in this phase.

#### Phase 1.2 — `ALLOWED_HOSTS` field and production host-header gate

- **`CommonSettings.ALLOWED_HOSTS`** (`Optional[List[str]]`, default `None`) —
  comma-separated or list-valued; intended as the allowlist for Starlette
  `TrustedHostMiddleware`. An empty string or empty list normalises to `None`.
- **`_check_allowed_hosts_config()`** in `config_health.py` — called by
  `check_config_health()` at startup:
  - `ALLOWED_HOSTS` not configured in production: warning (operators should
    restrict Host headers).
  - `ALLOWED_HOSTS` not configured under `STRICT_PRODUCTION_MODE`: fatal
    (`ConfigurationError`).
  - `ALLOWED_HOSTS` contains `'*'` under `STRICT_PRODUCTION_MODE`: fatal.
  - Non-prod, non-strict, or explicitly configured hosts: no-op.
  - Settings type without the attribute is a no-op (backward-compatible).

#### Phase 1.3 — `ALLOW_INTERNAL_HTTP` field and inter-service http:// URL gate

- **`CommonSettings.ALLOW_INTERNAL_HTTP`** (`bool`, default `False`) —
  break-glass opt-in for services where `JWKS_URI` / `INTROSPECTION_URL` point
  at plain `http://` because all traffic is confined to a trusted internal
  Docker network.
- **`_check_internal_url_config()`** in `config_health.py` — called by
  `check_config_health()` at startup for `JWKS_URI` and `INTROSPECTION_URL`:
  - `local` / `development` environments: always allowed (Docker bridge).
  - `ALLOW_INTERNAL_HTTP=true`: exempt regardless of environment.
  - `staging` / `production` + `http://`: warning.
  - `staging` / `production` + `http://` + `STRICT_PRODUCTION_MODE`: fatal
    (`ConfigurationError`).
  - `https://` or field not set: always passes.

#### Phase 1.4 — shared app-layer guards for `/metrics` and deep `/health`

New `auth_sdk_m8.security.guards` module (requires the `fastapi` extra, like
`security.headers`). Provides proxy-independent app-layer primitives so the
guarantee for sensitive operational surfaces survives a reverse-proxy swap or
misconfiguration — proxy route-hiding stays defense-in-depth, not the primary
control. `fa-auth-m8` and `fastapi-m8` consume these instead of each
re-deriving its own `X-Internal-Token` comparison:

- **`compare_secret(provided, expected)`** — `None`/empty-safe, constant-time
  secret comparison (`secrets.compare_digest`). A missing header or unset
  secret yields `False` rather than a spurious empty-string match.
- **`extract_bearer_token(request)`** — parses `Authorization: Bearer <token>`
  (case-insensitive scheme); returns `None` when absent, wrong-scheme, or empty.
- **`make_internal_token_authorizer(secret, *, header_name="X-Internal-Token")`**
  — builds a `(Request) -> bool` **predicate** for *detail gating*: deep
  `/health` answers shallow status to everyone and reveals the detail body only
  when the predicate is `True`. Fail-closed — an unset secret never authorizes.
- **`make_scrape_credential_guard(credential)`** — builds a `(Request) -> None`
  FastAPI **dependency** for `/metrics`: when *credential* is unset the route is
  network-gated only (no-op); when set, the request must present a matching
  `Authorization: Bearer` credential or receive `401` with a
  `WWW-Authenticate: Bearer` challenge. A deliberately long-lived static
  credential (maps to Prometheus `authorization` in `scrape_configs`); short-TTL
  tokens are not forced here.

**Backward compatibility:** purely additive — a new optional-`fastapi` submodule;
no existing import path or signature changes.

### Revocation-cache observability (Phase 7.x.2)

Metrics and structured logs for the `AuthEventStreamClient` (the SSE revocation
bridge consumers run as a best-effort cache accelerator), so operators can see
the live cache-invalidation path without ever exposing secrets.

- **New auth-group Prometheus metrics** (`observability` extra; only registered
  when `METRICS_ENABLED=true` and the `auth` group is on):
  - `auth_event_stream_connected` (gauge) — `1` while the SSE stream is
    connected, `0` once it drops.
  - `auth_event_stream_events_total{event_type,result}` (counter) — received
    frames by outcome: `delivered` (verified, dispatched to `on_event`),
    `dropped_sig_fail` (signature verification failed — a forged/unsigned frame,
    **not** dispatched, so it cannot evict cache entries), or `dropped_malformed`
    (undeserializable data).
  - `auth_event_stream_gap_total` (counter) — unresumable gap signals received;
    each forces a local revocation-cache flush via `on_gap`.
  - `auth_event_stream_reconnects_total` (counter) — disconnects that triggered
    a reconnect.
- **Logs:** connection established (logs the stream URL only — never the
  `X-Internal-Token` or signing key), gap-flush at `INFO`, malformed/forged
  frames at `WARNING`. Metric labels carry only the bounded `event_type` and a
  fixed `result`; no JTIs, payloads, or secrets are ever logged or labelled.
- **Best-effort / decoupled:** the `events` extra has no hard dependency on
  `observability`; when `prometheus-client` is absent metric emission is a
  silent no-op and the client behaves exactly as before.

**Backward compatibility:** purely additive — no API or signature changes; the
event-stream client works unchanged with or without the `observability` extra.

### Secret-file (`*_FILE`) source support (Phase 6.1)

`CommonSettings` now resolves the Docker/K8s `*_FILE` secret convention, so the
production overlay can source runtime secrets from mounted files (Docker secrets
/ SOPS / Vault agent / K8s) instead of inlining plaintext values into env files:

- **`_build_file_secret_source(settings_cls)`** — a settings source wired into
  `CommonSettings.settings_customise_sources`. For *any* declared field `FOO`,
  if the environment defines `FOO_FILE` pointing at a readable file, the file's
  stripped contents become the value of `FOO`. Field names are resolved from the
  concrete settings subclass, so every secret a service declares
  (`DB_PASSWORD_FILE`, `REDIS_PASSWORD_FILE`, `EVENT_SIGNING_KEY_FILE`, and any
  service-specific secret such as `PRIVATE_API_SECRET_FILE`,
  `SESSION_SECRET_FILE`, `TOKENS_ENCRYPTION_KEY_FILE`,
  `MEDIA_INTERNAL_SERVICE_TOKEN_FILE`, …) is covered with no explicit allowlist.
- **`_read_secret_file(path, field_name)`** — reads and strips the mounted file.
  Fail-closed: a `*_FILE` variable pointing at a missing file raises at settings
  construction (`<FIELD>_FILE points to a missing file`) rather than silently
  falling back to a plaintext value. File contents are never logged.
- **Source priority:** init kwargs > `*_FILE` secrets > `.env` > env vars >
  pydantic secrets-dir > Vault. A mounted secret file therefore overrides a
  plaintext value in `.env` or the process environment, while explicit
  constructor kwargs still win (so tests and programmatic overrides are
  unaffected).

**Backward compatibility:** purely additive — services that set no `*_FILE`
variables are unaffected; the new source returns nothing and the existing
init/dotenv/env/Vault chain is unchanged.

### Fixed

- **Duplicate `CommonSettings.ALLOW_INTERNAL_HTTP` field definition** (introduced
  in Phase 1.3) collapsed to a single declaration — it tripped a `mypy`
  `no-redef` error. Behaviour is unchanged (same field, same `False` default).
- **`SecurityHeadersSettings.ENVIRONMENT`** is now a read-only `@property` in the
  structural protocol instead of a mutable attribute, so concrete settings whose
  `ENVIRONMENT` is a `Literal[...]` subtype of `str` (e.g. `CommonSettings`)
  satisfy it without a `mypy` attribute-variance conflict. Read-only; no runtime
  or API change.
- **Test suite is `mypy`-clean across `auth_sdk_m8` *and* `tests`** (previously
  only the package was gated): added `None`/`Optional` narrowing for awaited
  background tasks and `deserialize()`/secret accessors, switched UUID-coercion
  tests to `UserModel.model_validate`, and `cast` the deliberately non-conforming
  backward-compat stubs to the settings protocol.

### Security

- **Dependency security floors** (clears `pip-audit`):
  - `cryptography>=48.0.1` (was `>=48.0.0`) — GHSA-537c-gmf6-5ccf.
  - Added a `starlette>=1.3.1` floor to the `fastapi` / `observability` / `all`
    extras — `fastapi` permits the vulnerable `>=0.46.0` transitively; excludes
    CVE-2026-54282 / CVE-2026-54283. (Minimum floor only, no upper pin.)

---

## [1.5.0] — 2026-06-17 · `/ping` reachable behind a prefix-routing proxy

Fixes liveness probing for any service mounted behind a prefix-routing reverse
proxy (e.g. Traefik). `1.4.0` mounted `/ping` only at the root, but such proxies
forward only `PathPrefix({API_PREFIX})`, so a root-only `/ping` 404s at the
gateway while `{prefix}/meta` resolves — observed across the compose examples
where every service carries an `API_PREFIX` (`/user`, `/media`, …).

- **`mount_service_meta` now dual-mounts `/ping`** (`controllers/meta.py`) — the
  root `/ping` is unchanged (direct container/sidecar probes stay
  prefix-independent), and when `prefix` is non-empty the route is **also**
  mounted at `{prefix}/ping` so it is reachable through the proxy, exactly like
  `{prefix}/meta`. The prefixed copy is `include_in_schema=False`, so the OpenAPI
  document still carries a single `ping` operation.

**Backward compatibility:** purely additive — the root `/ping` behaviour and the
`mount_service_meta` signature are unchanged; an empty `prefix` mounts the root
route only (no new path). Consumers on `fastapi-m8` and the issuer `fa-auth-m8`
pick up `{API_PREFIX}/ping` automatically on upgrade with no call-site change.

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
