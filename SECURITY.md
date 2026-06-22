# Security — auth-sdk-m8

## Trust model

`auth-sdk-m8` is a **verification library**. It owns the cryptographic and configuration
primitives; it does not own network controls, secret storage, or key rotation procedures.

**What this library provides:**

- Token validation — signature, expiry, algorithm, `iss`/`aud` claims, JTI revocation check.
- Startup config health checks (`check_config_health`) — fatal misconfig blocks boot before the
  first request.
- App-layer access guards — `make_internal_token_authorizer` (detail-gating predicate for deep
  `/health`), `make_scrape_credential_guard` (hard gate for `/metrics`), and
  `make_consumer_authorizer` (per-consumer scope enforcement for `/private/*`). These guards hold
  regardless of which reverse proxy is in front.
- Per-consumer credential verification (`ConsumerCredentialRegistry`) — salted SHA-256 digests,
  constant-time comparison, deny-by-default scope model.
- Response security headers — `add_security_headers_middleware` attaches hardening headers at the
  ASGI layer so they apply even to errors raised before a route handler.

**What this library does NOT own:**

- Network-layer controls (TLS termination, firewall rules, Traefik/nginx routing). These are the
  deployer's responsibility; guards here are the primary control, proxy hiding is defense-in-depth.
- Secret storage. Secrets are loaded from env files, `_FILE` mounts, Docker secrets, or Vault
  through `CommonSettings.settings_customise_sources` — the library reads them, it does not store them.
- Key generation or rotation procedures. See the rotation playbooks below for the correct steps.
- Rate limiting at the infrastructure layer or per-IP/per-user network throttling.

---

## Secret inventory

| Secret | Held by | Blast radius if leaked | Rotation priority |
| --- | --- | --- | --- |
| `ACCESS_SECRET_KEY` (HS256) | issuer | Any holder can forge valid access tokens | **Immediate** |
| RSA/EC private key (`ACCESS_PRIVATE_KEY_FILE`) | issuer only (never consumers) | Any holder can forge access tokens and sign a rogue JWKS | **Immediate** |
| `REFRESH_SECRET_KEY` | issuer | Any holder can forge refresh tokens, bypassing rotation | **Immediate** |
| `REFRESH_SECRET_KEY_OLD` | issuer (rotation window only) | Same as `REFRESH_SECRET_KEY` while set | **Remove after rotation window expires** |
| `EVENT_SIGNING_KEY` | issuer + all consumers | Forged event frames — malicious session-revoked / user-deleted delivery can corrupt revocation caches | **Immediate; rotate all services together** |
| `PRIVATE_API_SECRET` (shared model) | issuer + registered consumers | Any holder can call `/private/*` endpoints (JTI-status, event-stream) | **Immediate; scoped per-consumer credentials (9.1) reduce blast radius** |
| `DB_PASSWORD` | issuer | Direct read/write access to the user, session, auth-code, and API-key tables | **Immediate** |
| `REDIS_PASSWORD` / per-ACL-user password | issuer (and media-service if bundled) | Session and refresh-token store; JTI blacklist reads and writes | **Immediate** |
| `METRICS_SCRAPE_CREDENTIAL` | per-service, Prometheus scraper | Unauthorised metrics reads | Rotate promptly |
| Per-consumer credential (`ConsumerCredential`) | issuer credential map | A leaked credential can call the scoped `/private/*` operation it was granted | Rotate the individual credential; no fleet-wide impact |

---

## Incident response

### Leaked access-token signing key (`ACCESS_SECRET_KEY` or `ACCESS_PRIVATE_KEY_FILE`)

1. **Detection** — unusual API activity, unfamiliar JWTs in logs, or an external report.
2. **Containment** — generate a new key immediately (RSA: `openssl genrsa`; HS256: a new 32+ char
   random string). Deploy the issuer with the new key.
3. **Session wipe** — invalidate all active sessions: in Redis, delete `rt:*`, `oauth_session:*`,
   `auth_code:*`, and `jwt:blacklist:*`; or wipe the refresh-token and session tables in the DB.
   All users must re-authenticate.
4. **RS256 consumers** — after the issuer is redeployed, wait for `JWKS_CACHE_TTL_SECONDS`
   (default 300 s) to expire on every consumer, or restart them to force JWKS re-fetch. Tokens
   signed with the old key are then rejected.
5. **Validation** — issue a new access token and confirm it is accepted; attempt to validate a
   token signed with the old key — it must be rejected with `InvalidToken`.

### Leaked refresh signing key (`REFRESH_SECRET_KEY`)

1. **Containment** — generate a new key. Use the zero-downtime path: set the new key as
   `REFRESH_SECRET_KEY` and move the old key to `REFRESH_SECRET_KEY_OLD`. Deploy.
2. **Window** — `REFRESH_SECRET_KEY_OLD` lets existing refresh tokens survive until they expire
   (after `REFRESH_TOKEN_EXPIRE_MINUTES`). Once the window closes, remove `REFRESH_SECRET_KEY_OLD`
   and redeploy.
3. **Forced wipe** — if you cannot wait for natural expiry, wipe `rt:*` in Redis (same as above).
   All active refresh tokens are then invalid and users must re-login.
4. **Validation** — issue a new refresh token; confirm the old key no longer signs valid tokens.

### Leaked event-signing key (`EVENT_SIGNING_KEY`)

1. **Impact** — an attacker can forge `session-revoked` / `user-deleted` SSE frames, causing
   consumers to incorrectly flush their revocation caches (false logouts) or suppress legitimate
   revocation events (tokens appear valid longer than they are). Token issuance is unaffected.
2. **Rollout window** — set `EVENT_SIGNING_ACCEPT_UNSIGNED=true` on consumers and
   `EVENT_SIGNING_ENABLED=false` on the publisher; distribute the new `EVENT_SIGNING_KEY` to
   every service; re-enable signing; flip `EVENT_SIGNING_ACCEPT_UNSIGNED` back to `false`.
3. **Verification** — the `auth_event_stream_events_total{result="dropped_sig_fail"}` metric
   should reach zero once every publisher is signing with the new key.

### Leaked `PRIVATE_API_SECRET` (shared model)

1. **Impact** — any holder can call `/private/*` endpoints: JTI-status introspection and the
   event-stream. They cannot forge tokens or read the database directly.
2. **Containment** — rotate the value in the issuer **and every registered consumer** simultaneously;
   redeploy all services.
3. **Longer-term hardening** — deploy per-consumer credentials via `ConsumerCredentialRegistry`
   (Phase 9.1 issuer-side). Each consumer then holds its own secret; rotating one does not
   require touching all others. Blast radius drops from fleet-wide to a single consumer.

### Leaked database password (`DB_PASSWORD`)

1. **Containment** — change the DB password immediately; redeploy the issuer with the new
   credential.
2. **Audit** — review database audit logs for unauthorized reads/writes to the `user`, `session`,
   `auth_code`, `refresh_token`, and `api_key` tables. If write access was exploited, treat all
   active sessions and issued tokens as potentially compromised and follow the signing-key rotation
   playbook above.

### Leaked Redis password / ACL credential

1. **Containment** — change the ACL user password (`ACL SETUSER auth on >newpassword …`) and
   redeploy.
2. **Audit** — an attacker with Redis write access can modify `rt:*` (refresh-token allowlist),
   `jwt:blacklist:*` (JTI blacklist), and `oauth_session:*` (auth-code sessions). Treat all active
   sessions as potentially compromised; wipe the relevant key prefixes and force re-authentication.
3. **Key-prefix isolation** — the scoped ACL (Phase 6.x.1) limits the Redis user to exactly the
   prefixes the auth service uses. An attacker who only reads/writes those prefixes cannot pivot to
   other Redis namespaces.

### Leaked per-consumer credential (`ConsumerCredential`)

1. **Scope** — the leaked credential can call only the scopes it was granted (e.g.
   `ConsumerScope.INTROSPECTION`). It cannot forge tokens or access other consumers' operations.
2. **Containment** — remove the entry from `ConsumerCredentialRegistry` and deploy a new
   credential for the affected consumer. No other consumer is affected.

---

## Reporting a vulnerability

Report security issues privately to **mex.serra@gmail.com** with `[auth-sdk-m8] SECURITY` in the
subject line. Do not open a public GitHub issue for vulnerabilities. Expected response within 48 h.
