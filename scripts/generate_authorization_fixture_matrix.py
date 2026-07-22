"""Generate the versioned, checksummed authorization fixture matrix (§5.5).

auth-sdk-m8 is the single canonical owner of the shared role/flag/decision/
event test-fixture matrix consumed by fastapi-m8, fa-auth-m8, and
security-tests-m8. Run this script and commit the regenerated
``auth_sdk_m8/testing/authorization_matrix.json`` whenever the canonical
truth table or the session-revoked event shape changes —
``tests/test_fixture_matrix.py`` fails if the checked-in file drifts from what
this script produces.

Usage: python scripts/generate_authorization_fixture_matrix.py
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt

import auth_sdk_m8
from auth_sdk_m8.authorization import (
    API_KEY_MAX_REQUIRED_ROLE,
    ApiKeyCapabilityCeilingError,
    has_api_key_capability,
    has_minimum_role,
    has_superuser_privileges,
    privilege_claims_are_consistent,
)
from auth_sdk_m8.schemas.api_key import (
    API_KEY_AUTHENTICATION_METHOD,
    API_KEY_INTROSPECTION_SCHEMA_VERSION,
)
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType
from auth_sdk_m8.schemas.jti_status import JTI_STATUS_SCHEMA_VERSION

#: Schema version of the published fixture matrix. Bump only alongside a
#: breaking change to the matrix's own shape (not the SDK's package version).
#: v2 is additive over v1: it adds the JTI-status v1/v2, API-key
#: introspection + status-matrix, local/remote principal-equivalence, and
#: audience/capability-policy sections without altering any v1 field.
FIXTURE_MATRIX_SCHEMA_VERSION = "2"

#: A schema version this SDK release deliberately does not implement, used
#: only to build the unknown-schema-version fail-closed fixture rows below —
#: never a version that will ever be assigned.
_UNSUPPORTED_SCHEMA_VERSION_PROBE = "999"

#: Dedicated fixture-only signing key — never a production secret. Satisfies
#: the SDK's own SECRET_KEY_REGEX so a consumer can build a TokenSecret /
#: TokenValidator directly from it without a separate key of its own.
TRUSTED_TEST_SIGNING_KEY = "AuthSdkM8-Fixture_TrustedTestKey-2026-DoNotUseInProd!"

#: Far-future, fixed expiry so the checked-in tokens never expire in CI.
_FIXTURE_TOKEN_EXP = int(datetime(2100, 1, 1, tzinfo=timezone.utc).timestamp())

_ALL_ROLES = list(RoleType)

_OUTPUT_PATH = (
    Path(__file__).resolve().parent.parent
    / "auth_sdk_m8"
    / "testing"
    / "authorization_matrix.json"
)


def _role_flag_matrix() -> list[dict[str, Any]]:
    """Every role/flag pair (5 roles × 2 flags), with its truth-table verdict."""
    rows = []
    for role in _ALL_ROLES:
        for is_superuser in (False, True):
            rows.append(
                {
                    "role": role.value,
                    "is_superuser": is_superuser,
                    "consistent": privilege_claims_are_consistent(role, is_superuser),
                    "has_superuser_privileges": has_superuser_privileges(
                        role, is_superuser
                    ),
                }
            )
    return rows


def _minimum_role_matrix() -> list[dict[str, Any]]:
    """Every current/required role pair (5 × 5), with its decision."""
    rows = []
    for current in _ALL_ROLES:
        for required in _ALL_ROLES:
            rows.append(
                {
                    "current_role": current.value,
                    "required_role": required.value,
                    "satisfied": has_minimum_role(current, required),
                }
            )
    return rows


def _session_revoked_events() -> dict[str, Any]:
    """v1 and v2 session-revoked event fixtures (3.5.2)."""
    user_id = "11111111-1111-4111-8111-111111111111"
    single_jti = "22222222-2222-4222-8222-222222222222"
    return {
        "v1": {
            "event_type": "session.revoked",
            "version": "v1",
            "user_id": user_id,
            "jti": single_jti,
        },
        "v2_single_session": {
            "event_type": "session.revoked",
            "version": "v2",
            "user_id": user_id,
            "jti": single_jti,
            "auth_generation": 1,
            "event_id": "33333333-3333-4333-8333-333333333333",
        },
        "v2_user_wide": {
            "event_type": "session.revoked",
            "version": "v2",
            "user_id": user_id,
            "jti": None,
            "auth_generation": 2,
            "event_id": "44444444-4444-4444-8444-444444444444",
        },
    }


def _canonical_jwt_fixtures() -> dict[str, Any]:
    """Every role/flag pair signed with the trusted test key (§3.9/3.1)."""
    tokens = []
    for role in _ALL_ROLES:
        for is_superuser in (False, True):
            payload = {
                "sub": "55555555-5555-4555-8555-555555555555",
                "type": "access",
                "email": "fixture-user@example.com",
                "role": role.value,
                "is_active": True,
                "email_verified": True,
                "is_superuser": is_superuser,
                "jti": f"fixture-{role.value}-{is_superuser}",
                "exp": _FIXTURE_TOKEN_EXP,
            }
            token = jwt.encode(payload, TRUSTED_TEST_SIGNING_KEY, algorithm="HS256")
            tokens.append(
                {
                    "role": role.value,
                    "is_superuser": is_superuser,
                    "consistent": privilege_claims_are_consistent(role, is_superuser),
                    "jwt": token,
                }
            )
    return {
        "algorithm": "HS256",
        "trusted_test_signing_key": TRUSTED_TEST_SIGNING_KEY,
        "tokens": tokens,
    }


def _jti_status_fixtures() -> dict[str, Any]:
    """v1 and v2 JTI-status introspection request/response fixtures (3.5.2)."""
    user_id = "66666666-6666-4666-8666-666666666666"
    other_user_id = "77777777-7777-4777-8777-777777777777"
    jti = "88888888-8888-4888-8888-888888888888"
    return {
        "v1": {
            "request": {"jti": jti},
            "active": {"active": True},
            "inactive": {"active": False},
        },
        "v2": {
            "request": {
                "jti": jti,
                "expected_user_id": user_id,
                "schema_version": JTI_STATUS_SCHEMA_VERSION,
            },
            "active": {
                "active": True,
                "user_id": user_id,
                "auth_generation": 3,
                "schema_version": JTI_STATUS_SCHEMA_VERSION,
            },
            "inactive": {
                "active": False,
                "schema_version": JTI_STATUS_SCHEMA_VERSION,
            },
            "subject_mismatch_request": {
                "jti": jti,
                "expected_user_id": other_user_id,
                "schema_version": JTI_STATUS_SCHEMA_VERSION,
            },
            "subject_mismatch_inactive": {
                "active": False,
                "schema_version": JTI_STATUS_SCHEMA_VERSION,
            },
        },
        "unsupported_schema_version_response": {
            "active": True,
            "user_id": user_id,
            "auth_generation": 1,
            "schema_version": _UNSUPPORTED_SCHEMA_VERSION_PROBE,
        },
    }


def _api_key_principals() -> list[dict[str, Any]]:
    """One consistent :class:`ApiKeyPrincipal` per role x access-mode pair."""
    owner_id = "99999999-9999-4999-8999-999999999999"
    principals = []
    for role in _ALL_ROLES:
        is_superuser = role == RoleType.SUPERADMIN
        if not privilege_claims_are_consistent(role, is_superuser):
            continue
        for access_mode in ApiKeyAccessMode:
            principals.append(
                {
                    "user_id": owner_id,
                    "role": role.value,
                    "is_superuser": is_superuser,
                    "access_mode": access_mode.value,
                    "authentication_method": API_KEY_AUTHENTICATION_METHOD,
                    "auth_generation": 4,
                }
            )
    return principals


def _api_key_introspection_fixtures(
    principals: list[dict[str, Any]],
) -> dict[str, Any]:
    """API-key introspection request/response shapes + status matrix (§3.12)."""
    audience_id = "fixture-consumer-m8"
    representative = next(
        p
        for p in principals
        if p["role"] == RoleType.WRITER.value
        and p["access_mode"] == ApiKeyAccessMode.READ_WRITE.value
    )
    return {
        "request": {
            "api_key": "fixture-raw-api-key-do-not-use-in-prod",
            "schema_version": API_KEY_INTROSPECTION_SCHEMA_VERSION,
        },
        "active_response": {
            "active": True,
            "schema_version": API_KEY_INTROSPECTION_SCHEMA_VERSION,
            "audience_id": audience_id,
            "principal": representative,
            "key_expires_at": None,
        },
        "inactive_response": {
            "active": False,
            "schema_version": API_KEY_INTROSPECTION_SCHEMA_VERSION,
        },
        "unsupported_schema_version_response": {
            "active": False,
            "schema_version": _UNSUPPORTED_SCHEMA_VERSION_PROBE,
        },
        # Bounded, secret-free HTTP-status expectations for the issuer's
        # introspection endpoint and the consumer's mapping of it (§3.12).
        # These are documentation-as-data for the surfaces named in the
        # scenario, not a substitute for the live status-matrix tests owned
        # by fastapi-m8/fa-auth-m8 themselves.
        "status_matrix": [
            {
                "scenario": "invalid_internal_consumer_credential",
                "surface": "issuer",
                "http_status": 401,
            },
            {
                "scenario": "credential_missing_introspection_scope",
                "surface": "issuer",
                "http_status": 403,
            },
            {
                "scenario": "unknown_revoked_expired_key",
                "surface": "issuer",
                "http_status": 200,
                "body_active": False,
            },
            {
                "scenario": "missing_inactive_inconsistent_owner",
                "surface": "issuer",
                "http_status": 200,
                "body_active": False,
            },
            {
                "scenario": "audience_not_bound_to_key",
                "surface": "issuer",
                "http_status": 200,
                "body_active": False,
            },
            {
                "scenario": "key_quota_exhausted",
                "surface": "issuer",
                "http_status": 429,
                "retry_after_header": True,
            },
            {
                "scenario": "issuer_database_unavailable",
                "surface": "issuer",
                "http_status": 503,
            },
            {
                "scenario": "consumer_maps_inactive_to_generic_401",
                "surface": "consumer",
                "http_status": 401,
            },
            {
                "scenario": "consumer_maps_issuer_429_relaying_retry_after",
                "surface": "consumer",
                "http_status": 429,
                "retry_after_header": True,
            },
            {
                "scenario": "introspection_outage_or_timeout",
                "surface": "consumer",
                "http_status": 503,
            },
            {
                "scenario": "unsupported_schema_version_returned",
                "surface": "consumer",
                "http_status": 503,
            },
            {
                "scenario": "audience_id_mismatch_vs_configured_identity",
                "surface": "consumer",
                "http_status": 503,
            },
        ],
    }


def _local_remote_principal_equivalence(
    principals: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Local (issuer DB) and remote (introspection) principal parity pairs.

    Both halves of the API-key rule resolve the *same* :class:`ApiKeyPrincipal`
    from the same owner state (§3.12) — the fixture pairs are identical by
    construction, so the consuming test proves the assertion, not the fixture.
    """
    return [{"local": principal, "remote": principal} for principal in principals]


def _audience_and_capability_policy_matrix(
    principals: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """API-key access-mode/audience/capability-ceiling decision rows (§3.11/§3.12)."""
    rows: list[dict[str, Any]] = []
    for principal in principals:
        role = RoleType(principal["role"])
        access_mode = ApiKeyAccessMode(principal["access_mode"])
        for required_role in (RoleType.USER, RoleType.READER, RoleType.WRITER):
            allowed = has_api_key_capability(
                role, principal["is_superuser"], access_mode, required_role
            )
            for has_audience in (True, False):
                rows.append(
                    {
                        "role": role.value,
                        "access_mode": access_mode.value,
                        "required_role": required_role.value,
                        "has_audience": has_audience,
                        # The issuer-local path has no audience concept — it
                        # is same-service authorization, never a remote call.
                        "issuer_local_allowed": allowed,
                        # No audience bound to the key ⇒ remote introspection
                        # answers active:false regardless of role/access_mode.
                        "remote_active": has_audience,
                        "remote_allowed": allowed and has_audience,
                        "capability_ceiling_error": False,
                    }
                )
    # Administrative and superuser capability are never reachable via an API
    # key at all, whatever the owner's role/access_mode/audience (§3.11) — the
    # ceiling check raises before any owner/audience dimension is considered.
    for required_role in (RoleType.ADMIN, RoleType.SUPERADMIN):
        try:
            has_api_key_capability(
                RoleType.SUPERADMIN,
                True,
                ApiKeyAccessMode.READ_WRITE,
                required_role,
            )
            ceiling_error = False
        except ApiKeyCapabilityCeilingError:
            ceiling_error = True
        rows.append(
            {
                "role": None,
                "access_mode": None,
                "required_role": required_role.value,
                "has_audience": None,
                "issuer_local_allowed": False,
                "remote_active": None,
                "remote_allowed": False,
                "capability_ceiling_error": ceiling_error,
            }
        )
    assert API_KEY_MAX_REQUIRED_ROLE == RoleType.WRITER
    return rows


def _compute_checksum(payload: dict[str, Any]) -> str:
    """Deterministic sha256 over every field except the checksum itself."""
    body = {k: v for k, v in payload.items() if k != "checksum_sha256"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_fixture_matrix() -> dict[str, Any]:
    """Build the full fixture-matrix payload, checksum included."""
    principals = _api_key_principals()
    payload: dict[str, Any] = {
        "schema_version": FIXTURE_MATRIX_SCHEMA_VERSION,
        "sdk_version": auth_sdk_m8.__version__,
        "role_flag_matrix": _role_flag_matrix(),
        "minimum_role_matrix": _minimum_role_matrix(),
        "session_revoked_events": _session_revoked_events(),
        "canonical_jwt_fixtures": _canonical_jwt_fixtures(),
        "jti_status_fixtures": _jti_status_fixtures(),
        "api_key_introspection_fixtures": _api_key_introspection_fixtures(principals),
        "local_remote_principal_equivalence": _local_remote_principal_equivalence(
            principals
        ),
        "audience_and_capability_policy_matrix": _audience_and_capability_policy_matrix(
            principals
        ),
    }
    payload["checksum_sha256"] = _compute_checksum(payload)
    return payload


def main() -> None:
    """Regenerate and write the checked-in fixture-matrix JSON file."""
    matrix = build_fixture_matrix()
    _OUTPUT_PATH.write_text(
        json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote {_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
