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
    has_minimum_role,
    has_superuser_privileges,
    privilege_claims_are_consistent,
)
from auth_sdk_m8.schemas.base import RoleType

#: Schema version of the published fixture matrix. Bump only alongside a
#: breaking change to the matrix's own shape (not the SDK's package version).
FIXTURE_MATRIX_SCHEMA_VERSION = "1"

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


def _compute_checksum(payload: dict[str, Any]) -> str:
    """Deterministic sha256 over every field except the checksum itself."""
    body = {k: v for k, v in payload.items() if k != "checksum_sha256"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_fixture_matrix() -> dict[str, Any]:
    """Build the full fixture-matrix payload, checksum included."""
    payload: dict[str, Any] = {
        "schema_version": FIXTURE_MATRIX_SCHEMA_VERSION,
        "sdk_version": auth_sdk_m8.__version__,
        "role_flag_matrix": _role_flag_matrix(),
        "minimum_role_matrix": _minimum_role_matrix(),
        "session_revoked_events": _session_revoked_events(),
        "canonical_jwt_fixtures": _canonical_jwt_fixtures(),
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
