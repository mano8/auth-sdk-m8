"""Tests for the packaged authorization fixture matrix (§5.5, FIXTURE-01).

Proves the checked-in ``authorization_matrix.json`` matches what
``scripts/generate_authorization_fixture_matrix.py`` currently produces (so
the file cannot drift from the canonical predicates without CI catching it),
that its checksum/schema-version guards are load-bearing, and that its
canonical/mismatched JWT fixtures round-trip through the SDK's own
``TokenValidator`` exactly like a live-issued token would.
"""

import copy
import importlib
import json

import jwt as pyjwt
import pytest
from pydantic import SecretStr

import auth_sdk_m8
from auth_sdk_m8.core.exceptions import (
    FixtureChecksumMismatchError,
    UnsupportedFixtureMatrixSchemaVersionError,
)
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.security import TokenValidationConfig, TokenValidator
from auth_sdk_m8.testing import (
    FIXTURE_MATRIX_SCHEMA_VERSION,
    load_authorization_fixture_matrix,
)
from scripts.generate_authorization_fixture_matrix import build_fixture_matrix

_ALL_ROLES = [r.value for r in RoleType]


@pytest.fixture(scope="module")
def matrix() -> dict:
    return load_authorization_fixture_matrix()


class TestGeneratorReproducibility:
    def test_checked_in_file_matches_generator_output(self, matrix: dict) -> None:
        """The committed JSON must be exactly what the generator produces now.

        Guards against a hand-edit or a partial regeneration after a source
        change — if this fails, re-run
        ``scripts/generate_authorization_fixture_matrix.py`` and commit the
        result.
        """
        regenerated = build_fixture_matrix()
        assert matrix == regenerated


class TestSchemaVersionAndChecksumGuards:
    def test_loader_returns_declared_schema_version(self, matrix: dict) -> None:
        assert matrix["schema_version"] == FIXTURE_MATRIX_SCHEMA_VERSION

    def test_unknown_schema_version_is_rejected(self, matrix: dict) -> None:
        from auth_sdk_m8.testing import (
            _compute_checksum,
            _parse_and_verify_fixture_matrix,
        )

        tampered = copy.deepcopy(matrix)
        tampered["schema_version"] = "999"
        # Recompute the checksum so only the version is being exercised here.
        tampered["checksum_sha256"] = _compute_checksum(tampered)

        with pytest.raises(UnsupportedFixtureMatrixSchemaVersionError):
            _parse_and_verify_fixture_matrix(json.dumps(tampered))

    def test_tampered_content_fails_checksum_verification(self, matrix: dict) -> None:
        from auth_sdk_m8.testing import _parse_and_verify_fixture_matrix

        tampered = copy.deepcopy(matrix)
        tampered["role_flag_matrix"][0]["has_superuser_privileges"] = True

        with pytest.raises(FixtureChecksumMismatchError):
            _parse_and_verify_fixture_matrix(json.dumps(tampered))

    def test_checksum_matches_recomputation(self, matrix: dict) -> None:
        from auth_sdk_m8.testing import _compute_checksum

        assert matrix["checksum_sha256"] == _compute_checksum(matrix)

    def test_loader_reads_the_real_packaged_resource(self, matrix: dict) -> None:
        # End-to-end: the public loader (real importlib.resources path) agrees
        # with the module-scoped fixture used throughout this file.
        assert load_authorization_fixture_matrix() == matrix


class TestRoleFlagMatrixContent:
    def test_has_ten_rows(self, matrix: dict) -> None:
        assert len(matrix["role_flag_matrix"]) == 10

    def test_every_role_flag_combination_present_exactly_once(
        self, matrix: dict
    ) -> None:
        seen = {
            (row["role"], row["is_superuser"]) for row in matrix["role_flag_matrix"]
        }
        expected = {(role, flag) for role in _ALL_ROLES for flag in (False, True)}
        assert seen == expected

    def test_only_canonical_superadmin_pair_is_consistent_and_privileged(
        self, matrix: dict
    ) -> None:
        for row in matrix["role_flag_matrix"]:
            is_canonical = row["role"] == "superadmin" and row["is_superuser"] is True
            assert row["consistent"] is (
                is_canonical
                or (row["role"] != "superadmin" and not row["is_superuser"])
            )
            assert row["has_superuser_privileges"] is is_canonical


class TestMinimumRoleMatrixContent:
    def test_has_twenty_five_rows(self, matrix: dict) -> None:
        assert len(matrix["minimum_role_matrix"]) == 25

    def test_every_pair_present_exactly_once(self, matrix: dict) -> None:
        seen = {
            (row["current_role"], row["required_role"])
            for row in matrix["minimum_role_matrix"]
        }
        expected = {(c, r) for c in _ALL_ROLES for r in _ALL_ROLES}
        assert seen == expected

    def test_same_role_always_satisfies_itself(self, matrix: dict) -> None:
        for row in matrix["minimum_role_matrix"]:
            if row["current_role"] == row["required_role"]:
                assert row["satisfied"] is True


class TestSessionRevokedEventFixtures:
    def test_v1_event_has_no_generation_or_event_id(self, matrix: dict) -> None:
        v1 = matrix["session_revoked_events"]["v1"]
        assert v1["version"] == "v1"
        assert "auth_generation" not in v1
        assert "event_id" not in v1

    def test_v2_single_session_event_carries_generation_and_event_id(
        self, matrix: dict
    ) -> None:
        v2 = matrix["session_revoked_events"]["v2_single_session"]
        assert v2["version"] == "v2"
        assert v2["jti"] is not None
        assert v2["auth_generation"] >= 1
        assert v2["event_id"]

    def test_v2_user_wide_event_has_null_jti(self, matrix: dict) -> None:
        v2 = matrix["session_revoked_events"]["v2_user_wide"]
        assert v2["jti"] is None

    def test_v1_and_v2_share_the_same_user_id(self, matrix: dict) -> None:
        events = matrix["session_revoked_events"]
        assert events["v1"]["user_id"] == events["v2_single_session"]["user_id"]
        assert events["v1"]["user_id"] == events["v2_user_wide"]["user_id"]

    def test_events_validate_against_the_sdk_schema(self, matrix: dict) -> None:
        from auth_sdk_m8.schemas.user_events import SessionRevokedEvent

        for event in matrix["session_revoked_events"].values():
            SessionRevokedEvent.model_validate(event)


class TestCanonicalJwtFixtures:
    def test_ten_tokens_covering_every_role_flag_pair(self, matrix: dict) -> None:
        tokens = matrix["canonical_jwt_fixtures"]["tokens"]
        assert len(tokens) == 10
        seen = {(t["role"], t["is_superuser"]) for t in tokens}
        expected = {(role, flag) for role in _ALL_ROLES for flag in (False, True)}
        assert seen == expected

    def test_signing_key_passes_the_sdk_secret_strength_check(
        self, matrix: dict
    ) -> None:
        key = matrix["canonical_jwt_fixtures"]["trusted_test_signing_key"]
        # Raises if the fixture key does not meet the SDK's own key-strength
        # rule, so a consumer can build a TokenSecret from it directly.
        TokenSecret(secret_key=SecretStr(key), algorithm="HS256")

    def test_tokens_are_signed_with_the_declared_key(self, matrix: dict) -> None:
        fixtures = matrix["canonical_jwt_fixtures"]
        for entry in fixtures["tokens"]:
            decoded = pyjwt.decode(
                entry["jwt"],
                fixtures["trusted_test_signing_key"],
                algorithms=[fixtures["algorithm"]],
            )
            assert decoded["role"] == entry["role"]
            assert decoded["is_superuser"] == entry["is_superuser"]

    def test_consistent_tokens_validate_through_the_sdk_validator(
        self, matrix: dict
    ) -> None:
        fixtures = matrix["canonical_jwt_fixtures"]
        validator = TokenValidator(
            secrets=TokenSecret(
                secret_key=SecretStr(fixtures["trusted_test_signing_key"]),
                algorithm="HS256",
            ),
            config=TokenValidationConfig(allowed_algorithms=["HS256"]),
        )
        for entry in fixtures["tokens"]:
            if not entry["consistent"]:
                continue
            payload = validator.validate_access_token(entry["jwt"])
            assert payload.role.value == entry["role"]
            assert payload.is_superuser is entry["is_superuser"]

    def test_inconsistent_tokens_are_rejected_by_the_sdk_validator(
        self, matrix: dict
    ) -> None:
        from auth_sdk_m8.core.exceptions import InvalidToken

        fixtures = matrix["canonical_jwt_fixtures"]
        validator = TokenValidator(
            secrets=TokenSecret(
                secret_key=SecretStr(fixtures["trusted_test_signing_key"]),
                algorithm="HS256",
            ),
            config=TokenValidationConfig(allowed_algorithms=["HS256"]),
        )
        for entry in fixtures["tokens"]:
            if entry["consistent"]:
                continue
            with pytest.raises(InvalidToken):
                validator.validate_access_token(entry["jwt"])


class TestPublicPackageSurface:
    def test_loader_and_constants_re_exported_from_package_root(self) -> None:
        assert (
            auth_sdk_m8.load_authorization_fixture_matrix
            is load_authorization_fixture_matrix
        )
        assert (
            auth_sdk_m8.FIXTURE_MATRIX_SCHEMA_VERSION == FIXTURE_MATRIX_SCHEMA_VERSION
        )
        assert auth_sdk_m8.FixtureChecksumMismatchError is FixtureChecksumMismatchError
        assert (
            auth_sdk_m8.UnsupportedFixtureMatrixSchemaVersionError
            is UnsupportedFixtureMatrixSchemaVersionError
        )

    def test_all_exports_present_in_dunder_all(self) -> None:
        for name in (
            "FIXTURE_MATRIX_CHECKSUM_MISMATCH_REASON",
            "FIXTURE_MATRIX_SCHEMA_VERSION",
            "UNSUPPORTED_FIXTURE_MATRIX_SCHEMA_VERSION_REASON",
            "FixtureChecksumMismatchError",
            "UnsupportedFixtureMatrixSchemaVersionError",
            "load_authorization_fixture_matrix",
        ):
            assert name in auth_sdk_m8.__all__

    def test_testing_module_reimports_cleanly(self) -> None:
        # Guards against any accidental import-time side effect/circularity.
        importlib.reload(importlib.import_module("auth_sdk_m8.testing"))
