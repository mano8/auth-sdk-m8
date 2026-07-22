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


class TestJtiStatusFixtures:
    def test_v1_shapes_have_no_v2_fields(self, matrix: dict) -> None:
        v1 = matrix["jti_status_fixtures"]["v1"]
        for shape in (v1["active"], v1["inactive"]):
            assert "schema_version" not in shape
            assert "auth_generation" not in shape

    def test_v2_active_validates_against_sdk_schema(self, matrix: dict) -> None:
        from auth_sdk_m8.schemas.jti_status import JtiStatusActiveResponse

        v2 = matrix["jti_status_fixtures"]["v2"]
        JtiStatusActiveResponse.model_validate(v2["active"])

    def test_v2_inactive_shapes_validate_against_sdk_schema(self, matrix: dict) -> None:
        from auth_sdk_m8.schemas.jti_status import JtiStatusInactiveResponse

        v2 = matrix["jti_status_fixtures"]["v2"]
        JtiStatusInactiveResponse.model_validate(v2["inactive"])
        JtiStatusInactiveResponse.model_validate(v2["subject_mismatch_inactive"])

    def test_subject_mismatch_request_targets_a_different_user(
        self, matrix: dict
    ) -> None:
        v2 = matrix["jti_status_fixtures"]["v2"]
        assert (
            v2["subject_mismatch_request"]["expected_user_id"]
            != v2["request"]["expected_user_id"]
        )

    def test_unsupported_schema_version_response_is_rejected(
        self, matrix: dict
    ) -> None:
        from pydantic import ValidationError

        from auth_sdk_m8.core.exceptions import UnsupportedJtiStatusSchemaVersionError
        from auth_sdk_m8.schemas.jti_status import JtiStatusActiveResponse

        bad = matrix["jti_status_fixtures"]["unsupported_schema_version_response"]
        with pytest.raises(ValidationError) as exc_info:
            JtiStatusActiveResponse.model_validate(bad)
        causes = [
            (detail.get("ctx") or {}).get("error")
            for detail in exc_info.value.errors(include_url=False, include_context=True)
        ]
        assert any(
            isinstance(cause, UnsupportedJtiStatusSchemaVersionError)
            for cause in causes
        )


class TestApiKeyIntrospectionFixtures:
    def test_active_response_validates_against_sdk_schema(self, matrix: dict) -> None:
        from auth_sdk_m8.schemas.api_key import ApiKeyIntrospectionActiveResponse

        fixtures = matrix["api_key_introspection_fixtures"]
        ApiKeyIntrospectionActiveResponse.model_validate(fixtures["active_response"])

    def test_inactive_response_validates_against_sdk_schema(self, matrix: dict) -> None:
        from auth_sdk_m8.schemas.api_key import ApiKeyIntrospectionInactiveResponse

        fixtures = matrix["api_key_introspection_fixtures"]
        ApiKeyIntrospectionInactiveResponse.model_validate(
            fixtures["inactive_response"]
        )

    def test_active_response_shape_is_minimized(self, matrix: dict) -> None:
        active = matrix["api_key_introspection_fixtures"]["active_response"]
        for forbidden in ("is_active", "key_hash", "key_id", "email", "reason"):
            assert forbidden not in active
            assert forbidden not in active["principal"]

    def test_unsupported_schema_version_response_is_rejected(
        self, matrix: dict
    ) -> None:
        from pydantic import ValidationError

        from auth_sdk_m8.core.exceptions import UnsupportedApiKeySchemaVersionError
        from auth_sdk_m8.schemas.api_key import ApiKeyIntrospectionInactiveResponse

        fixtures = matrix["api_key_introspection_fixtures"]
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyIntrospectionInactiveResponse.model_validate(
                fixtures["unsupported_schema_version_response"]
            )
        causes = [
            (detail.get("ctx") or {}).get("error")
            for detail in exc_info.value.errors(include_url=False, include_context=True)
        ]
        assert any(
            isinstance(cause, UnsupportedApiKeySchemaVersionError) for cause in causes
        )

    def test_status_matrix_covers_both_surfaces(self, matrix: dict) -> None:
        rows = matrix["api_key_introspection_fixtures"]["status_matrix"]
        surfaces = {row["surface"] for row in rows}
        assert surfaces == {"issuer", "consumer"}
        statuses = {row["http_status"] for row in rows}
        assert statuses == {200, 401, 403, 429, 503}


class TestLocalRemotePrincipalEquivalence:
    def test_every_pair_is_identical(self, matrix: dict) -> None:
        for pair in matrix["local_remote_principal_equivalence"]:
            assert pair["local"] == pair["remote"]

    def test_pairs_validate_against_sdk_principal_schema(self, matrix: dict) -> None:
        from auth_sdk_m8.schemas.api_key import ApiKeyPrincipal

        for pair in matrix["local_remote_principal_equivalence"]:
            ApiKeyPrincipal.model_validate(pair["local"])
            ApiKeyPrincipal.model_validate(pair["remote"])

    def test_covers_every_role_crossed_with_every_access_mode(
        self, matrix: dict
    ) -> None:
        from auth_sdk_m8.schemas.base import ApiKeyAccessMode

        seen = {
            (pair["local"]["role"], pair["local"]["access_mode"])
            for pair in matrix["local_remote_principal_equivalence"]
        }
        expected = {
            (role, mode.value) for role in _ALL_ROLES for mode in ApiKeyAccessMode
        }
        # Every (role, access_mode) pair is present: each role has exactly one
        # canonically consistent superuser-flag value, so none is excluded by
        # the truth-table filter in the generator.
        assert seen == expected


class TestAudienceAndCapabilityPolicyMatrix:
    def test_no_audience_never_reaches_remote_active(self, matrix: dict) -> None:
        for row in matrix["audience_and_capability_policy_matrix"]:
            if row["has_audience"] is False:
                assert row["remote_active"] is False
                assert row["remote_allowed"] is False

    def test_remote_allowed_requires_audience_and_local_allowed(
        self, matrix: dict
    ) -> None:
        for row in matrix["audience_and_capability_policy_matrix"]:
            if row["has_audience"] is None:
                continue
            assert row["remote_allowed"] == (
                row["issuer_local_allowed"] and row["has_audience"]
            )

    def test_admin_and_superuser_required_roles_are_ceiling_denied(
        self, matrix: dict
    ) -> None:
        rows = [
            row
            for row in matrix["audience_and_capability_policy_matrix"]
            if row["required_role"] in ("admin", "superadmin")
        ]
        assert len(rows) == 2
        for row in rows:
            assert row["capability_ceiling_error"] is True
            assert row["issuer_local_allowed"] is False
            assert row["remote_allowed"] is False

    def test_read_only_access_mode_never_allows_writer_capability(
        self, matrix: dict
    ) -> None:
        for row in matrix["audience_and_capability_policy_matrix"]:
            if row["access_mode"] == "read_only" and row["required_role"] == "writer":
                assert row["issuer_local_allowed"] is False


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
