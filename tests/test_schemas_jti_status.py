"""Tests for auth_sdk_m8.schemas.jti_status — the v2 JTI-status response contract.

Covers the exact minimized wire shapes (active-only ``user_id``/
``auth_generation``, one generic inactive shape) and the fail-closed
schema-version handling.
"""

import pytest
from pydantic import TypeAdapter, ValidationError

from auth_sdk_m8.core.exceptions import UnsupportedJtiStatusSchemaVersionError
from auth_sdk_m8.schemas.jti_status import (
    JTI_STATUS_SCHEMA_VERSION,
    SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS,
    UNSUPPORTED_JTI_STATUS_SCHEMA_VERSION_REASON,
    JtiStatusActiveResponse,
    JtiStatusInactiveResponse,
    JtiStatusResponse,
    validate_jti_status_schema_version,
)

_RESPONSE_ADAPTER: TypeAdapter[JtiStatusResponse] = TypeAdapter(JtiStatusResponse)


# ── module constants ─────────────────────────────────────────────────────────


def test_schema_version_constant() -> None:
    assert JTI_STATUS_SCHEMA_VERSION == "2"


def test_supported_versions_contains_the_current_version() -> None:
    assert JTI_STATUS_SCHEMA_VERSION in SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS


def test_v1_is_not_a_supported_v2_version() -> None:
    # The legacy v1 response has no schema_version field at all; it is not a
    # member of the v2-only supported set.
    assert "1" not in SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS


# ── schema-version fail-closed ───────────────────────────────────────────────


class TestValidateSchemaVersion:
    def test_supported_version_does_not_raise(self) -> None:
        validate_jti_status_schema_version(JTI_STATUS_SCHEMA_VERSION)

    @pytest.mark.parametrize("version", ["1", "3", "0", "", "2.0", "v2", "latest"])
    def test_unknown_version_raises(self, version: str) -> None:
        with pytest.raises(UnsupportedJtiStatusSchemaVersionError) as exc_info:
            validate_jti_status_schema_version(version)
        assert str(exc_info.value) == UNSUPPORTED_JTI_STATUS_SCHEMA_VERSION_REASON

    def test_error_message_is_bounded_reason_only(self) -> None:
        with pytest.raises(UnsupportedJtiStatusSchemaVersionError) as exc_info:
            validate_jti_status_schema_version("99-secret-ish")
        message = str(exc_info.value)
        assert message == "unsupported_jti_status_schema_version"
        assert "99-secret-ish" not in message


# ── inactive response ────────────────────────────────────────────────────────


class TestInactiveResponse:
    def test_is_the_generic_shape(self) -> None:
        response = JtiStatusInactiveResponse()

        assert response.active is False
        assert response.model_dump(mode="json") == {
            "active": False,
            "schema_version": "2",
        }

    def test_active_cannot_be_true(self) -> None:
        with pytest.raises(ValidationError):
            JtiStatusInactiveResponse(active=True)  # type: ignore[arg-type]

    def test_carries_no_reason_or_subject_state(self) -> None:
        # Never-issued, revoked, expired, tombstoned, subject-mismatched,
        # inconsistent-owner, and stale-generation all collapse to this one
        # shape, so the endpoint cannot be used as an enumeration oracle.
        assert set(JtiStatusInactiveResponse.model_fields) == {
            "active",
            "schema_version",
        }


# ── active response ───────────────────────────────────────────────────────────


class TestActiveResponse:
    def test_serialises_to_the_contract_shape(self) -> None:
        response = JtiStatusActiveResponse(user_id="u-1", auth_generation=7)

        assert response.model_dump(mode="json") == {
            "active": True,
            "schema_version": "2",
            "user_id": "u-1",
            "auth_generation": 7,
        }

    def test_exposes_no_role_privilege_or_pii_beyond_user_id(self) -> None:
        assert set(JtiStatusActiveResponse.model_fields) == {
            "active",
            "schema_version",
            "user_id",
            "auth_generation",
        }

    def test_active_cannot_be_false(self) -> None:
        with pytest.raises(ValidationError):
            JtiStatusActiveResponse(
                active=False,  # type: ignore[arg-type]
                user_id="u-1",
                auth_generation=1,
            )

    def test_rejects_an_empty_user_id(self) -> None:
        with pytest.raises(ValidationError):
            JtiStatusActiveResponse(user_id="", auth_generation=1)

    def test_user_id_is_required(self) -> None:
        with pytest.raises(ValidationError):
            JtiStatusActiveResponse(auth_generation=1)  # type: ignore[call-arg]

    @pytest.mark.parametrize("generation", [0, -1])
    def test_rejects_a_non_positive_generation(self, generation: int) -> None:
        with pytest.raises(ValidationError):
            JtiStatusActiveResponse(user_id="u-1", auth_generation=generation)

    def test_accepts_a_large_generation(self) -> None:
        response = JtiStatusActiveResponse(user_id="u-1", auth_generation=2**62)

        assert response.auth_generation == 2**62


class TestResponseSchemaVersionFailsClosed:
    def test_active_response_rejects_an_unknown_version(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            JtiStatusActiveResponse(
                schema_version="1", user_id="u-1", auth_generation=1
            )

        assert _version_error_in(exc_info.value) is not None

    def test_inactive_response_rejects_an_unknown_version(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            JtiStatusInactiveResponse(schema_version="1")

        assert _version_error_in(exc_info.value) is not None

    def test_a_supported_version_is_accepted(self) -> None:
        assert JtiStatusInactiveResponse(schema_version="2").active is False


def _version_error_in(error: ValidationError) -> object | None:
    for detail in error.errors(include_url=False, include_context=True):
        cause = (detail.get("ctx") or {}).get("error")
        if isinstance(cause, UnsupportedJtiStatusSchemaVersionError):
            return cause
    return None


class TestResponseUnion:
    def test_active_payload_parses_as_the_active_shape(self) -> None:
        parsed = _RESPONSE_ADAPTER.validate_python(
            {
                "active": True,
                "schema_version": "2",
                "user_id": "u-1",
                "auth_generation": 3,
            }
        )

        assert isinstance(parsed, JtiStatusActiveResponse)
        assert parsed.user_id == "u-1"
        assert parsed.auth_generation == 3

    def test_inactive_payload_parses_as_the_inactive_shape(self) -> None:
        parsed = _RESPONSE_ADAPTER.validate_python(
            {"active": False, "schema_version": "2"}
        )

        assert isinstance(parsed, JtiStatusInactiveResponse)

    def test_payload_without_the_discriminator_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _RESPONSE_ADAPTER.validate_python({"schema_version": "2"})

    def test_unknown_version_fails_closed_through_the_union(self) -> None:
        with pytest.raises(ValidationError):
            _RESPONSE_ADAPTER.validate_python({"active": False, "schema_version": "1"})


# ── public package surface ───────────────────────────────────────────────────


class TestPublicPackageSurface:
    def test_contract_re_exported_from_package_root(self) -> None:
        import auth_sdk_m8

        assert auth_sdk_m8.JtiStatusActiveResponse is JtiStatusActiveResponse
        assert auth_sdk_m8.JtiStatusInactiveResponse is JtiStatusInactiveResponse
        assert (
            auth_sdk_m8.UnsupportedJtiStatusSchemaVersionError
            is UnsupportedJtiStatusSchemaVersionError
        )
        assert (
            auth_sdk_m8.validate_jti_status_schema_version
            is validate_jti_status_schema_version
        )
        assert auth_sdk_m8.JTI_STATUS_SCHEMA_VERSION == JTI_STATUS_SCHEMA_VERSION
        assert (
            auth_sdk_m8.SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS
            == SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS
        )
        assert (
            auth_sdk_m8.UNSUPPORTED_JTI_STATUS_SCHEMA_VERSION_REASON
            == UNSUPPORTED_JTI_STATUS_SCHEMA_VERSION_REASON
        )

    def test_all_exports_present_in_dunder_all(self) -> None:
        import auth_sdk_m8

        for name in (
            "JtiStatusActiveResponse",
            "JtiStatusInactiveResponse",
            "JtiStatusResponse",
            "UnsupportedJtiStatusSchemaVersionError",
            "validate_jti_status_schema_version",
            "JTI_STATUS_SCHEMA_VERSION",
            "SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS",
            "UNSUPPORTED_JTI_STATUS_SCHEMA_VERSION_REASON",
        ):
            assert name in auth_sdk_m8.__all__

    def test_response_union_is_exported(self) -> None:
        import auth_sdk_m8

        assert auth_sdk_m8.JtiStatusResponse == JtiStatusResponse

    def test_sdk_ships_no_http_transport_for_the_call(self) -> None:
        import auth_sdk_m8.schemas.jti_status as module

        source = module.__file__
        assert source is not None
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        assert "httpx" not in text
        assert "import requests" not in text
