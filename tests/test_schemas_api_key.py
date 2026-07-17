"""Tests for auth_sdk_m8.schemas.api_key — the API-key principal contract.

Covers the exact minimized wire shapes, the one canonical principal both the
issuer-local and remote paths return, raw-key redaction, and the fail-closed
schema-version handling.
"""

from datetime import datetime, timezone

import pytest
from pydantic import BaseModel, SecretStr, TypeAdapter, ValidationError

from auth_sdk_m8.authorization import (
    has_api_key_capability,
    has_minimum_role,
    has_superuser_privileges,
)
from auth_sdk_m8.core.exceptions import (
    ApiKeyCapabilityCeilingError,
    InconsistentPrivilegeClaimsError,
    UnsupportedApiKeySchemaVersionError,
)
from auth_sdk_m8.schemas.api_key import (
    API_KEY_AUTHENTICATION_METHOD,
    API_KEY_INTROSPECTION_SCHEMA_VERSION,
    SUPPORTED_API_KEY_INTROSPECTION_SCHEMA_VERSIONS,
    UNSUPPORTED_API_KEY_SCHEMA_VERSION_REASON,
    ApiKeyIntrospectionActiveResponse,
    ApiKeyIntrospectionInactiveResponse,
    ApiKeyIntrospectionRequest,
    ApiKeyIntrospectionResponse,
    ApiKeyPrincipal,
    validate_api_key_introspection_schema_version,
)
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType

RAW_KEY = "ak_0123456789abcdef0123456789abcdef"
_RESPONSE_ADAPTER: TypeAdapter[ApiKeyIntrospectionResponse] = TypeAdapter(
    ApiKeyIntrospectionResponse
)

_ALL_ROLES = list(RoleType)
_VALID_PAIRS = [(role, role == RoleType.SUPERADMIN) for role in _ALL_ROLES]
_INVALID_PAIRS = [(role, role != RoleType.SUPERADMIN) for role in _ALL_ROLES]


def _principal(**overrides: object) -> ApiKeyPrincipal:
    payload: dict[str, object] = {
        "user_id": "3f1b0e8a-0000-4000-8000-000000000001",
        "role": RoleType.WRITER,
        "is_superuser": False,
        "access_mode": ApiKeyAccessMode.READ_WRITE,
        "auth_generation": 7,
    }
    payload.update(overrides)
    return ApiKeyPrincipal(**payload)  # type: ignore[arg-type]


# ── module constants ─────────────────────────────────────────────────────────


def test_schema_version_constant() -> None:
    assert API_KEY_INTROSPECTION_SCHEMA_VERSION == "1"


def test_supported_versions_contains_the_current_version() -> None:
    assert API_KEY_INTROSPECTION_SCHEMA_VERSION in (
        SUPPORTED_API_KEY_INTROSPECTION_SCHEMA_VERSIONS
    )


def test_authentication_method_constant() -> None:
    assert API_KEY_AUTHENTICATION_METHOD == "api_key"


def test_access_mode_values() -> None:
    assert ApiKeyAccessMode.READ_ONLY == "read_only"
    assert ApiKeyAccessMode.READ_WRITE == "read_write"
    assert len(list(ApiKeyAccessMode)) == 2


# ── schema-version fail-closed ───────────────────────────────────────────────


class TestValidateSchemaVersion:
    def test_supported_version_does_not_raise(self) -> None:
        validate_api_key_introspection_schema_version(
            API_KEY_INTROSPECTION_SCHEMA_VERSION
        )

    @pytest.mark.parametrize("version", ["2", "0", "", "1.0", "v1", "latest"])
    def test_unknown_version_raises(self, version: str) -> None:
        with pytest.raises(UnsupportedApiKeySchemaVersionError) as exc_info:
            validate_api_key_introspection_schema_version(version)
        assert str(exc_info.value) == UNSUPPORTED_API_KEY_SCHEMA_VERSION_REASON

    def test_error_message_is_bounded_reason_only(self) -> None:
        with pytest.raises(UnsupportedApiKeySchemaVersionError) as exc_info:
            validate_api_key_introspection_schema_version("99-secret-ish")
        message = str(exc_info.value)
        assert message == "unsupported_api_key_schema_version"
        # The rejected payload value never travels with the error.
        assert "99-secret-ish" not in message


# ── ApiKeyPrincipal ──────────────────────────────────────────────────────────


class TestApiKeyPrincipalShape:
    def test_minimized_field_set(self) -> None:
        # No is_active, key hash, key id, email, or rejection reason: an active
        # principal is by definition an existing, active, canonical owner.
        assert set(ApiKeyPrincipal.model_fields) == {
            "user_id",
            "role",
            "is_superuser",
            "access_mode",
            "authentication_method",
            "auth_generation",
        }

    def test_serialises_to_the_contract_shape(self) -> None:
        principal = _principal()

        assert principal.model_dump(mode="json") == {
            "user_id": "3f1b0e8a-0000-4000-8000-000000000001",
            "role": "writer",
            "is_superuser": False,
            "access_mode": "read_write",
            "authentication_method": "api_key",
            "auth_generation": 7,
        }

    def test_authentication_method_defaults_to_api_key(self) -> None:
        assert _principal().authentication_method == API_KEY_AUTHENTICATION_METHOD

    def test_authentication_method_cannot_be_another_method(self) -> None:
        with pytest.raises(ValidationError):
            _principal(authentication_method="jwt")

    def test_parses_from_the_wire_payload(self) -> None:
        principal = ApiKeyPrincipal.model_validate(
            {
                "user_id": "u-1",
                "role": "reader",
                "is_superuser": False,
                "access_mode": "read_only",
                "authentication_method": "api_key",
                "auth_generation": 1,
            }
        )

        assert principal.role is RoleType.READER
        assert principal.access_mode is ApiKeyAccessMode.READ_ONLY

    def test_rejects_an_empty_user_id(self) -> None:
        with pytest.raises(ValidationError):
            _principal(user_id="")

    def test_requires_an_access_mode(self) -> None:
        # The cap is never implied; a principal without one cannot exist.
        with pytest.raises(ValidationError):
            ApiKeyPrincipal(user_id="u-1", role=RoleType.READER, auth_generation=1)  # type: ignore[call-arg]

    @pytest.mark.parametrize("generation", [0, -1])
    def test_rejects_a_non_positive_generation(self, generation: int) -> None:
        # Generations start at 1; a missing/legacy generation means revoked and
        # must never be representable as an active principal.
        with pytest.raises(ValidationError):
            _principal(auth_generation=generation)

    def test_accepts_a_large_generation(self) -> None:
        assert _principal(auth_generation=2**62).auth_generation == 2**62


class TestApiKeyPrincipalClaimInvariant:
    @pytest.mark.parametrize("role,is_superuser", _VALID_PAIRS)
    def test_canonical_pairs_are_accepted(
        self, role: RoleType, is_superuser: bool
    ) -> None:
        assert _principal(role=role, is_superuser=is_superuser).role is role

    @pytest.mark.parametrize("role,is_superuser", _INVALID_PAIRS)
    def test_inconsistent_pairs_are_rejected(
        self, role: RoleType, is_superuser: bool
    ) -> None:
        # An inconsistent owner is never representable as a principal — the
        # issuer answers active:false for one instead.
        with pytest.raises(ValidationError) as exc_info:
            _principal(role=role, is_superuser=is_superuser)

        causes = [
            (detail.get("ctx") or {}).get("error")
            for detail in exc_info.value.errors(include_url=False, include_context=True)
        ]
        assert any(
            isinstance(cause, InconsistentPrivilegeClaimsError) for cause in causes
        )


class TestApiKeyPrincipalPredicates:
    def test_has_capability_matches_the_shared_predicate(self) -> None:
        for role, is_superuser in _VALID_PAIRS:
            for access_mode in ApiKeyAccessMode:
                for required_role in (RoleType.WRITER, RoleType.READER, RoleType.USER):
                    principal = _principal(
                        role=role, is_superuser=is_superuser, access_mode=access_mode
                    )
                    assert principal.has_capability(required_role) == (
                        has_api_key_capability(
                            role, is_superuser, access_mode, required_role
                        )
                    )

    def test_has_capability_rejects_a_requirement_above_the_ceiling(self) -> None:
        principal = _principal(role=RoleType.SUPERADMIN, is_superuser=True)

        for required_role in (RoleType.ADMIN, RoleType.SUPERADMIN):
            with pytest.raises(ApiKeyCapabilityCeilingError):
                principal.has_capability(required_role)

    def test_has_minimum_role_reports_the_owner_standing(self) -> None:
        for role, is_superuser in _VALID_PAIRS:
            principal = _principal(role=role, is_superuser=is_superuser)
            for required_role in _ALL_ROLES:
                assert principal.has_minimum_role(required_role) == (
                    has_minimum_role(role, required_role)
                )

    def test_has_minimum_role_ignores_the_access_mode_cap(self) -> None:
        # It reports the owner's role only — capability is has_capability().
        principal = _principal(access_mode=ApiKeyAccessMode.READ_ONLY)

        assert principal.has_minimum_role(RoleType.WRITER) is True
        assert principal.has_capability(RoleType.WRITER) is False

    def test_owner_has_superuser_privileges_reuses_the_shared_predicate(self) -> None:
        for role, is_superuser in _VALID_PAIRS:
            principal = _principal(role=role, is_superuser=is_superuser)
            assert principal.owner_has_superuser_privileges() == (
                has_superuser_privileges(role, is_superuser)
            )

    def test_superuser_owner_still_gets_no_superuser_capability(self) -> None:
        # The flag is evidence about the owner record, never authority here.
        principal = _principal(role=RoleType.SUPERADMIN, is_superuser=True)

        assert principal.owner_has_superuser_privileges() is True
        with pytest.raises(ApiKeyCapabilityCeilingError):
            principal.has_capability(RoleType.SUPERADMIN)


# ── ApiKeyIntrospectionRequest ───────────────────────────────────────────────


class TestApiKeyIntrospectionRequest:
    def test_holds_the_raw_key_as_a_secret(self) -> None:
        request = ApiKeyIntrospectionRequest(api_key=SecretStr(RAW_KEY))

        assert isinstance(request.api_key, SecretStr)
        assert request.api_key.get_secret_value() == RAW_KEY

    def test_schema_version_defaults_to_the_current_version(self) -> None:
        request = ApiKeyIntrospectionRequest(api_key=SecretStr(RAW_KEY))

        assert request.schema_version == API_KEY_INTROSPECTION_SCHEMA_VERSION

    def test_raw_key_is_masked_in_repr_and_str(self) -> None:
        request = ApiKeyIntrospectionRequest(api_key=SecretStr(RAW_KEY))

        assert RAW_KEY not in repr(request)
        assert RAW_KEY not in str(request)
        assert RAW_KEY not in repr(request.api_key)

    def test_raw_key_is_masked_in_generic_serialisation(self) -> None:
        # Generic serialisation is the accidental path: it must never carry the
        # credential. The transport unwraps it deliberately at the boundary.
        request = ApiKeyIntrospectionRequest(api_key=SecretStr(RAW_KEY))

        assert RAW_KEY not in request.model_dump_json()
        assert RAW_KEY not in str(request.model_dump())
        assert RAW_KEY not in str(request.model_dump(mode="json"))

    def test_raw_key_is_masked_when_nested_in_another_model(self) -> None:
        class _Envelope(BaseModel):
            request: ApiKeyIntrospectionRequest

        envelope = _Envelope(request=ApiKeyIntrospectionRequest(api_key=RAW_KEY))

        assert RAW_KEY not in envelope.model_dump_json()
        assert RAW_KEY not in repr(envelope)

    def test_raw_key_is_masked_in_a_validation_error(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyIntrospectionRequest(api_key=RAW_KEY, schema_version=object())  # type: ignore[arg-type]

        assert RAW_KEY not in str(exc_info.value)

    def test_unknown_schema_version_is_left_to_the_issuer(self) -> None:
        # Parsing must not raise: the endpoint answers 503 for a version it
        # does not implement, rather than a schema error.
        request = ApiKeyIntrospectionRequest(api_key=RAW_KEY, schema_version="99")

        assert request.schema_version == "99"
        with pytest.raises(UnsupportedApiKeySchemaVersionError):
            validate_api_key_introspection_schema_version(request.schema_version)

    def test_rejects_a_client_supplied_hash_field(self) -> None:
        # A client-generated hash is bearer-equivalent and never accepted; the
        # model has no field for one.
        assert set(ApiKeyIntrospectionRequest.model_fields) == {
            "api_key",
            "schema_version",
        }


# ── introspection responses ──────────────────────────────────────────────────


class TestInactiveResponse:
    def test_is_the_generic_shape(self) -> None:
        response = ApiKeyIntrospectionInactiveResponse()

        assert response.active is False
        assert response.model_dump(mode="json") == {
            "active": False,
            "schema_version": "1",
        }

    def test_active_cannot_be_true(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyIntrospectionInactiveResponse(active=True)  # type: ignore[arg-type]

    def test_carries_no_reason_or_owner_state(self) -> None:
        # Every inactive cause — unknown/revoked/expired key, missing/inactive/
        # tombstoned/inconsistent owner, wrong audience — is one shape, so a
        # caller cannot probe another account's state.
        assert set(ApiKeyIntrospectionInactiveResponse.model_fields) == {
            "active",
            "schema_version",
        }


class TestActiveResponse:
    def test_serialises_to_the_contract_shape(self) -> None:
        response = ApiKeyIntrospectionActiveResponse(
            audience_id="prompt-engine-m8",
            principal=_principal(),
            key_expires_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )

        assert response.model_dump(mode="json") == {
            "active": True,
            "schema_version": "1",
            "audience_id": "prompt-engine-m8",
            "principal": {
                "user_id": "3f1b0e8a-0000-4000-8000-000000000001",
                "role": "writer",
                "is_superuser": False,
                "access_mode": "read_write",
                "authentication_method": "api_key",
                "auth_generation": 7,
            },
            "key_expires_at": "2026-08-01T00:00:00Z",
        }

    def test_exposes_no_owner_or_key_detail(self) -> None:
        assert set(ApiKeyIntrospectionActiveResponse.model_fields) == {
            "active",
            "schema_version",
            "audience_id",
            "principal",
            "key_expires_at",
        }

    def test_active_cannot_be_false(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyIntrospectionActiveResponse(
                active=False,  # type: ignore[arg-type]
                audience_id="prompt-engine-m8",
                principal=_principal(),
            )

    def test_audience_id_is_required_and_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyIntrospectionActiveResponse(audience_id="", principal=_principal())
        with pytest.raises(ValidationError):
            ApiKeyIntrospectionActiveResponse(principal=_principal())  # type: ignore[call-arg]

    def test_a_never_expiring_key_reports_no_expiry(self) -> None:
        response = ApiKeyIntrospectionActiveResponse(
            audience_id="prompt-engine-m8", principal=_principal()
        )

        assert response.key_expires_at is None

    def test_inconsistent_principal_is_rejected_through_the_response(self) -> None:
        with pytest.raises(ValidationError):
            ApiKeyIntrospectionActiveResponse.model_validate(
                {
                    "active": True,
                    "schema_version": "1",
                    "audience_id": "prompt-engine-m8",
                    "principal": {
                        "user_id": "u-1",
                        "role": "reader",
                        "is_superuser": True,
                        "access_mode": "read_only",
                        "auth_generation": 1,
                    },
                }
            )


class TestResponseSchemaVersionFailsClosed:
    def test_active_response_rejects_an_unknown_version(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyIntrospectionActiveResponse(
                schema_version="2",
                audience_id="prompt-engine-m8",
                principal=_principal(),
            )

        assert _version_error_in(exc_info.value) is not None

    def test_inactive_response_rejects_an_unknown_version(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ApiKeyIntrospectionInactiveResponse(schema_version="2")

        assert _version_error_in(exc_info.value) is not None

    def test_a_supported_version_is_accepted(self) -> None:
        assert ApiKeyIntrospectionInactiveResponse(schema_version="1").active is False


def _version_error_in(error: ValidationError) -> object | None:
    for detail in error.errors(include_url=False, include_context=True):
        cause = (detail.get("ctx") or {}).get("error")
        if isinstance(cause, UnsupportedApiKeySchemaVersionError):
            return cause
    return None


class TestResponseUnion:
    def test_active_payload_parses_as_the_active_shape(self) -> None:
        parsed = _RESPONSE_ADAPTER.validate_python(
            {
                "active": True,
                "schema_version": "1",
                "audience_id": "prompt-engine-m8",
                "principal": _principal().model_dump(mode="json"),
                "key_expires_at": "2026-08-01T00:00:00Z",
            }
        )

        assert isinstance(parsed, ApiKeyIntrospectionActiveResponse)
        assert parsed.principal.has_capability(RoleType.WRITER) is True

    def test_inactive_payload_parses_as_the_inactive_shape(self) -> None:
        parsed = _RESPONSE_ADAPTER.validate_python(
            {"active": False, "schema_version": "1"}
        )

        assert isinstance(parsed, ApiKeyIntrospectionInactiveResponse)

    def test_payload_without_the_discriminator_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _RESPONSE_ADAPTER.validate_python({"schema_version": "1"})

    def test_unknown_version_fails_closed_through_the_union(self) -> None:
        with pytest.raises(ValidationError):
            _RESPONSE_ADAPTER.validate_python({"active": False, "schema_version": "2"})


# ── local/remote equivalence ─────────────────────────────────────────────────


class TestOneCanonicalPrincipal:
    def test_local_and_remote_paths_yield_the_same_principal_type(self) -> None:
        # The issuer builds the principal from its own database read; a
        # consumer parses it out of the introspection response. Both are the
        # same type, so the two halves of the rule cannot drift.
        local = _principal(role=RoleType.WRITER, access_mode=ApiKeyAccessMode.READ_ONLY)
        remote = _RESPONSE_ADAPTER.validate_python(
            {
                "active": True,
                "schema_version": "1",
                "audience_id": "prompt-engine-m8",
                "principal": local.model_dump(mode="json"),
            }
        )

        assert isinstance(remote, ApiKeyIntrospectionActiveResponse)
        assert type(remote.principal) is type(local)
        assert remote.principal == local

    def test_local_and_remote_decisions_match_for_every_pair(self) -> None:
        for role, is_superuser in _VALID_PAIRS:
            for access_mode in ApiKeyAccessMode:
                local = _principal(
                    role=role, is_superuser=is_superuser, access_mode=access_mode
                )
                remote = ApiKeyIntrospectionActiveResponse.model_validate(
                    {
                        "active": True,
                        "schema_version": "1",
                        "audience_id": "prompt-engine-m8",
                        "principal": local.model_dump(mode="json"),
                    }
                ).principal

                for required_role in (RoleType.WRITER, RoleType.READER, RoleType.USER):
                    assert local.has_capability(required_role) == (
                        remote.has_capability(required_role)
                    )


# ── public package surface ───────────────────────────────────────────────────


class TestPublicPackageSurface:
    def test_contract_re_exported_from_package_root(self) -> None:
        import auth_sdk_m8

        assert auth_sdk_m8.ApiKeyPrincipal is ApiKeyPrincipal
        assert auth_sdk_m8.ApiKeyIntrospectionRequest is ApiKeyIntrospectionRequest
        assert (
            auth_sdk_m8.ApiKeyIntrospectionActiveResponse
            is ApiKeyIntrospectionActiveResponse
        )
        assert (
            auth_sdk_m8.ApiKeyIntrospectionInactiveResponse
            is ApiKeyIntrospectionInactiveResponse
        )
        assert auth_sdk_m8.ApiKeyAccessMode is ApiKeyAccessMode
        assert (
            auth_sdk_m8.UnsupportedApiKeySchemaVersionError
            is UnsupportedApiKeySchemaVersionError
        )
        assert (
            auth_sdk_m8.validate_api_key_introspection_schema_version
            is validate_api_key_introspection_schema_version
        )
        assert (
            auth_sdk_m8.API_KEY_INTROSPECTION_SCHEMA_VERSION
            == API_KEY_INTROSPECTION_SCHEMA_VERSION
        )
        assert (
            auth_sdk_m8.SUPPORTED_API_KEY_INTROSPECTION_SCHEMA_VERSIONS
            == SUPPORTED_API_KEY_INTROSPECTION_SCHEMA_VERSIONS
        )
        assert (
            auth_sdk_m8.UNSUPPORTED_API_KEY_SCHEMA_VERSION_REASON
            == UNSUPPORTED_API_KEY_SCHEMA_VERSION_REASON
        )
        assert (
            auth_sdk_m8.API_KEY_AUTHENTICATION_METHOD == API_KEY_AUTHENTICATION_METHOD
        )

    def test_all_exports_present_in_dunder_all(self) -> None:
        import auth_sdk_m8

        for name in (
            "ApiKeyAccessMode",
            "ApiKeyIntrospectionActiveResponse",
            "ApiKeyIntrospectionInactiveResponse",
            "ApiKeyIntrospectionRequest",
            "ApiKeyIntrospectionResponse",
            "ApiKeyPrincipal",
            "UnsupportedApiKeySchemaVersionError",
            "validate_api_key_introspection_schema_version",
            "API_KEY_AUTHENTICATION_METHOD",
            "API_KEY_INTROSPECTION_SCHEMA_VERSION",
            "SUPPORTED_API_KEY_INTROSPECTION_SCHEMA_VERSIONS",
            "UNSUPPORTED_API_KEY_SCHEMA_VERSION_REASON",
        ):
            assert name in auth_sdk_m8.__all__

    def test_response_union_is_exported(self) -> None:
        import auth_sdk_m8

        assert auth_sdk_m8.ApiKeyIntrospectionResponse == ApiKeyIntrospectionResponse

    def test_sdk_ships_no_http_transport_for_the_call(self) -> None:
        # The introspection client lives in fastapi-m8, mirroring the
        # JTI-status precedent; the SDK owns only the contract shapes.
        import auth_sdk_m8.schemas.api_key as module

        source = module.__file__
        assert source is not None
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        assert "httpx" not in text
        assert "import requests" not in text
