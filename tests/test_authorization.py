"""Tests for auth_sdk_m8.authorization."""

import uuid

import pytest
from pydantic import BaseModel, ValidationError, model_validator

from auth_sdk_m8.authorization import (
    API_KEY_CAPABILITY_CEILING_REASON,
    API_KEY_MAX_REQUIRED_ROLE,
    INCONSISTENT_PRIVILEGE_CLAIMS_REASON,
    api_key_capability_requires_write,
    find_inconsistent_privilege_claims_error,
    has_api_key_capability,
    has_minimum_role,
    has_superuser_privileges,
    privilege_claims_are_consistent,
    validate_api_key_required_role,
    validate_privilege_claims,
)
from auth_sdk_m8.core.exceptions import (
    ApiKeyCapabilityCeilingError,
    InconsistentPrivilegeClaimsError,
)
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType
from auth_sdk_m8.schemas.user import UserModel

_ALL_ROLES = list(RoleType)

_API_KEY_ROLES = [RoleType.WRITER, RoleType.READER, RoleType.USER]
_ABOVE_CEILING_ROLES = [RoleType.SUPERADMIN, RoleType.ADMIN]
_ALL_ACCESS_MODES = list(ApiKeyAccessMode)

# The canonical truth table (§3.1): only SUPERADMIN pairs with is_superuser=True.
_VALID_PAIRS = [(role, role == RoleType.SUPERADMIN) for role in _ALL_ROLES]
_INVALID_PAIRS = [(role, not (role == RoleType.SUPERADMIN)) for role in _ALL_ROLES]


class TestHasMinimumRole:
    def test_same_role_satisfies_itself(self) -> None:
        for role in _ALL_ROLES:
            assert has_minimum_role(role, role) is True

    def test_higher_role_satisfies_lower_requirement(self) -> None:
        assert has_minimum_role(RoleType.SUPERADMIN, RoleType.USER) is True
        assert has_minimum_role(RoleType.ADMIN, RoleType.READER) is True
        assert has_minimum_role(RoleType.WRITER, RoleType.USER) is True

    def test_lower_role_does_not_satisfy_higher_requirement(self) -> None:
        assert has_minimum_role(RoleType.USER, RoleType.SUPERADMIN) is False
        assert has_minimum_role(RoleType.READER, RoleType.ADMIN) is False
        assert has_minimum_role(RoleType.USER, RoleType.WRITER) is False

    def test_full_hierarchy_matrix(self) -> None:
        ordered = RoleType.get_ordered_roles()
        for i, current in enumerate(ordered):
            for j, required in enumerate(ordered):
                expected = i <= j
                assert (
                    has_minimum_role(RoleType(current), RoleType(required)) is expected
                )

    def test_unrecognised_role_value_returns_false(self) -> None:
        class _FakeRole:
            value = "not_a_real_role"

        assert has_minimum_role(_FakeRole(), RoleType.USER) is False  # type: ignore[arg-type]
        assert has_minimum_role(RoleType.USER, _FakeRole()) is False  # type: ignore[arg-type]


class TestPrivilegeClaimsAreConsistent:
    @pytest.mark.parametrize("role,is_superuser", _VALID_PAIRS)
    def test_valid_pairs_are_consistent(
        self, role: RoleType, is_superuser: bool
    ) -> None:
        assert privilege_claims_are_consistent(role, is_superuser) is True

    @pytest.mark.parametrize("role,is_superuser", _INVALID_PAIRS)
    def test_invalid_pairs_are_inconsistent(
        self, role: RoleType, is_superuser: bool
    ) -> None:
        assert privilege_claims_are_consistent(role, is_superuser) is False


class TestHasSuperuserPrivileges:
    def test_canonical_superuser_is_privileged(self) -> None:
        assert has_superuser_privileges(RoleType.SUPERADMIN, True) is True

    def test_non_superadmin_roles_never_privileged(self) -> None:
        for role in _ALL_ROLES:
            if role == RoleType.SUPERADMIN:
                continue
            assert has_superuser_privileges(role, False) is False
            assert has_superuser_privileges(role, True) is False

    def test_superadmin_without_flag_is_not_privileged(self) -> None:
        assert has_superuser_privileges(RoleType.SUPERADMIN, False) is False

    def test_flag_alone_never_grants_privileges(self) -> None:
        # is_superuser=True on a non-SUPERADMIN role must never bypass the check.
        for role in _ALL_ROLES:
            if role == RoleType.SUPERADMIN:
                continue
            assert has_superuser_privileges(role, True) is False


class TestValidatePrivilegeClaims:
    @pytest.mark.parametrize("role,is_superuser", _VALID_PAIRS)
    def test_valid_pairs_do_not_raise(self, role: RoleType, is_superuser: bool) -> None:
        validate_privilege_claims(role, is_superuser)

    @pytest.mark.parametrize("role,is_superuser", _INVALID_PAIRS)
    def test_invalid_pairs_raise_typed_error(
        self, role: RoleType, is_superuser: bool
    ) -> None:
        with pytest.raises(InconsistentPrivilegeClaimsError) as exc_info:
            validate_privilege_claims(role, is_superuser)
        assert str(exc_info.value) == INCONSISTENT_PRIVILEGE_CLAIMS_REASON

    def test_error_message_is_bounded_reason_only(self) -> None:
        with pytest.raises(InconsistentPrivilegeClaimsError) as exc_info:
            validate_privilege_claims(RoleType.USER, True)
        message = str(exc_info.value)
        assert message == "inconsistent_privilege_claims"
        # No raw claim values (role/flag) leak into the error message.
        assert "user" not in message
        assert "True" not in message


class TestFindInconsistentPrivilegeClaimsError:
    def test_returns_typed_error_from_model_validation_failure(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            UserModel(id=uuid.uuid4(), email="a@b.com", is_superuser=True)

        found = find_inconsistent_privilege_claims_error(exc_info.value)
        assert isinstance(found, InconsistentPrivilegeClaimsError)
        assert str(found) == INCONSISTENT_PRIVILEGE_CLAIMS_REASON

    def test_returns_none_for_an_unrelated_validation_error(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            UserModel(id=uuid.uuid4(), email="not-an-email")

        assert find_inconsistent_privilege_claims_error(exc_info.value) is None

    def test_returns_none_when_error_has_no_context(self) -> None:
        class _Plain(BaseModel):
            count: int

        with pytest.raises(ValidationError) as exc_info:
            _Plain(count="not-a-number")  # type: ignore[arg-type]

        assert find_inconsistent_privilege_claims_error(exc_info.value) is None

    def test_returns_none_for_another_value_error(self) -> None:
        # A ctx-carrying error of a different type must not be mistaken for one.
        class _Other(BaseModel):
            value: str

            @model_validator(mode="after")
            def _reject(self) -> "_Other":
                raise ValueError("something_else")

        with pytest.raises(ValidationError) as exc_info:
            _Other(value="x")

        assert find_inconsistent_privilege_claims_error(exc_info.value) is None


class TestRoleTypeCompatibility:
    """RoleType.is_valid_role_auth() must keep working through has_minimum_role()."""

    def test_delegates_to_has_minimum_role(self) -> None:
        for current in _ALL_ROLES:
            for required in _ALL_ROLES:
                assert RoleType.is_valid_role_auth(current, required) == (
                    has_minimum_role(current, required)
                )

    def test_still_rejects_unrecognised_role(self) -> None:
        class _FakeRole:
            value = "unknown_role"

        assert (
            RoleType.is_valid_role_auth(_FakeRole(), RoleType.USER) is False  # type: ignore[arg-type]
        )


class TestApiKeyCapabilityRequiresWrite:
    def test_writer_requirement_is_a_write_capability(self) -> None:
        assert api_key_capability_requires_write(RoleType.WRITER) is True

    def test_requirements_below_writer_are_reads(self) -> None:
        assert api_key_capability_requires_write(RoleType.READER) is False
        assert api_key_capability_requires_write(RoleType.USER) is False

    def test_requirements_above_writer_are_writes(self) -> None:
        # Above the API-key ceiling, so unreachable through a key — but the
        # read/write boundary itself must not mislabel them as reads.
        assert api_key_capability_requires_write(RoleType.ADMIN) is True
        assert api_key_capability_requires_write(RoleType.SUPERADMIN) is True


class TestValidateApiKeyRequiredRole:
    def test_ceiling_is_writer(self) -> None:
        assert API_KEY_MAX_REQUIRED_ROLE == RoleType.WRITER

    @pytest.mark.parametrize("required_role", _API_KEY_ROLES)
    def test_roles_at_or_below_the_ceiling_are_accepted(
        self, required_role: RoleType
    ) -> None:
        validate_api_key_required_role(required_role)

    @pytest.mark.parametrize("required_role", _ABOVE_CEILING_ROLES)
    def test_roles_above_the_ceiling_raise(self, required_role: RoleType) -> None:
        with pytest.raises(ApiKeyCapabilityCeilingError) as exc_info:
            validate_api_key_required_role(required_role)
        assert str(exc_info.value) == API_KEY_CAPABILITY_CEILING_REASON

    def test_error_message_is_bounded_reason_only(self) -> None:
        with pytest.raises(ApiKeyCapabilityCeilingError) as exc_info:
            validate_api_key_required_role(RoleType.SUPERADMIN)
        message = str(exc_info.value)
        assert message == "api_key_capability_ceiling"
        assert "superadmin" not in message

    def test_unrecognised_required_role_raises(self) -> None:
        class _FakeRole:
            value = "not_a_real_role"

        # A role the ceiling cannot be compared against is treated as a
        # programming error, never as an unchecked grant.
        with pytest.raises(ApiKeyCapabilityCeilingError):
            validate_api_key_required_role(_FakeRole())  # type: ignore[arg-type]


class TestHasApiKeyCapability:
    def test_full_owner_mode_requirement_matrix(self) -> None:
        for role, is_superuser in _VALID_PAIRS + _INVALID_PAIRS:
            for access_mode in _ALL_ACCESS_MODES:
                for required_role in _API_KEY_ROLES:
                    expected = (
                        privilege_claims_are_consistent(role, is_superuser)
                        and has_minimum_role(role, required_role)
                        and (
                            not api_key_capability_requires_write(required_role)
                            or access_mode == ApiKeyAccessMode.READ_WRITE
                        )
                    )
                    assert (
                        has_api_key_capability(
                            role, is_superuser, access_mode, required_role
                        )
                        is expected
                    )

    def test_read_write_key_of_a_writer_owner_may_write(self) -> None:
        assert (
            has_api_key_capability(
                RoleType.WRITER, False, ApiKeyAccessMode.READ_WRITE, RoleType.WRITER
            )
            is True
        )

    def test_read_only_key_of_a_writer_owner_may_not_write(self) -> None:
        # The key's immutable cap narrows an owner who is otherwise authorized.
        assert (
            has_api_key_capability(
                RoleType.WRITER, False, ApiKeyAccessMode.READ_ONLY, RoleType.WRITER
            )
            is False
        )

    def test_read_only_key_of_a_writer_owner_may_still_read(self) -> None:
        assert (
            has_api_key_capability(
                RoleType.WRITER, False, ApiKeyAccessMode.READ_ONLY, RoleType.READER
            )
            is True
        )

    def test_read_write_key_of_a_reader_owner_may_not_write(self) -> None:
        # The access mode never widens: the owner's live role is the ceiling.
        assert (
            has_api_key_capability(
                RoleType.READER, False, ApiKeyAccessMode.READ_WRITE, RoleType.WRITER
            )
            is False
        )

    def test_writer_to_reader_downgrade_denies_the_write_capability(self) -> None:
        # The same key evaluated against the owner's new role: authority is
        # read live, so a downgrade takes effect on the next request.
        for role, expected in ((RoleType.WRITER, True), (RoleType.READER, False)):
            assert (
                has_api_key_capability(
                    role, False, ApiKeyAccessMode.READ_WRITE, RoleType.WRITER
                )
                is expected
            )

    @pytest.mark.parametrize("access_mode", _ALL_ACCESS_MODES)
    @pytest.mark.parametrize("required_role", _ABOVE_CEILING_ROLES)
    def test_administrative_capability_is_never_granted(
        self, required_role: RoleType, access_mode: ApiKeyAccessMode
    ) -> None:
        # Not even to a canonical superuser owner with an unrestricted key.
        with pytest.raises(ApiKeyCapabilityCeilingError):
            has_api_key_capability(
                RoleType.SUPERADMIN, True, access_mode, required_role
            )

    def test_superuser_owner_gets_no_more_than_writer_capability(self) -> None:
        # An owner's SUPERADMIN role grants an API-key request nothing beyond
        # writer-level user-domain capability.
        assert (
            has_api_key_capability(
                RoleType.SUPERADMIN, True, ApiKeyAccessMode.READ_WRITE, RoleType.WRITER
            )
            is True
        )
        with pytest.raises(ApiKeyCapabilityCeilingError):
            has_api_key_capability(
                RoleType.SUPERADMIN, True, ApiKeyAccessMode.READ_WRITE, RoleType.ADMIN
            )

    @pytest.mark.parametrize("role,is_superuser", _INVALID_PAIRS)
    def test_inconsistent_owner_claims_grant_nothing(
        self, role: RoleType, is_superuser: bool
    ) -> None:
        assert (
            has_api_key_capability(
                role, is_superuser, ApiKeyAccessMode.READ_WRITE, RoleType.USER
            )
            is False
        )

    def test_flag_alone_never_grants_capability(self) -> None:
        # is_superuser=true on a READER owner must not reach writer capability.
        assert (
            has_api_key_capability(
                RoleType.READER, True, ApiKeyAccessMode.READ_WRITE, RoleType.WRITER
            )
            is False
        )


class TestPublicPackageSurface:
    def test_helpers_re_exported_from_package_root(self) -> None:
        import auth_sdk_m8

        assert auth_sdk_m8.has_minimum_role is has_minimum_role
        assert auth_sdk_m8.has_superuser_privileges is has_superuser_privileges
        assert (
            auth_sdk_m8.privilege_claims_are_consistent
            is privilege_claims_are_consistent
        )
        assert auth_sdk_m8.validate_privilege_claims is validate_privilege_claims
        assert (
            auth_sdk_m8.find_inconsistent_privilege_claims_error
            is find_inconsistent_privilege_claims_error
        )
        assert (
            auth_sdk_m8.INCONSISTENT_PRIVILEGE_CLAIMS_REASON
            == INCONSISTENT_PRIVILEGE_CLAIMS_REASON
        )
        assert (
            auth_sdk_m8.InconsistentPrivilegeClaimsError
            is InconsistentPrivilegeClaimsError
        )

    def test_api_key_helpers_re_exported_from_package_root(self) -> None:
        import auth_sdk_m8

        assert auth_sdk_m8.has_api_key_capability is has_api_key_capability
        assert (
            auth_sdk_m8.api_key_capability_requires_write
            is api_key_capability_requires_write
        )
        assert (
            auth_sdk_m8.validate_api_key_required_role is validate_api_key_required_role
        )
        assert auth_sdk_m8.API_KEY_MAX_REQUIRED_ROLE == API_KEY_MAX_REQUIRED_ROLE
        assert (
            auth_sdk_m8.API_KEY_CAPABILITY_CEILING_REASON
            == API_KEY_CAPABILITY_CEILING_REASON
        )
        assert auth_sdk_m8.ApiKeyCapabilityCeilingError is ApiKeyCapabilityCeilingError

    def test_all_exports_present_in_dunder_all(self) -> None:
        import auth_sdk_m8

        for name in (
            "has_minimum_role",
            "has_superuser_privileges",
            "privilege_claims_are_consistent",
            "validate_privilege_claims",
            "find_inconsistent_privilege_claims_error",
            "INCONSISTENT_PRIVILEGE_CLAIMS_REASON",
            "InconsistentPrivilegeClaimsError",
            "has_api_key_capability",
            "api_key_capability_requires_write",
            "validate_api_key_required_role",
            "API_KEY_MAX_REQUIRED_ROLE",
            "API_KEY_CAPABILITY_CEILING_REASON",
            "ApiKeyCapabilityCeilingError",
        ):
            assert name in auth_sdk_m8.__all__
