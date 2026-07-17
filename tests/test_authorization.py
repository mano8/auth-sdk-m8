"""Tests for auth_sdk_m8.authorization."""

import uuid

import pytest
from pydantic import BaseModel, ValidationError, model_validator

from auth_sdk_m8.authorization import (
    INCONSISTENT_PRIVILEGE_CLAIMS_REASON,
    find_inconsistent_privilege_claims_error,
    has_minimum_role,
    has_superuser_privileges,
    privilege_claims_are_consistent,
    validate_privilege_claims,
)
from auth_sdk_m8.core.exceptions import InconsistentPrivilegeClaimsError
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.user import UserModel

_ALL_ROLES = list(RoleType)

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
        ):
            assert name in auth_sdk_m8.__all__
