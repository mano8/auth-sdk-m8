"""Property-based (Hypothesis) coverage of the pure authorization predicates.

Complements the fixed-matrix tests in ``test_authorization.py`` with
generated coverage of every role/flag pair, every current/required-role pair,
and unknown/malformed role inputs (§6 auth-sdk-m8 verification plan) — so the
invariant is proven against the space of inputs, not only the cases someone
thought to enumerate by hand.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from auth_sdk_m8.authorization import (
    api_key_capability_requires_write,
    has_api_key_capability,
    has_minimum_role,
    has_superuser_privileges,
    privilege_claims_are_consistent,
)
from auth_sdk_m8.core.exceptions import ApiKeyCapabilityCeilingError
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType

_roles = st.sampled_from(list(RoleType))
_flags = st.booleans()
_access_modes = st.sampled_from(list(ApiKeyAccessMode))
_api_key_roles = st.sampled_from([RoleType.WRITER, RoleType.READER, RoleType.USER])

#: A role-shaped object that is not a real RoleType member, for the
#: unknown/malformed-input branch of has_minimum_role.
_malformed_roles = st.builds(
    lambda value: type("_FakeRole", (), {"value": value})(),
    st.text(min_size=1, max_size=20).filter(
        lambda s: s not in {r.value for r in RoleType}
    ),
)


class TestHasMinimumRoleProperties:
    @given(role=_roles)
    def test_reflexive_for_every_real_role(self, role: RoleType) -> None:
        assert has_minimum_role(role, role) is True

    @given(current=_roles, required=_roles)
    def test_matches_ordered_index_comparison(
        self, current: RoleType, required: RoleType
    ) -> None:
        ordered = RoleType.get_ordered_roles()
        expected = ordered.index(current.value) <= ordered.index(required.value)
        assert has_minimum_role(current, required) is expected

    @given(current=_roles, required=_roles)
    def test_antisymmetric_unless_equal(
        self, current: RoleType, required: RoleType
    ) -> None:
        # Two distinct roles can never satisfy each other in both directions.
        if current != required:
            assert not (
                has_minimum_role(current, required)
                and has_minimum_role(required, current)
            )

    @given(role=_malformed_roles, other=_roles)
    def test_malformed_current_role_never_raises_and_returns_false(
        self, role: Any, other: RoleType
    ) -> None:
        assert has_minimum_role(role, other) is False

    @given(role=_malformed_roles, other=_roles)
    def test_malformed_required_role_never_raises_and_returns_false(
        self, role: Any, other: RoleType
    ) -> None:
        assert has_minimum_role(other, role) is False


class TestPrivilegeClaimsAreConsistentProperties:
    @given(role=_roles, is_superuser=_flags)
    def test_matches_the_truth_table_definition(
        self, role: RoleType, is_superuser: bool
    ) -> None:
        expected = (
            is_superuser is True
            if role == RoleType.SUPERADMIN
            else is_superuser is False
        )
        assert privilege_claims_are_consistent(role, is_superuser) is expected

    @given(role=_roles)
    def test_exactly_one_flag_value_is_consistent_per_role(
        self, role: RoleType
    ) -> None:
        assert privilege_claims_are_consistent(
            role, True
        ) != privilege_claims_are_consistent(role, False)


class TestHasSuperuserPrivilegesProperties:
    @given(role=_roles, is_superuser=_flags)
    def test_implies_consistency(self, role: RoleType, is_superuser: bool) -> None:
        if has_superuser_privileges(role, is_superuser):
            assert privilege_claims_are_consistent(role, is_superuser)

    @given(role=_roles, is_superuser=_flags)
    def test_true_only_for_canonical_superadmin(
        self, role: RoleType, is_superuser: bool
    ) -> None:
        expected = role == RoleType.SUPERADMIN and is_superuser is True
        assert has_superuser_privileges(role, is_superuser) is expected

    @given(role=_roles)
    def test_flag_alone_never_grants_privileges_for_non_superadmin(
        self, role: RoleType
    ) -> None:
        if role != RoleType.SUPERADMIN:
            assert has_superuser_privileges(role, True) is False


class TestHasApiKeyCapabilityProperties:
    @given(
        role=_roles,
        is_superuser=_flags,
        access_mode=_access_modes,
        required_role=_api_key_roles,
    )
    def test_matches_the_intersection_of_narrowing_dimensions(
        self,
        role: RoleType,
        is_superuser: bool,
        access_mode: ApiKeyAccessMode,
        required_role: RoleType,
    ) -> None:
        expected = (
            privilege_claims_are_consistent(role, is_superuser)
            and has_minimum_role(role, required_role)
            and (
                not api_key_capability_requires_write(required_role)
                or access_mode == ApiKeyAccessMode.READ_WRITE
            )
        )
        assert (
            has_api_key_capability(role, is_superuser, access_mode, required_role)
            is expected
        )

    @given(
        role=_roles,
        is_superuser=_flags,
        access_mode=_access_modes,
        required_role=st.sampled_from([RoleType.ADMIN, RoleType.SUPERADMIN]),
    )
    def test_above_ceiling_requirement_always_raises(
        self,
        role: RoleType,
        is_superuser: bool,
        access_mode: ApiKeyAccessMode,
        required_role: RoleType,
    ) -> None:
        with pytest.raises(ApiKeyCapabilityCeilingError):
            has_api_key_capability(role, is_superuser, access_mode, required_role)

    @given(role=_roles, is_superuser=_flags, required_role=_api_key_roles)
    def test_read_only_key_never_grants_write_capability(
        self, role: RoleType, is_superuser: bool, required_role: RoleType
    ) -> None:
        if api_key_capability_requires_write(required_role):
            assert (
                has_api_key_capability(
                    role, is_superuser, ApiKeyAccessMode.READ_ONLY, required_role
                )
                is False
            )
