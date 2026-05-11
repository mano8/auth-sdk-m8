"""Tests for auth_sdk_m8.schemas.base."""

from auth_sdk_m8.schemas.base import (
    AuthProviderType,
    Period,
    ResponseError,
    ResponseErrorBase,
    ResponseMessage,
    ResponseModelBase,
    RoleType,
)


def test_auth_provider_type_values() -> None:
    assert AuthProviderType.PASSWORD == "password"
    assert AuthProviderType.GOOGLE == "google"


def test_role_type_values() -> None:
    assert RoleType.SUPERADMIN == "superadmin"
    assert RoleType.ADMIN == "admin"
    assert RoleType.WRITER == "writer"
    assert RoleType.READER == "reader"
    assert RoleType.USER == "user"


def test_role_type_get_ordered_roles() -> None:
    ordered = RoleType.get_ordered_roles()
    assert ordered == ["superadmin", "admin", "writer", "reader", "user"]


def test_role_type_is_valid_role_auth_true() -> None:
    # superadmin has higher privilege than user
    assert RoleType.is_valid_role_auth(RoleType.SUPERADMIN, RoleType.USER) is True
    # same role
    assert RoleType.is_valid_role_auth(RoleType.USER, RoleType.USER) is True


def test_role_type_is_valid_role_auth_false() -> None:
    # user does NOT have superadmin privilege
    assert RoleType.is_valid_role_auth(RoleType.USER, RoleType.SUPERADMIN) is False


def test_role_type_is_valid_role_auth_invalid_value() -> None:
    class _FakeRole:
        value = "unknown_role"

    assert RoleType.is_valid_role_auth(_FakeRole(), RoleType.USER) is False  # type: ignore[arg-type]


def test_period_values() -> None:
    assert Period.MINUTE == "minute"
    assert Period.HOUR == "hour"
    assert Period.DAY == "day"


def test_response_error_defaults() -> None:
    err = ResponseError()
    assert err.table is None
    assert err.field_name is None
    assert err.error is None


def test_response_error_with_values() -> None:
    err = ResponseError(table="users", field_name="email", error="Duplicate")
    assert err.table == "users"
    assert err.field_name == "email"
    assert err.error == "Duplicate"


def test_response_model_base() -> None:
    r = ResponseModelBase(success=True)
    assert r.success is True
    assert r.data is None

    r2 = ResponseModelBase(success=False, data={"key": "val"})
    assert r2.data == {"key": "val"}


def test_response_message() -> None:
    r = ResponseMessage(success=True, msg="done")
    assert r.success is True
    assert r.msg == "done"


def test_response_error_base_defaults() -> None:
    r = ResponseErrorBase()
    assert r.success is False
    assert r.msg is None
    assert r.from_error is None
    assert r.errors == []
    assert r.status_code is None


def test_response_error_base_with_values() -> None:
    r = ResponseErrorBase(
        success=False,
        msg="boom",
        from_error="Exception",
        errors=[ResponseError(error="something went wrong")],
        status_code=500,
    )
    assert r.errors == [ResponseError(error="something went wrong")]
    assert r.status_code == 500


def test_response_error_base_with_response_error_objects() -> None:
    r = ResponseErrorBase(
        errors=[ResponseError(field_name="x", error="required")],
    )
    assert len(r.errors) == 1
    assert r.errors[0].field_name == "x"
