"""Tests for auth_sdk_m8.security.consumer_auth — per-consumer primitives (9.1).

Covers the framework-agnostic verification building blocks: salted-hash
credentials, the encoded round-trip load path, scope grants (deny-by-default),
and the registry's authenticate/authorize flow including the no-enumeration
guarantee. The FastAPI dependency that wires these into a route is exercised in
``test_security_guards.py``.
"""

import pytest

from auth_sdk_m8.security.consumer_auth import (
    INTERNAL_CLIENT_HEADER,
    ConsumerAuthenticationError,
    ConsumerCredential,
    ConsumerCredentialRegistry,
    ConsumerScope,
    ConsumerScopeError,
)

SECRET_A = "consumer-a-bootstrap-secret-value-0001"
SECRET_B = "consumer-b-bootstrap-secret-value-0002"
FIXED_SALT = bytes(range(16))


# ── module constants ─────────────────────────────────────────────────────────


def test_internal_client_header_value() -> None:
    assert INTERNAL_CLIENT_HEADER == "X-Internal-Client"


def test_consumer_scope_values() -> None:
    # StrEnum members compare equal to and stringify as their raw value.
    assert ConsumerScope.INTROSPECTION == "introspection"
    assert str(ConsumerScope.USER_CREATE) == "user-create"
    assert ConsumerScope.EVENT_STREAM == "event-stream"


# ── ConsumerCredential.create ────────────────────────────────────────────────


def test_create_hashes_secret_and_keeps_no_plaintext() -> None:
    cred = ConsumerCredential.create("svc-a", SECRET_A)
    assert cred.client_id == "svc-a"
    assert SECRET_A not in cred.digest
    assert SECRET_A not in cred.encoded_secret
    assert cred.verify_secret(SECRET_A) is True


def test_create_random_salt_differs_per_credential() -> None:
    # Same secret, two credentials → different salt → different digest.
    one = ConsumerCredential.create("svc-a", SECRET_A)
    two = ConsumerCredential.create("svc-a", SECRET_A)
    assert one.salt != two.salt
    assert one.digest != two.digest


def test_create_explicit_salt_is_deterministic() -> None:
    one = ConsumerCredential.create("svc-a", SECRET_A, salt=FIXED_SALT)
    two = ConsumerCredential.create("svc-a", SECRET_A, salt=FIXED_SALT)
    assert one.digest == two.digest
    assert one.salt == FIXED_SALT.hex()


@pytest.mark.parametrize("client_id", ["", None])
def test_create_rejects_empty_client_id(client_id) -> None:
    with pytest.raises(ValueError, match="client_id"):
        ConsumerCredential.create(client_id, SECRET_A)


@pytest.mark.parametrize("secret", ["", None])
def test_create_rejects_empty_secret(secret) -> None:
    with pytest.raises(ValueError, match="secret"):
        ConsumerCredential.create("svc-a", secret)


# ── verify_secret ────────────────────────────────────────────────────────────


def test_verify_secret_matches_only_correct_value() -> None:
    cred = ConsumerCredential.create("svc-a", SECRET_A, salt=FIXED_SALT)
    assert cred.verify_secret(SECRET_A) is True
    assert cred.verify_secret(SECRET_B) is False


@pytest.mark.parametrize("provided", [None, ""])
def test_verify_secret_rejects_missing(provided) -> None:
    cred = ConsumerCredential.create("svc-a", SECRET_A)
    assert cred.verify_secret(provided) is False


# ── scopes (deny by default) ─────────────────────────────────────────────────


def test_scopes_default_to_none() -> None:
    cred = ConsumerCredential.create("svc-a", SECRET_A)
    assert cred.scopes == frozenset()
    assert cred.has_scope(ConsumerScope.INTROSPECTION) is False


def test_single_scope_is_not_split_into_characters() -> None:
    cred = ConsumerCredential.create("svc-a", SECRET_A, ConsumerScope.INTROSPECTION)
    assert cred.scopes == frozenset({"introspection"})
    assert cred.has_scope(ConsumerScope.INTROSPECTION) is True
    assert cred.has_scope("i") is False


def test_single_string_scope_grant() -> None:
    cred = ConsumerCredential.create("svc-a", SECRET_A, "user-create")
    assert cred.has_scope(ConsumerScope.USER_CREATE) is True


def test_iterable_scope_grant() -> None:
    cred = ConsumerCredential.create(
        "svc-a", SECRET_A, [ConsumerScope.INTROSPECTION, "event-stream"]
    )
    assert cred.has_scope(ConsumerScope.INTROSPECTION) is True
    assert cred.has_scope(ConsumerScope.EVENT_STREAM) is True
    assert cred.has_scope(ConsumerScope.USER_CREATE) is False


def test_invalid_scope_type_rejected() -> None:
    with pytest.raises(TypeError, match="scopes must be"):
        ConsumerCredential.create("svc-a", SECRET_A, 123)


# ── encoded round-trip / from_encoded ────────────────────────────────────────


def test_encoded_secret_round_trip() -> None:
    original = ConsumerCredential.create(
        "svc-a", SECRET_A, ConsumerScope.INTROSPECTION, salt=FIXED_SALT
    )
    rebuilt = ConsumerCredential.from_encoded(
        "svc-a", original.encoded_secret, ConsumerScope.INTROSPECTION
    )
    assert rebuilt.digest == original.digest
    assert rebuilt.salt == original.salt
    assert rebuilt.verify_secret(SECRET_A) is True
    assert rebuilt.has_scope(ConsumerScope.INTROSPECTION) is True


def test_encoded_secret_format() -> None:
    cred = ConsumerCredential.create("svc-a", SECRET_A, salt=FIXED_SALT)
    assert cred.encoded_secret == f"sha256${FIXED_SALT.hex()}${cred.digest}"


@pytest.mark.parametrize(
    "encoded",
    [
        "md5$0011$abcd",  # wrong algorithm
        "sha256$$abcd",  # empty salt
        "sha256$0011$",  # empty digest
        "sha256",  # no separators at all
    ],
)
def test_from_encoded_rejects_malformed(encoded) -> None:
    with pytest.raises(ValueError, match="sha256"):
        ConsumerCredential.from_encoded("svc-a", encoded)


@pytest.mark.parametrize(
    "encoded",
    [
        "sha256$zz$abcd",  # salt not hex
        "sha256$0011$zz",  # digest not hex
    ],
)
def test_from_encoded_rejects_non_hex(encoded) -> None:
    with pytest.raises(ValueError, match="hex"):
        ConsumerCredential.from_encoded("svc-a", encoded)


# ── ConsumerCredentialRegistry: construction ─────────────────────────────────


def test_registry_register_and_client_ids() -> None:
    registry = ConsumerCredentialRegistry()
    registry.register(ConsumerCredential.create("svc-a", SECRET_A))
    chained = registry.register(ConsumerCredential.create("svc-b", SECRET_B))
    assert chained is registry  # register returns self for chaining
    assert registry.client_ids == frozenset({"svc-a", "svc-b"})


def test_registry_rejects_duplicate_client_id() -> None:
    cred = ConsumerCredential.create("svc-a", SECRET_A)
    dupe = ConsumerCredential.create("svc-a", SECRET_B)
    with pytest.raises(ValueError, match="duplicate consumer credential"):
        ConsumerCredentialRegistry([cred, dupe])


def test_registry_get() -> None:
    cred = ConsumerCredential.create("svc-a", SECRET_A)
    registry = ConsumerCredentialRegistry([cred])
    assert registry.get("svc-a") is cred
    assert registry.get("absent") is None


def test_from_secrets_bare_and_scoped() -> None:
    registry = ConsumerCredentialRegistry.from_secrets(
        {
            "svc-a": SECRET_A,
            "svc-b": (SECRET_B, ConsumerScope.USER_CREATE),
        }
    )
    assert registry.verify("svc-a", SECRET_A).scopes == frozenset()
    assert registry.get("svc-b").has_scope(ConsumerScope.USER_CREATE) is True


def test_from_encoded_bare_and_scoped() -> None:
    enc_a = ConsumerCredential.create("svc-a", SECRET_A, salt=FIXED_SALT)
    enc_b = ConsumerCredential.create("svc-b", SECRET_B, salt=FIXED_SALT)
    registry = ConsumerCredentialRegistry.from_encoded(
        {
            "svc-a": enc_a.encoded_secret,
            "svc-b": (enc_b.encoded_secret, [ConsumerScope.INTROSPECTION]),
        }
    )
    assert registry.verify("svc-a", SECRET_A).client_id == "svc-a"
    assert registry.get("svc-b").has_scope(ConsumerScope.INTROSPECTION) is True


# ── verify (authentication only, no enumeration) ─────────────────────────────


def _two_consumer_registry() -> ConsumerCredentialRegistry:
    return ConsumerCredentialRegistry.from_secrets(
        {
            "svc-a": (SECRET_A, ConsumerScope.INTROSPECTION),
            "svc-b": (SECRET_B, ConsumerScope.USER_CREATE),
        }
    )


def test_verify_success_returns_credential() -> None:
    registry = _two_consumer_registry()
    matched = registry.verify("svc-a", SECRET_A)
    assert matched is not None
    assert matched.client_id == "svc-a"


def test_verify_wrong_secret_returns_none() -> None:
    registry = _two_consumer_registry()
    assert registry.verify("svc-a", "wrong-secret") is None


def test_consumer_a_cannot_use_consumer_b_secret() -> None:
    registry = _two_consumer_registry()
    # B's secret against A's id must not authenticate.
    assert registry.verify("svc-a", SECRET_B) is None
    assert registry.verify("svc-b", SECRET_A) is None


@pytest.mark.parametrize("client_id", ["unknown", None, ""])
def test_verify_unknown_client_returns_none(client_id) -> None:
    registry = _two_consumer_registry()
    assert registry.verify(client_id, SECRET_A) is None


# ── authorize (authentication + scope) ───────────────────────────────────────


def test_authorize_without_required_scope() -> None:
    registry = _two_consumer_registry()
    cred = registry.authorize("svc-a", SECRET_A)
    assert cred.client_id == "svc-a"


def test_authorize_with_matching_scope() -> None:
    registry = _two_consumer_registry()
    cred = registry.authorize("svc-a", SECRET_A, ConsumerScope.INTROSPECTION)
    assert cred.client_id == "svc-a"


def test_authorize_bad_secret_raises_authentication_error() -> None:
    registry = _two_consumer_registry()
    with pytest.raises(ConsumerAuthenticationError, match="unknown consumer"):
        registry.authorize("svc-a", "nope", ConsumerScope.INTROSPECTION)


def test_authorize_unknown_client_raises_authentication_error() -> None:
    registry = _two_consumer_registry()
    with pytest.raises(ConsumerAuthenticationError):
        registry.authorize("ghost", SECRET_A)


def test_authorize_scope_violation_raises_scope_error() -> None:
    registry = _two_consumer_registry()
    # svc-a is introspection-only; user-create must be denied.
    with pytest.raises(ConsumerScopeError, match="lacks scope 'user-create'"):
        registry.authorize("svc-a", SECRET_A, ConsumerScope.USER_CREATE)
