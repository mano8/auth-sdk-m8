"""HMAC signing tests for the auth event-stream signing helpers.

Covers the canonical-JSON HMAC-SHA256 sign/verify used by the fa-auth SSE
bridge: signed messages round-trip; tampered, wrong-key or (by default)
unsigned messages are dropped.
"""

import json

from auth_sdk_m8.events._signing import deserialize, serialize

KEY = "Abcdef-1234_XYZ-abcdef-ghijkl-mnopqr-stuvwx"
OTHER_KEY = "Zyxwvu-9876_ABC-zyxwvu-tsrqpo-nmlkji-hgfedc"


def test_serialize_unsigned_passthrough() -> None:
    assert json.loads(serialize({"a": 1}, None)) == {"a": 1}


def test_serialize_signed_envelope_roundtrips() -> None:
    raw = serialize({"a": 1, "b": 2}, KEY)
    env = json.loads(raw)
    assert set(env) == {"payload", "sig"}
    assert deserialize(raw, KEY) == {"a": 1, "b": 2}


def test_deserialize_tampered_payload_dropped() -> None:
    env = json.loads(serialize({"a": 1}, KEY))
    env["payload"]["a"] = 999  # tamper after signing
    assert deserialize(json.dumps(env), KEY) is None


def test_deserialize_wrong_key_dropped() -> None:
    raw = serialize({"a": 1}, KEY)
    assert deserialize(raw, OTHER_KEY) is None


def test_deserialize_unsigned_dropped_by_default() -> None:
    assert deserialize(json.dumps({"a": 1}), KEY) is None


def test_deserialize_unsigned_accepted_with_flag() -> None:
    assert deserialize(json.dumps({"a": 1}), KEY, accept_unsigned=True) == {"a": 1}


def test_deserialize_no_key_passthrough() -> None:
    assert deserialize(json.dumps({"a": 1}), None) == {"a": 1}
