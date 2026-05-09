"""Tests for AccessTokenBlacklist."""

from unittest.mock import MagicMock

from redis import Redis

from auth_sdk_m8.security import AccessTokenBlacklist

# ── helpers ──────────────────────────────────────────────────────────────────


def _make_blacklist(exists_return: int = 0) -> tuple[AccessTokenBlacklist, MagicMock]:
    """Return a blacklist wired to a mock Redis client."""
    client = MagicMock(spec=Redis)
    client.exists.return_value = exists_return
    return AccessTokenBlacklist(client), client


# ── is_revoked ────────────────────────────────────────────────────────────────


def test_is_revoked_returns_false_when_key_absent() -> None:
    blacklist, _ = _make_blacklist(exists_return=0)
    assert blacklist.is_revoked("some-jti") is False


def test_is_revoked_returns_true_when_key_present() -> None:
    blacklist, _ = _make_blacklist(exists_return=1)
    assert blacklist.is_revoked("some-jti") is True


def test_is_revoked_uses_correct_key_prefix() -> None:
    blacklist, client = _make_blacklist()
    jti = "abc-123"
    blacklist.is_revoked(jti)
    client.exists.assert_called_once_with(f"jwt:blacklist:{jti}")


def test_prefix_constant() -> None:
    assert AccessTokenBlacklist.PREFIX == "jwt:blacklist:"


def test_different_jtis_produce_different_keys() -> None:
    blacklist, client = _make_blacklist()
    blacklist.is_revoked("jti-A")
    blacklist.is_revoked("jti-B")
    calls = [c.args[0] for c in client.exists.call_args_list]
    assert calls == ["jwt:blacklist:jti-A", "jwt:blacklist:jti-B"]
