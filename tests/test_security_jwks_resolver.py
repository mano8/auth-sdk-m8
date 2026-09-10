"""Tests for JwksKeyResolver."""

import json
import time
from unittest.mock import MagicMock, patch

import jwt
import pytest

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security import (
    JwksKeyResolver,
    RefreshableKeyResolver,
    TokenValidationConfig,
    TokenValidator,
)

# ── RSA test key (2048-bit, generated for tests only) ────────────────────────

_RSA_PRIVATE_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzWCXqrK+FlZPOYIieExjEQCqHeIQrEDiAJN6zIWAULZlV2BS
SUHlIhQqZQ0zSoORT30G6AHXCC+bjCz06piAhA/nMiD1szbymxThnumDVcS3/tdl
BIMmRyfdWzUCxgMdV1OsVtQAC0lVThwKfyDdoCeyRFUYa9tfwIjMSvuU0PFXAtvU
EDwJlLmH4a8lkTcfAB5DD0eWzK2Q6KLT34VLMT8PQxtNfucWvuGnyhBHe4Ze2cvG
hINTLL4nUGi0YqwWAnxkzb3NnWJ5PV/X08QKZtJUy2pbhysV/Th9gu8sxnKN2mNz
TgSeGVaE+Yk5hpi+UTqfWQCK594KTowJa0LTMwIDAQABAoIBACBlL5c/2YcJdzax
hcFm/ytj6PGMwqeBFoUTvkd7eWmB08tsCJ7Ak6WD+8nzwpbq2OVqacf33lTOuaDr
SHimtILgRU4db9QkgzEeIpaf69UAEivTCv6it0t7CMoFuxnDzQGE08bgat9c4mVP
PAKgiwTjrhVkPNVqhZiHm33qYCdy2blTOBotgnG5tMUpKmT5BtXAq3/f8qadH5SB
CNqL0lwlfBB5CzTO/RIFNDA4IwwbpVYrIWKq83q0DlyDRl4/4qLY/0osZW506NJf
A8QUOgQGiW6X7IaPSZ5OaL1c8EnmhrGanZnYjh7dMsDJFAoY2yQ6a7iJqPMAivVd
tA2jDOECgYEA5x8NRDsMt9C/DbixP3YAsVBkCBUQAHuumC4YNphKN7M/SE0oDc57
7dkJghLJbrQ5ssuFodUKVIXM1UCZk7EgAUKrKCNli01/bhIxgPcKbSxLGjKRWAUW
UxhK00tLRrR1QiEoR077huLewHuG+mw4FL1I2MEP+/tYEaPwf0hIaKECgYEA43we
3JE0Tm3OwY8CcRRhMEn++DZFioobm0pIT80p5GEKjolbQQex+dulpd9i/0GLER+C
vW+ickW62Z6L7tez2u51GSyQEAUEKKsUbruKjCW/8KKx7s4/f/qiLrYkzhcSGGvZ
A4t7WoLxt0sV2gk0yWXYJWRVgomtXBv/tnsch1MCgYBVmqi9RunVA5pgKLJuAPUM
t+v1GmgM5cKrVxdc0Vdb/iZIT1uwkXRRinv9E5xMRrDASqW6ZUAoQk62BfFcRNTH
4rumaEXqLNAwIsj3LYlNGoTOtUAkS+4S5QKB9HdzPs/XqJRUpSqAsXMz9AzwoDi9
ZcafkhKrkFL0ZbZkTo+TQQKBgQDE8jm51hDF8fV1yD1h7zXxW67d8Aam2cjq2hXe
2Q3yxj0giDS0CViBrDMud0c7HOCsc256WYL3kf0h2Uzm/GKfIaHJqLYU2HLwTqVC
9SUPDsOtLv4DdRau0yvEazdUIc8ty3k3w3OJOiLRALWrbhsAXicSwFnzyQSI4Uiz
EMTzNwKBgQDkKBaMUOr2M5uhRltCZTiZIFJTlFUB4NEt0JurqwlMgGrHsQIH7b+w
CfXhpg/P/cn2UjoHonHYWAw/5AWv7NJAMiSoPFM41ypgqdWecwSDzm2aPOpQE4oZ
an056qoZgrQRdeX5bYMCU+t+DJFFJCItpFkQ2jGGEFe6oslrZvgNMw==
-----END RSA PRIVATE KEY-----"""

_RSA_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzWCXqrK+FlZPOYIieExj
EQCqHeIQrEDiAJN6zIWAULZlV2BSSUHlIhQqZQ0zSoORT30G6AHXCC+bjCz06piA
hA/nMiD1szbymxThnumDVcS3/tdlBIMmRyfdWzUCxgMdV1OsVtQAC0lVThwKfyDd
oCeyRFUYa9tfwIjMSvuU0PFXAtvUEDwJlLmH4a8lkTcfAB5DD0eWzK2Q6KLT34VL
MT8PQxtNfucWvuGnyhBHe4Ze2cvGhINTLL4nUGi0YqwWAnxkzb3NnWJ5PV/X08QK
ZtJUy2pbhysV/Th9gu8sxnKN2mNzTgSeGVaE+Yk5hpi+UTqfWQCK594KTowJa0LT
MwIDAQAB
-----END PUBLIC KEY-----"""


# ── Rotated RSA test key (2048-bit, generated for tests only) ───────────────
# A *second* key that the JWKS endpoint can serve under an unchanged ``kid``.
# That is the J3 failure this module's escalation tests reproduce: the label
# stays put while the material behind it is replaced.

_ROTATED_PRIVATE_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA6pU7KOhMn2b5QU4J2qMtZibGKpi1zYQOyIvDx17tOk/tXVsS
ISdL6T5Be63lpMEdFjDpOwP64V2nBTYdJqrk2Vky74RDtWaMN8Z67bjl15NKOz7H
kce8WiOgWCXB35o19qLfGUnJBvNdUdAtvEN1lzSjRS92VbXXV9sk23TiF9USiLyM
cO7Ud2PAAIdWrY8yHG74tjNbAmM3GzQqPugD3+tiPGcafmRSNDrqIzPvmmvTAHJ9
xfLDqsNQDPDAG3eHcR+1d4O9XSYEJ2Y3lwpTbqA3KkZHPHVF7RlfuorUx6p1Y09e
/DvxA1eFMhJdQBj5wZoZGd0GYi+hWQHWPqUS2wIDAQABAoIBAF6ECSWWz0SMg1JG
JJ9EjuaxKbgA9oNbOW+hLJ04SKHtkUhDiN71y9aq4Ex6SOQkcNk/lMFT/bHu/3wQ
jRdG1NUj5OtvYa6FpmpUnLQKgwTkUgzj4xoAHYo9/310nRRAOIzqm7Q/L/GOfaOY
mszXa1okecJG+MlY7m52G/gWNIB/8gakKTJCy810j7HJmYMmg24MZrqQQ4KXbZQx
NWpz5pUns+F55cEtMiT4bQNF19hSndaLXB+o+6CYutSZKIMRsgo2areiLZwZSCiV
X4eKcQxQiTaRl4eP07OE7MJqs5/ByleYYWPZNA9vyqQjtgoG8sxA8s7Ompmho/kY
moWlcskCgYEA/1+ZAhJ3Cy7Cag+oBCZdReXb3UOiKsRtbAS/FJs/TLoadV2nw7I0
oNLO74qGCuX3vBZ9ffHVjxD5gruIsR0dX5qNdslooNkNPr+AD/i4Xhxkh3CK6jbm
MsdAZqb3RFwQhdv6gc5ZAIjdGehk5HydasPYEby7WukSAzHB/a3VvJkCgYEA6yiT
IEhkgJze9w2Uwq1GylGsdPJhbi85cqdxSvIGbSy50SfFnUKBAtJFNEAWlUl/yO+U
A6ctTRghIUcmOpH16yEYxcxSPAlUpkRY7CfBi9origpMfu2lzpE3yDIxhghXJC7a
bTXFvTNS1DoDE4+A2BChsM9FYc8APHlygXp1X5MCgYBM72AJX8a9d7jaex0DIwu2
oyk538ZbXBIbGNL4Qk0vsGGIOk7whh+U0+3D/NelMOMRpzTnXJQaJeMFn7nuofbX
dphn0QXUb4+t98N9DFF/CM7AfwdayG9RnPWp92NHFPVlXoB52tC1eIYj5/99Vo2W
PKo7rcBEAzOKAtOOuXBLAQKBgQCLjhfKJ8wlG3OisBehdM23EcND3/f8OOBh74bn
kDxKHCnmOzEmg6omb30MZiBA1k6Ug8GWbWcQAoreweepCKglsw2NjRUcdfkbdyJC
e9F72qzODhCZnxUwQrQVBdyoC1kTqw6Lk0bXYpb8RbU/rYEsOKqMUGV/hyY/vV88
Ad2YKwKBgQCU6h4kvqk+vaTZF7BRK42LzAIqwNNKkoeRmQTl8Z+sjC5+J5uLqEqH
5Omnz+unR84dqgiDTuefZyo1NXP3P99Zk1ANUdF0tex4vkpdX3VS6nGiIdPkMrvF
c97/Wq+7CQuZohQ9ou8FKMuCMXv0AmXRVh7U49KaZKwt8iX5gcPwcA==
-----END RSA PRIVATE KEY-----"""

_ROTATED_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6pU7KOhMn2b5QU4J2qMt
ZibGKpi1zYQOyIvDx17tOk/tXVsSISdL6T5Be63lpMEdFjDpOwP64V2nBTYdJqrk
2Vky74RDtWaMN8Z67bjl15NKOz7Hkce8WiOgWCXB35o19qLfGUnJBvNdUdAtvEN1
lzSjRS92VbXXV9sk23TiF9USiLyMcO7Ud2PAAIdWrY8yHG74tjNbAmM3GzQqPugD
3+tiPGcafmRSNDrqIzPvmmvTAHJ9xfLDqsNQDPDAG3eHcR+1d4O9XSYEJ2Y3lwpT
bqA3KkZHPHVF7RlfuorUx6p1Y09e/DvxA1eFMhJdQBj5wZoZGd0GYi+hWQHWPqUS
2wIDAQAB
-----END PUBLIC KEY-----"""


def _make_jwk(kid: str = "test-kid-1", public_pem: str = _RSA_PUBLIC_PEM) -> dict:
    """Build a minimal synthetic JWK that the resolver will parse."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from jwt.algorithms import RSAAlgorithm

    key_obj = load_pem_public_key(public_pem.strip().encode())
    jwk = json.loads(RSAAlgorithm.to_jwk(key_obj))  # type: ignore[arg-type]
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    jwk["kid"] = kid
    return jwk


def _make_jwks_response(
    kids: list[str] | None = None,
    public_pem: str = _RSA_PUBLIC_PEM,
) -> bytes:
    kids = kids or ["test-kid-1"]
    keys = [_make_jwk(k, public_pem) for k in kids]
    return json.dumps({"keys": keys}).encode()


def _jwks_endpoint(*bodies: bytes) -> MagicMock:
    """Patchable ``urlopen`` serving *bodies* in order, repeating the last one.

    Rotation is a property of successive fetches, so these tests need an
    endpoint whose answer changes between them.
    """
    served: list[bytes] = list(bodies)

    def _open(*_args: object, **_kwargs: object) -> MagicMock:
        body = served.pop(0) if len(served) > 1 else served[0]
        resp = MagicMock()
        resp.read.return_value = body
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    return MagicMock(side_effect=_open)


# ── _fetch_jwks ───────────────────────────────────────────────────────────────


def test_fetch_jwks_returns_key_list():
    resolver = JwksKeyResolver("http://auth/jwks.json")
    mock_resp = MagicMock()
    mock_resp.read.return_value = _make_jwks_response(["kid-a"])
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        keys = resolver._fetch_jwks()

    assert len(keys) == 1
    assert keys[0]["kid"] == "kid-a"


def test_fetch_jwks_rejects_oversized_response():
    from auth_sdk_m8.security.jwks_resolver import _MAX_JWKS_BYTES

    resolver = JwksKeyResolver("http://auth/jwks.json")
    oversized = b"x" * (_MAX_JWKS_BYTES + 1)

    mock_resp = MagicMock()
    # Mirror urllib's read(n): return at most n bytes of the body.
    mock_resp.read.side_effect = lambda n=None: (
        oversized if n is None else oversized[:n]
    )
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(ValueError, match="byte cap"):
            resolver._fetch_jwks()


def test_fetch_jwks_accepts_response_at_cap_boundary():
    from auth_sdk_m8.security.jwks_resolver import _MAX_JWKS_BYTES

    resolver = JwksKeyResolver("http://auth/jwks.json")
    body = _make_jwks_response(["kid-a"])
    assert len(body) <= _MAX_JWKS_BYTES

    mock_resp = MagicMock()
    mock_resp.read.side_effect = lambda n=None: body if n is None else body[:n]
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        keys = resolver._fetch_jwks()

    assert keys[0]["kid"] == "kid-a"


# ── resolve — cache hit ───────────────────────────────────────────────────────


def test_resolve_returns_token_secret_on_cache_hit():
    resolver = JwksKeyResolver("http://auth/jwks.json")
    mock_resp = MagicMock()
    mock_resp.read.return_value = _make_jwks_response(["test-kid-1"])
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        secret = resolver.resolve("test-kid-1")

    assert isinstance(secret, TokenSecret)
    assert secret.algorithm == "RS256"
    assert "BEGIN PUBLIC KEY" in secret.secret_key.get_secret_value()


def test_resolve_cache_is_reused_without_refetch():
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=60)
    mock_resp = MagicMock()
    mock_resp.read.return_value = _make_jwks_response(["kid-x"])
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        resolver.resolve("kid-x")
        resolver.resolve("kid-x")

    assert mock_open.call_count == 1


# ── resolve — cache miss (unknown kid) ───────────────────────────────────────


def test_resolve_refreshes_on_unknown_kid():
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=60)
    mock_resp = MagicMock()
    mock_resp.read.return_value = _make_jwks_response(["kid-1"])
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        resolver.resolve("kid-1")  # populates cache
        mock_resp.read.return_value = _make_jwks_response(["kid-1", "kid-2"])
        resolver._last_refresh_attempt = 0  # bypass throttle gate
        resolver.resolve("kid-2")  # unknown → triggers refresh

    assert mock_open.call_count == 2


def test_resolve_raises_lookup_error_for_unknown_kid_after_refresh():
    resolver = JwksKeyResolver("http://auth/jwks.json")
    mock_resp = MagicMock()
    mock_resp.read.return_value = _make_jwks_response(["existing-kid"])
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(LookupError, match="no-such-kid"):
            resolver.resolve("no-such-kid")


# ── resolve — TTL expiry ──────────────────────────────────────────────────────


def test_resolve_refetches_after_ttl_expiry():
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=1)
    mock_resp = MagicMock()
    mock_resp.read.return_value = _make_jwks_response(["kid-a"])
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        resolver.resolve("kid-a")
        # Force expiry and reset throttle so the second call fetches
        resolver._cache_expires_at = time.monotonic() - 1
        resolver._last_refresh_attempt = 0
        resolver.resolve("kid-a")

    assert mock_open.call_count == 2


# ── multi-key JWKS parsing (W1.3 dual-key overlap, consumer half) ────────────


def test_multi_key_jwks_populates_one_cache_entry_per_kid():
    """A JWKS with several keys must cache all of them, not just the first.

    This is the consumer half of W1.3's dual-key overlap window: the issuer
    can publish a current and an `_OLD` key under distinct `kid`s, and a
    resolver that only kept the first entry would silently drop coverage for
    whichever key `_jwk_to_pem` did not see first.
    """
    resolver = JwksKeyResolver("http://auth/jwks.json")
    mock_resp = MagicMock()
    mock_resp.read.return_value = _make_jwks_response(
        ["kid-current", "kid-old"], _RSA_PUBLIC_PEM
    )
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        resolver._guarded_refresh()

    assert set(resolver._cache.keys()) == {"kid-current", "kid-old"}


def test_multi_key_jwks_verifies_tokens_under_either_kid():
    """Both keys in a two-key JWKS must independently verify a token."""
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=3600)
    validator = _rotation_validator(resolver)

    keys = [
        _make_jwk("kid-current", _RSA_PUBLIC_PEM),
        _make_jwk("kid-old", _ROTATED_PUBLIC_PEM),
    ]
    body = json.dumps({"keys": keys}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        current = validator.validate_access_token(
            _rs256_access_token(_RSA_PRIVATE_PEM, kid="kid-current")
        )
        old = validator.validate_access_token(
            _rs256_access_token(_ROTATED_PRIVATE_PEM, kid="kid-old")
        )

    assert current.sub == "user-123"
    assert old.sub == "user-123"


# ── non-sig keys are ignored ──────────────────────────────────────────────────


def test_non_sig_keys_skipped():
    resolver = JwksKeyResolver("http://auth/jwks.json")
    enc_jwk = {**_make_jwk("enc-key"), "use": "enc"}
    sig_jwk = _make_jwk("sig-key")
    payload = json.dumps({"keys": [enc_jwk, sig_jwk]}).encode()

    mock_resp = MagicMock()
    mock_resp.read.return_value = payload
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(LookupError):
            resolver.resolve("enc-key")
        secret = resolver.resolve("sig-key")

    assert isinstance(secret, TokenSecret)


# ── factory integration ───────────────────────────────────────────────────────


def test_build_access_validator_uses_jwks_resolver_when_uri_set():
    from auth_sdk_m8.security import build_access_validator
    from auth_sdk_m8.security.jwks_resolver import JwksKeyResolver

    settings = MagicMock()
    settings.ACCESS_TOKEN_ALGORITHM = "RS256"
    settings.JWKS_URI = "http://auth/jwks.json"
    settings.JWKS_CACHE_TTL_SECONDS = 300
    settings.TOKEN_STRICT_VALIDATION = False
    del settings.TOKEN_ISSUER
    del settings.TOKEN_AUDIENCE

    validator = build_access_validator(settings)
    assert validator._key_resolver is not None
    assert isinstance(validator._key_resolver, JwksKeyResolver)
    assert validator._default_secrets is None


# ── _guarded_refresh — rate-limiting branches ────────────────────────────────


def test_guarded_refresh_rate_limited_skips_fetch() -> None:
    resolver = JwksKeyResolver("http://auth/jwks.json")
    mock_resp = MagicMock()
    mock_resp.read.return_value = _make_jwks_response(["kid-a"])
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        resolver._guarded_refresh()  # first call — fetches, sets _last_refresh_attempt
        resolver._guarded_refresh()  # second call — rate-limited, hits line 92 early return

    assert mock_open.call_count == 1


def test_guarded_refresh_inner_lock_double_check() -> None:
    resolver = JwksKeyResolver("http://auth/jwks.json")
    resolver._last_refresh_attempt = 0.0

    call_count = [0]

    def patched_monotonic() -> float:
        call_count[0] += 1
        if call_count[0] == 1:
            # Outer check: 100-0=100 > _MIN_REFRESH_INTERVAL → pass outer gate
            return 100.0
        # Inner check (under lock): simulate concurrent refresh by bumping last_attempt
        resolver._last_refresh_attempt = 99.0
        return 100.0  # 100-99=1 < 10 → rate-limited inside lock → hits line 99

    with (
        patch("auth_sdk_m8.security.jwks_resolver.time.monotonic", patched_monotonic),
        patch.object(resolver, "_refresh") as mock_refresh,
    ):
        resolver._guarded_refresh()

    mock_refresh.assert_not_called()


# ── _refresh — stale-cache fallback ──────────────────────────────────────────


def test_refresh_stale_cache_served_on_fetch_failure() -> None:
    from pydantic import SecretStr

    from auth_sdk_m8.schemas.auth import TokenSecret

    resolver = JwksKeyResolver("http://auth/jwks.json")
    resolver._cache = {
        "old-kid": TokenSecret(secret_key=SecretStr("old-key"), algorithm="RS256")
    }

    with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
        resolver._refresh()  # should serve stale cache, not raise

    assert "old-kid" in resolver._cache


def test_refresh_raises_when_cache_empty_and_fetch_fails() -> None:
    resolver = JwksKeyResolver("http://auth/jwks.json")
    # Cache is empty — no stale fallback available.
    with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
        with pytest.raises(OSError):
            resolver._refresh()


def test_jwks_key_resolver_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError, match="http or https"):
        JwksKeyResolver("ftp://auth/jwks.json")


# ── refresh — signature-failure escalation (J3) ──────────────────────────────


def _rs256_access_token(private_pem: str, kid: str = "kid-1") -> str:
    """Sign a well-formed access token with *private_pem*, labelled *kid*."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "jti": "test-jti-0000",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
    }
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid})


def _rotation_validator(resolver: JwksKeyResolver) -> TokenValidator:
    return TokenValidator(
        secrets=None,
        config=TokenValidationConfig(allowed_algorithms=["RS256"]),
        key_resolver=resolver,
    )


def test_resolver_satisfies_refreshable_protocol() -> None:
    assert isinstance(JwksKeyResolver("http://auth/jwks.json"), RefreshableKeyResolver)


def test_refresh_returns_none_when_throttled() -> None:
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=3600)
    opener = _jwks_endpoint(_make_jwks_response(["kid-1"]))

    with patch("urllib.request.urlopen", opener):
        resolver.resolve("kid-1")  # populates cache, arms the throttle
        assert resolver.refresh("kid-1") is None

    assert opener.call_count == 1


def test_refresh_returns_rotated_key_under_unchanged_kid() -> None:
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=3600)
    opener = _jwks_endpoint(
        _make_jwks_response(["kid-1"]),
        _make_jwks_response(["kid-1"], _ROTATED_PUBLIC_PEM),
    )

    with patch("urllib.request.urlopen", opener):
        original = resolver.resolve("kid-1")
        resolver._last_refresh_attempt = 0.0  # throttle window elapsed
        rotated = resolver.refresh("kid-1")

    assert rotated is not None
    assert (
        rotated.secret_key.get_secret_value() != original.secret_key.get_secret_value()
    )
    assert _ROTATED_PUBLIC_PEM.strip() in rotated.secret_key.get_secret_value()


def test_refresh_returns_none_for_kid_absent_from_refreshed_set() -> None:
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=3600)
    opener = _jwks_endpoint(
        _make_jwks_response(["kid-1"]),
        _make_jwks_response(["kid-2"]),
    )

    with patch("urllib.request.urlopen", opener):
        resolver.resolve("kid-1")
        resolver._last_refresh_attempt = 0.0
        assert resolver.refresh("kid-1") is None


def test_refresh_serves_stale_cache_when_the_fetch_fails() -> None:
    """A failed escalation must not evict a cache that still works."""
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=3600)
    opener = _jwks_endpoint(_make_jwks_response(["kid-1"]))

    with patch("urllib.request.urlopen", opener):
        cached = resolver.resolve("kid-1")

    resolver._last_refresh_attempt = 0.0
    with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
        returned = resolver.refresh("kid-1")

    assert returned is not None
    assert (
        returned.secret_key.get_secret_value() == cached.secret_key.get_secret_value()
    )


# ── TokenValidator ↔ resolver: recovery within one refresh interval ──────────


def test_validator_recovers_when_the_key_changes_under_a_fixed_kid() -> None:
    """The J3 case: cache_ttl is an hour, recovery must not wait for it."""
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=3600)
    validator = _rotation_validator(resolver)
    opener = _jwks_endpoint(
        _make_jwks_response(["kid-1"]),
        _make_jwks_response(["kid-1"], _ROTATED_PUBLIC_PEM),
    )

    with patch("urllib.request.urlopen", opener):
        # Warm the cache with the pre-rotation key.
        validator.validate_access_token(_rs256_access_token(_RSA_PRIVATE_PEM))
        resolver._last_refresh_attempt = 0.0  # one _MIN_REFRESH_INTERVAL later

        # The key behind kid-1 has been replaced; the cache still answers.
        result = validator.validate_access_token(
            _rs256_access_token(_ROTATED_PRIVATE_PEM)
        )

    assert result.sub == "user-123"
    assert opener.call_count == 2
    # The TTL never expired — recovery came from the escalation, not the clock.
    assert resolver._cache_expires_at > time.monotonic()


def test_validator_rejects_a_forged_signature_after_the_escalation() -> None:
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=3600)
    validator = _rotation_validator(resolver)
    opener = _jwks_endpoint(_make_jwks_response(["kid-1"]))

    with patch("urllib.request.urlopen", opener):
        validator.validate_access_token(_rs256_access_token(_RSA_PRIVATE_PEM))
        resolver._last_refresh_attempt = 0.0
        with pytest.raises(InvalidToken):
            validator.validate_access_token(
                _rs256_access_token(_ROTATED_PRIVATE_PEM)  # key never published
            )


def test_invalid_signature_flood_costs_at_most_one_fetch_per_interval() -> None:
    """The escalation is attacker-triggerable; the throttle is what bounds it."""
    resolver = JwksKeyResolver("http://auth/jwks.json", cache_ttl=3600)
    validator = _rotation_validator(resolver)
    opener = _jwks_endpoint(_make_jwks_response(["kid-1"]))

    with patch("urllib.request.urlopen", opener):
        validator.validate_access_token(_rs256_access_token(_RSA_PRIVATE_PEM))
        resolver._last_refresh_attempt = 0.0  # allow exactly one escalation
        for _ in range(25):
            with pytest.raises(InvalidToken):
                validator.validate_access_token(
                    _rs256_access_token(_ROTATED_PRIVATE_PEM)
                )

    # One warm-up fetch + one escalation, not one per forged token.
    assert opener.call_count == 2
