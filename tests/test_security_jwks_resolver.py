"""Tests for JwksKeyResolver."""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security import JwksKeyResolver

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


def _make_jwk(kid: str = "test-kid-1") -> dict:
    """Build a minimal synthetic JWK that the resolver will parse."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from jwt.algorithms import RSAAlgorithm

    key_obj = load_pem_public_key(_RSA_PUBLIC_PEM.strip().encode())
    jwk = json.loads(RSAAlgorithm.to_jwk(key_obj))
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    jwk["kid"] = kid
    return jwk


def _make_jwks_response(kids: list[str] = None) -> bytes:
    kids = kids or ["test-kid-1"]
    keys = [_make_jwk(k) for k in kids]
    return json.dumps({"keys": keys}).encode()


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
        # Force expiry
        resolver._cache_expires_at = time.monotonic() - 1
        resolver.resolve("kid-a")

    assert mock_open.call_count == 2


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
    del settings.TOKEN_ISSUER
    del settings.TOKEN_AUDIENCE

    validator = build_access_validator(settings)
    assert validator._key_resolver is not None
    assert isinstance(validator._key_resolver, JwksKeyResolver)
    assert validator._default_secrets is None
