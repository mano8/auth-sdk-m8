"""HMAC-SHA256 signing helpers for the auth event stream.

Secure-by-default: when a signing key is configured, publishers wrap each
payload in a signed envelope and consumers verify the signature before
deserializing or dispatching to a handler.  Forged or (by default) unsigned
messages are dropped without invoking the handler.

These helpers are transport-agnostic; the fa-auth SSE bridge
(:mod:`auth_sdk_m8.events.stream_client`) uses them to verify incoming events.

Wire format (signed):  ``{"payload": {...}, "sig": "<hex hmac>"}``
Wire format (unsigned): the raw payload object (legacy / signing disabled).

The signature is computed over a canonical JSON encoding of *payload* (sorted
keys, no whitespace) so that publisher and consumer agree on the exact bytes
regardless of key ordering.
"""

import hashlib
import hmac
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _canonical(payload: Dict[str, Any]) -> bytes:
    """Return the canonical byte encoding signed/verified for *payload*."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_sig(payload: Dict[str, Any], key: str) -> str:
    """Compute the hex HMAC-SHA256 signature of *payload* under *key*."""
    return hmac.new(
        key.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


def serialize(payload: Dict[str, Any], signing_key: Optional[str]) -> str:
    """Serialize *payload* for publishing.

    When *signing_key* is set, the payload is wrapped in a signed envelope;
    otherwise the raw payload is emitted unchanged (signing disabled).
    """
    if signing_key is None:
        return json.dumps(payload)
    return json.dumps({"payload": payload, "sig": _compute_sig(payload, signing_key)})


def deserialize(
    raw: str,
    signing_key: Optional[str],
    *,
    accept_unsigned: bool = False,
) -> Optional[Dict[str, Any]]:
    """Parse and verify an incoming wire message.

    Returns the inner payload dict on success, or ``None`` when the message
    must be dropped — a forged signature, or an unsigned message while signed
    messages are required.  When *signing_key* is ``None`` no verification is
    performed (signing disabled) and the parsed object is returned as-is.
    """
    data = json.loads(raw)
    if signing_key is None:
        return data
    if isinstance(data, dict) and "sig" in data and "payload" in data:
        payload = data["payload"]
        expected = _compute_sig(payload, signing_key)
        if hmac.compare_digest(expected, str(data["sig"])):
            return payload
        logger.warning("Dropping event with invalid HMAC signature")
        return None
    if accept_unsigned:
        return data
    logger.warning("Dropping unsigned event (signed events required)")
    return None
