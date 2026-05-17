# Excerpt from iam-orchestrator — illustrative review copy. This file may
# import from the closed-source service tree and is not standalone-runnable.
# See README.md for scope and license.

"""HMAC-SHA256 packet signing — shared by gatekeeper (sign) and doer (verify).

The gatekeeper attaches a base64-encoded JSON wrapper containing the
canonical payload and an HMAC-SHA256 signature to every approved intent
forwarded to the doer.  Both services use the SAME ``secret_key`` env
var, so this module is the single source of truth for the algorithm.

Algorithm
---------
1. Augment the input payload dict with ``signed_at = now ISO-8601 UTC``.
2. Canonicalise via ``json.dumps(payload, sort_keys=True).encode()``.
3. Compute ``HMAC-SHA256(secret_key, canonical).hexdigest()``.
4. Emit ``base64({"payload": payload, "signature": hex})``.

Replay protection
-----------------
``verify`` accepts a ``max_age_seconds`` (default 300) window.  A
``signed_at`` more than that many seconds away from ``now`` (in either
direction — clock skew is symmetric) is rejected with
``reason="expired"``.

Constant-time comparison
------------------------
``hmac.compare_digest`` is used so that timing attacks cannot peel off
the signature one byte at a time.

Return shape
------------
``verify`` returns a frozen ``VerifyResult`` dataclass with three
fields: ``valid: bool``, ``payload: dict``, and ``reason`` (a literal
string used for structured logging and audit detail).  Callers MUST
NOT echo ``reason`` back to untrusted HTTP clients — a malicious
caller could enumerate failure modes.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

VerifyReason = Literal["ok", "malformed", "bad_signature", "expired", "empty_key"]


@dataclass(frozen=True)
class VerifyResult:
    valid: bool
    payload: dict
    reason: VerifyReason


def sign(
    payload: dict,
    *,
    secret_key: str,
    now: datetime | None = None,
) -> str:
    """Return base64({"payload": {...input + signed_at}, "signature": "<hex>"})."""
    now = now or datetime.now(timezone.utc)
    augmented = dict(payload)
    augmented["signed_at"] = now.isoformat()
    canonical = json.dumps(augmented, sort_keys=True).encode()
    digest = hmac.new(
        secret_key.encode(), canonical, hashlib.sha256
    ).hexdigest()
    wrapped = {"payload": augmented, "signature": digest}
    return base64.b64encode(json.dumps(wrapped).encode()).decode()


def verify(
    signed_payload: str,
    *,
    secret_key: str,
    max_age_seconds: int = 300,
    now: datetime | None = None,
) -> VerifyResult:
    """Validate ``signed_payload``.

    Returns a ``VerifyResult`` whose ``reason`` field describes the
    failure mode (or ``"ok"`` on success).  The HTTP layer should
    translate any non-``ok`` reason into a generic 401.
    """
    if not secret_key:
        return VerifyResult(valid=False, payload={}, reason="empty_key")
    if not signed_payload:
        return VerifyResult(valid=False, payload={}, reason="malformed")

    try:
        decoded_bytes = base64.b64decode(signed_payload.encode(), validate=True)
    except (binascii.Error, ValueError):
        return VerifyResult(valid=False, payload={}, reason="malformed")

    try:
        wrapped = json.loads(decoded_bytes.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return VerifyResult(valid=False, payload={}, reason="malformed")

    if not isinstance(wrapped, dict):
        return VerifyResult(valid=False, payload={}, reason="malformed")
    if "payload" not in wrapped or "signature" not in wrapped:
        return VerifyResult(valid=False, payload={}, reason="malformed")

    payload = wrapped["payload"]
    received_sig = wrapped["signature"]
    if not isinstance(payload, dict) or not isinstance(received_sig, str):
        return VerifyResult(valid=False, payload={}, reason="malformed")

    signed_at_str = payload.get("signed_at")
    if not isinstance(signed_at_str, str):
        return VerifyResult(valid=False, payload={}, reason="malformed")
    try:
        signed_at = datetime.fromisoformat(signed_at_str)
    except ValueError:
        return VerifyResult(valid=False, payload={}, reason="malformed")
    # Reject naive timestamps — the signer (gatekeeper) always emits a
    # tz-aware ISO string with "+00:00".  A naive value is either drift or
    # tampering; either way, refuse to fall back to implicit UTC.
    if signed_at.tzinfo is None:
        return VerifyResult(valid=False, payload={}, reason="malformed")

    # Recompute the HMAC over the canonical payload bytes and constant-
    # time compare.  Do this BEFORE the expiry check so a tampered
    # payload always returns ``bad_signature`` (more precise than
    # ``expired``).
    canonical = json.dumps(payload, sort_keys=True).encode()
    expected_sig = hmac.new(
        secret_key.encode(), canonical, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(received_sig, expected_sig):
        return VerifyResult(valid=False, payload={}, reason="bad_signature")

    # Replay-window check.
    now = now or datetime.now(timezone.utc)
    age_seconds = abs((now - signed_at).total_seconds())
    if age_seconds > max_age_seconds:
        return VerifyResult(valid=False, payload=payload, reason="expired")

    return VerifyResult(valid=True, payload=payload, reason="ok")