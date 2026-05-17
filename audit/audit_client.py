# Excerpt from iam-orchestrator/shared/utils/audit_client.py — illustrative
# review copy. This file imports from the closed-source service tree and is
# not standalone-runnable. See README.md for scope and license.

"""Shared audit-event client.

Centralised HTTP client for posting WORM audit events to the zero-trust
service (``POST /audit/event``).  Existed previously as five duplicated
``try/except``/``async with httpx.AsyncClient(...)`` blocks across three
services; extracted into this single module so the wire format and error
policy live in one place.

The two error-handling modes are explicit at the callsite:

  - Fire-and-forget: wrap the call in ``try/except`` and log on failure.
  - Write-ahead: let the exception propagate so the upstream request is
    rejected when the audit log is unreachable.

This module owns the wire format.  Each callsite passes its own
``payload`` dict.
"""
from __future__ import annotations

from typing import Any

import httpx
import structlog

log = structlog.get_logger(__name__)

DEFAULT_TIMEOUT_SECONDS = 3.0


def audit_headers(api_key: str) -> dict[str, str]:
    """Return the X-API-Key header dict if the key is non-empty,
    else ``{}``.  Empty dict in dev means zero-trust accepts the
    write without auth — matches the dev fail-open behaviour of
    ``check_api_key_match``."""
    return {"X-API-Key": api_key} if api_key else {}


async def post_audit_event(
    *,
    base_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> None:
    """POST a single audit event.

    Raises:
        Any ``httpx`` transport error or 4xx/5xx as
        ``httpx.HTTPStatusError`` (after ``raise_for_status``).
        Callers that want fire-and-forget semantics wrap the call
        in ``try/except`` and log; callers that want write-ahead
        semantics let it propagate.
    """
    async with httpx.AsyncClient(timeout=timeout) as ac:
        resp = await ac.post(
            f"{base_url}/audit/event",
            headers=audit_headers(api_key),
            json=payload,
        )
        resp.raise_for_status()
