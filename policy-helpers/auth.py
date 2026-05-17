# Excerpt from iam-orchestrator — illustrative review copy. This file may
# import from the closed-source service tree and is not standalone-runnable.
# See README.md for scope and license.

"""
Shared API-key auth helper.

Each service exposes a ``_require_api_key`` FastAPI dependency that
401s when ``X-API-Key`` is missing or doesn't match the service's
configured secret.  The four implementations in
``services/*/src/main.py`` were verbatim copies that differed only in
which settings attribute they consulted (``intake_api_key``,
``doer_agent_api_key``, ``licensing_api_key``,
``audit_service_api_key``) and the misconfig-label string.

This module centralises the policy:

  - dev (``environment == "development"``): no-op, dep returns silently
  - prod with empty expected key: 503 (``misconfig_label`` in detail)
  - prod with mismatched / missing presented key: 401
  - prod with matching key: returns silently

Each service still defines its own thin ``_require_api_key`` so the
``Depends()`` chain stays statically typed against its own settings
class and existing test fixtures keep their patch surface unchanged.
"""
from __future__ import annotations

from fastapi import HTTPException


def check_api_key_match(
    *,
    environment: str,
    expected_key: str,
    presented_key: str | None,
    misconfig_label: str,
) -> None:
    """Centralised auth gate.  See module docstring for behaviour."""
    if environment == "development":
        return
    if not expected_key:
        # Lifespan startup hooks refuse to boot in prod with empty
        # keys, so this branch should be unreachable in practice.
        # Fail closed if it ever fires.
        raise HTTPException(
            status_code=503,
            detail=f"{misconfig_label} misconfigured: API key is empty",
        )
    if presented_key != expected_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-API-Key",
        )