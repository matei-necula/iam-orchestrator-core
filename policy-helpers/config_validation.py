# Excerpt from iam-orchestrator — illustrative review copy. This file may
# import from the closed-source service tree and is not standalone-runnable.
# See README.md for scope and license.

"""Shared production-config validation.

Each service's settings class builds a list of `RequiredField` entries and
calls `validate_required(env, fields)` from its FastAPI startup hook.  When
`env == "production"` any missing or default-valued field aborts the boot
with a single `ConfigError` listing every offender.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    """Raised when a service is started in production mode with missing or
    default credentials."""


@dataclass(frozen=True)
class RequiredField:
    name: str
    value: str
    forbidden_defaults: tuple[str, ...] = field(default_factory=tuple)


def _is_invalid(rf: RequiredField) -> str | None:
    if rf.value == "" or rf.value is None:
        return "not set"
    if rf.value in rf.forbidden_defaults:
        return f"still set to default {rf.value!r}"
    return None


def validate_required(env: str, fields: list[RequiredField]) -> None:
    """Validate required fields when running in production.

    Raises ConfigError listing every missing/default field.  Dev/test envs
    pass unconditionally.
    """
    if env != "production":
        return

    problems: list[str] = []
    for rf in fields:
        reason = _is_invalid(rf)
        if reason is not None:
            problems.append(f"  - {rf.name}: {reason}")

    if problems:
        raise ConfigError(
            "production startup blocked — "
            f"{len(problems)} required field(s) missing or using default values:\n"
            + "\n".join(problems)
            + "\nSet these environment variables and restart."
        )