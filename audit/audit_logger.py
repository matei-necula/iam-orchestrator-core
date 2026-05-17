# Excerpt from iam-orchestrator — illustrative review copy. This file may
# import from the closed-source service tree and is not standalone-runnable.
# See README.md for scope and license.

"""
WORM Audit Logger — Zero-Trust Layer
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncpg
import structlog
import ulid as ulid_lib

log = structlog.get_logger(__name__)

_AUDIT_DIR = Path(os.getenv("WORM_LOG_PATH", "/tmp/iam-orchestrator/audit"))
_last_hash: str = "genesis"
_hash_lock = asyncio.Lock()

# Matches any token that looks like an email address inside an action string.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _pseudonymise(value: str, tenant_id: str, key: str) -> str:
    """
    HMAC-SHA256 pseudonymisation scoped to tenant_id (GDPR Art. 4(5)).
    Output format: ``sha256:<32 hex chars>`` — unambiguous in log viewers.
    Deterministic: same value + tenant → same digest (correlation preserved).
    Rotating ``key`` satisfies Art. 17 right-to-erasure without deleting records.
    """
    msg = f"{tenant_id}:{value}".encode()
    digest = hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()
    return f"sha256:{digest[:32]}"


def _redact_action(action: str, tenant_id: str, key: str) -> str:
    """Replace any email-like token inside an action string with its pseudonym."""
    return _EMAIL_RE.sub(
        lambda m: _pseudonymise(m.group(0), tenant_id, key),
        action,
    )


def _today_log_path() -> Path:
    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _AUDIT_DIR / f"audit-{date_str}.jsonl"


class AuditLogger:

    def __init__(
        self,
        pool: asyncpg.Pool | None = None,
        pseudonym_key: str = "",
    ) -> None:
        self._pool = pool
        # GDPR Art. 4(5): pseudonymise target_email before any write.
        # Empty key falls back to a no-op prefix so dev works without config.
        self._pseudonym_key = pseudonym_key or "dev-insecure-key"
        log.info("audit_logger.initialized", log_dir=str(_AUDIT_DIR))

    async def load_chain_head(self) -> str:
        """
        Seed the module-global ``_last_hash`` from the most recent
        ``chain_hash`` stored in Postgres.  Must be called once at
        service startup, *before* any new event is written.

        Without this, every service restart re-initialises the
        in-memory chain head to ``"genesis"``.  The next written event
        would then chain from ``genesis`` again, silently opening a new
        chain segment.  ``verify_chain`` tolerates segment boundaries
        (so restarts don't flip the log to ``TAMPERED``), which means
        an attacker who rewrites the first post-restart event cannot be
        distinguished from a genuine restart — the WORM guarantee only
        holds *within* a segment.  Loading the chain head from durable
        storage closes that cover story.

        Fail-closed: if the DB is reachable but the query fails, we
        refuse to seed from ``genesis`` — that would re-open the cover
        story we're trying to close.  The caller (lifespan) should
        treat a raised ``RuntimeError`` as a hard boot failure.
        """
        global _last_hash
        if not self._pool:
            return _last_hash
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT chain_hash FROM audit_events "
                    "ORDER BY occurred_at DESC, event_id DESC LIMIT 1"
                )
        except Exception as exc:
            raise RuntimeError(
                "audit_logger: failed to load WORM chain head from "
                f"Postgres on startup: {exc}.  Refusing to boot — "
                "seeding the chain from 'genesis' would mask any "
                "post-restart tampering of the pre-restart tail."
            ) from exc

        if row and row["chain_hash"]:
            _last_hash = row["chain_hash"]
            log.info(
                "audit_logger.chain_head_loaded",
                chain_head_prefix=_last_hash[:12] + "...",
            )
        else:
            _last_hash = "genesis"
            log.info(
                "audit_logger.chain_head_genesis",
                reason="audit_events is empty (fresh deployment)",
            )
        return _last_hash

    async def log_event(
        self,
        event_type: str,
        actor: str,
        action: str,
        outcome: str,
        intent_id: str | None = None,
        target_resource: str | None = None,
        payload: dict[str, Any] | None = None,
        tenant_id: str = "default",
    ) -> str:
        global _last_hash

        event_id = str(ulid_lib.new())
        occurred_at = datetime.now(timezone.utc).isoformat()

        # GDPR Art. 4(5): pseudonymise personal data before writing to disk/DB.
        safe_target = (
            _pseudonymise(target_resource, tenant_id, self._pseudonym_key)
            if target_resource
            else None
        )
        safe_action = _redact_action(action, tenant_id, self._pseudonym_key)

        event = {
            "event_id": event_id,
            "occurred_at": occurred_at,
            "event_type": event_type,
            "actor": actor,
            "tenant_id": tenant_id,
            "intent_id": intent_id,
            "target_resource": safe_target,
            "action": safe_action,
            "outcome": outcome,
            "payload": payload or {},
        }

        async with _hash_lock:
            event_json = json.dumps(event, sort_keys=True)
            chain_hash = _sha256(_last_hash + event_json)
            event["chain_hash"] = chain_hash
            _last_hash = chain_hash

            log_line = json.dumps(event) + "\n"
            log_path = _today_log_path()
            with open(log_path, "a") as f:
                f.write(log_line)

        asyncio.create_task(self._persist_to_db(event, chain_hash))

        log.info(
            "audit_logger.event_written",
            event_id=event_id,
            event_type=event_type,
            outcome=outcome,
            chain_hash=chain_hash[:12] + "...",
        )

        return event_id

    async def _persist_to_db(self, event: dict, chain_hash: str) -> None:
        if not self._pool:
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, occurred_at, event_type, actor,
                        intent_id, target_resource, action,
                        outcome, payload, chain_hash, tenant_id
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    event["event_id"],
                    datetime.fromisoformat(event["occurred_at"]),
                    event["event_type"],
                    event["actor"],
                    event.get("intent_id"),
                    event.get("target_resource"),
                    event["action"],
                    event["outcome"],
                    json.dumps(event.get("payload", {})),
                    chain_hash,
                    event.get("tenant_id", "default"),
                )
        except Exception as exc:
            log.error("audit_logger.db_write_failed", error=str(exc))

    async def verify_chain(self, date_str: str | None = None) -> dict:
        if not date_str:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        log_path = _AUDIT_DIR / f"audit-{date_str}.jsonl"
        if not log_path.exists():
            return {"date": date_str, "status": "no_log_found", "events_checked": 0}

        events = []
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))

        if not events:
            return {"date": date_str, "status": "empty", "events_checked": 0}

        tampered = []
        segments = 1
        prev_hash = "genesis"

        for event in events:
            stored_hash = event.get("chain_hash")
            event_copy = {k: v for k, v in event.items() if k != "chain_hash"}
            event_json = json.dumps(event_copy, sort_keys=True)

            expected = _sha256(prev_hash + event_json)
            if stored_hash == expected:
                prev_hash = stored_hash
            else:
                genesis_expected = _sha256("genesis" + event_json)
                if stored_hash == genesis_expected:
                    segments += 1
                    prev_hash = stored_hash
                else:
                    tampered.append(event["event_id"])
                    prev_hash = stored_hash or prev_hash

        return {
            "date": date_str,
            "status": "clean" if not tampered else "TAMPERED",
            "events_checked": len(events),
            "chain_segments": segments,
            "tampered_event_ids": tampered,
            "chain_intact": len(tampered) == 0,
        }

    async def tail(
        self,
        n: int = 20,
        date_str: str | None = None,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """
        Read the last N events from the WORM log.  When ``tenant_id`` is
        provided, only events belonging to that tenant are returned — the
        filter is applied *after* reading the full file, so a caller can't
        see or count rows from another tenant.  Passing ``None`` returns
        everything and is reserved for system-level chain verification.
        """
        if not date_str:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        log_path = _AUDIT_DIR / f"audit-{date_str}.jsonl"
        if not log_path.exists():
            return []

        with open(log_path) as f:
            lines = [line.strip() for line in f if line.strip()]

        events = [json.loads(line) for line in lines]
        if tenant_id is not None:
            events = [e for e in events if e.get("tenant_id") == tenant_id]
        return events[-n:]