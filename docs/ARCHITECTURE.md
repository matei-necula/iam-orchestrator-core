# Architecture — Security Primitives

This document walks through how the four primitives in this repository fit into the broader Orchestrator pipeline. It's aimed at security-minded readers (CISOs, security engineers, compliance auditors) who want to understand the design before evaluating the closed-source product.

## The pipeline at a glance

Orchestrator runs a five-stage pipeline for every IAM action:

```
  Slack message / HRIS event / webhook
              │
              ▼
       01 / Parse    (gatekeeper — Gemini intent extraction + adversarial filter)
              │
              ▼
       02 / Verify   (parallel HRIS + asset + portal lookups)
              │
              ▼
       03 / Score    (deterministic risk score; explainable)
              │
              ▼
       04 / Gate     (OPA evaluates policies/iam_policy.rego ← in this repo)
              │
              ▼
       05 / Execute  (doer-agent — JIT Vault credential, parallel portal calls)
              │
              ▼
       Tamper-evident WORM ledger  (audit/audit_logger.py ← in this repo)
```

Stages 01–03 produce a structured `IntentPacket`. Stage 04 evaluates the packet against the OPA policy in this repo. If allowed, the gatekeeper signs the packet (HMAC-SHA256 — see `signing/packet_signing.py`) and forwards it to the doer. The doer verifies the signature before executing any portal action; mismatched signatures fail closed.

## Primitive 1 — The OPA gate

**File:** `policies/iam_policy.rego` (production-identical, runnable)
**Tests:** `policies/iam_policy_test.rego` (50+ cases)

This is the single source of truth for which actions Orchestrator will execute. The gate:

- Defaults to **deny** (`default allow := false`) — explicit allow required.
- Requires a `tenant_id` on every decision; bare requests fail closed.
- Defines four risk levels (low / medium / high / critical) keyed off `risk_score`.
- Routes high-risk (0.75 ≤ score < 0.95) decisions to **human-in-the-loop** approval.
- **Hard-blocks** specific patterns: legal hold, critical-risk privileged involuntary separation, intent-types whose preconditions don't match (e.g., an offboard for someone HRIS says isn't terminated).

The policies you read here are byte-identical to what runs against every production decision. Customers can extend with tenant-specific Rego packs — those overlay rather than replace.

### Test it yourself

```bash
opa test policies/ -v
```

Each test exercises a distinct allow / HITL / block branch. The fixtures (`base_input` and `with_metadata()` in the test file) document exactly what data the policy expects.

## Primitive 2 — Packet signing

**File:** `signing/packet_signing.py` (excerpt, illustrative)

Every decision that passes the OPA gate is wrapped in a signed envelope before reaching the executor. Algorithm today is **HMAC-SHA256** with a per-tenant shared secret stored in Vault.

```
envelope = base64(json({
  "payload": { ...intent_packet, "signed_at": <ISO-8601> },
  "signature": "<HMAC-SHA256(secret_key, sort_keys(payload))>"
}))
```

Properties:

- **Replay protection** — a `signed_at` more than 5 minutes from the verifier's clock is rejected with `reason="expired"`.
- **Constant-time comparison** — `hmac.compare_digest` prevents byte-by-byte timing extraction.
- **Strict envelope** — malformed / missing / extra fields all return a generic `bad_signature` from the verifier so attackers cannot enumerate failure modes.
- **Tz-aware required** — naive timestamps are rejected to prevent UTC-implicit drift attacks.
- **Empty-key fail-closed** — verification with an empty key returns `empty_key`, never accepts silently.

### Roadmap

The current HMAC-SHA256 implementation requires both gatekeeper and doer to share the same per-tenant secret. We are migrating to **per-tenant Ed25519 keypairs** so that a compromised doer cannot forge gatekeeper decisions:

- Gatekeeper holds the private key (fetched JIT from Vault for signing).
- Doer holds only the public key (also JIT, for verification).
- Doer compromise no longer compromises signing.

The marketing site notes this on `/security` and `/how-it-works`.

## Primitive 3 — WORM audit chain

**File:** `audit/audit_logger.py` (excerpt, illustrative)
**Helper:** `audit/audit_client.py` (excerpt, illustrative — write-side HTTP client)

Every decision, execution, and credential lease emits an event to an append-only ledger. Each event's hash is computed as `SHA-256(prev_chain_hash || canonical(event_minus_chain_hash))`. The result is a hash-chained log that an auditor can verify themselves: any tampering with any past event invalidates the chain from that point forward.

Key design properties:

- **Genesis-seeded.** A fresh deployment starts with `prev_hash = "genesis"`. After the first restart, `load_chain_head()` is called from the lifespan startup hook to reload the durable chain head from Postgres before any new event is written.
- **Chain head fail-closed on reload error.** If the DB is reachable but the head query fails, the service refuses to boot rather than silently re-seeding from `"genesis"` (which would mask post-restart tampering of the pre-restart tail).
- **Segments are explicit.** `verify_chain` tolerates segment boundaries (so legitimate restarts don't flip the log to `TAMPERED`) and reports `chain_segments` in its result. An auditor seeing `2 segments` knows there was a restart and can correlate with deployment records.
- **GDPR Art. 4(5) pseudonymisation.** Every personal data field (e.g., target emails embedded in action strings) is replaced with a per-tenant HMAC-SHA256 digest before being written to disk or DB. Correlation within a tenant is preserved (deterministic for `(tenant_id, value)`); rotation of the per-tenant key satisfies Art. 17 right-to-erasure without deleting records.
- **Dual-write.** Each event lands in a daily JSONL file (durable, easy for an auditor to scan) and asynchronously to Postgres (queryable). File write is synchronous; DB write is fire-and-forget so audit pressure never blocks the request path.

## Primitive 4 — Configuration gating

**Files:** `policy-helpers/auth.py`, `policy-helpers/config_validation.py` (excerpts)

These are the boring-but-important gating helpers:

- **`auth.py`** centralises the dev-vs-prod API-key policy across services. Dev mode returns silently (`return`); prod with empty key returns 503; prod with mismatched key returns 401.
- **`config_validation.py`** runs at every service's lifespan startup. In production mode, missing or default-valued credentials raise a single `ConfigError` listing every offender. The service refuses to boot — there is no in-flight code path that can be reached with a default credential.

The dev/prod boundary is enforced **at startup**, not in the request path. Once a prod service has booted, it cannot accidentally fall back to dev behaviour at runtime. This is enforced by the absence of any environment re-evaluation after startup.

## Threat model

Orchestrator's explicit threat model — what we defend against and how:

| Threat | Mitigation | File |
|---|---|---|
| Prompt injection in intake | Deterministic post-filter clamps confidence < 0.4, scrubs target identity, fires HITL | (closed-source `intent_engine.py`) |
| Stale long-lived credentials | Vault JIT leases, 60-second TTL, per-tenant path | (closed-source `credential_vault.py`) |
| Forged decisions | HMAC-SHA256 packet signing today; Ed25519 on roadmap | `signing/packet_signing.py` |
| Silent tampering of audit | Hash-chained WORM ledger, durable chain-head reload, segment reporting | `audit/audit_logger.py` |
| Privileged account abuse | OPA policy hard-blocks critical-risk + involuntary + privileged combinations | `policies/iam_policy.rego` |
| Misconfigured deployment | `config_validation.py` boot guard refuses prod start with missing or default fields | `policy-helpers/config_validation.py` |

## What's explicitly out of scope

Orchestrator does **not**:

- Auto-execute outside the IAM domain. There is no "general agent" loop — the pipeline is a finite state machine with five named stages.
- Edit policy via UI. OPA policy is git-versioned alongside customer infrastructure; the admin UI displays it read-only.
- Store long-lived customer credentials in application memory. Tokens live in Vault and are leased JIT per execution.
- Dial home. No telemetry beacons or usage analytics. The only outbound traffic from a tenant deployment is to the portals it's configured to manage.

## Questions

For anything not covered here, the [pilot application form](https://iam-orchestrator.pages.dev/#cta) is the fastest path to a security-review call.
