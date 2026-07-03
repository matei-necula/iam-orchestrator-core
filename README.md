# iam-orchestrator-core

> Security primitives of the [Orchestrator](https://iamorchestrator.com/) IAM platform — open for evaluation.

This repository is a **source-available review copy** of the security-load-bearing components of the closed-source [iam-orchestrator](https://iamorchestrator.com/) product. It exists so prospective customers can read the OPA policies, the packet-signing implementation, and the tamper-evident audit chain *before* signing anything.

It is **not a working build.** It is a curated subset of files lifted from the production codebase, with the closed-source service tree, customer configuration, and deployment infrastructure deliberately excluded.

## What's in here

```
.
├── policies/             # OPA Rego policies (full, runnable)
│   ├── iam_policy.rego           — the policy gate every action passes
│   └── iam_policy_test.rego      — 50+ tests covering allow / HITL / block
├── signing/              # Packet signing primitives (excerpt)
│   └── packet_signing.py         — HMAC-SHA256 sign + verify with replay protection
├── audit/                # WORM audit chain (excerpt)
│   ├── audit_logger.py           — hash-chained ledger, GDPR pseudonymisation
│   └── audit_client.py           — uniform write-side HTTP client
├── policy-helpers/       # Cross-service config + auth primitives (excerpt)
│   ├── auth.py                   — API-key check policy
│   └── config_validation.py      — fail-fast prod boot guard
├── docs/
│   └── ARCHITECTURE.md           — how the pieces fit together
└── LICENSE               # Source-available evaluation license
```

## What's NOT in here

By design, this repository **excludes**:

- The FastAPI services that wire the primitives together (`gatekeeper`, `doer-agent`, `licensing-orchestrator`, `zero-trust`, `admin-ui`)
- Database migrations and schemas
- HRIS / SaaS connector implementations (Okta, M365, Google Workspace, GitHub, Slack, etc.)
- Customer configuration, tenant credentials, signing keys
- Deployment manifests, infrastructure-as-code, secrets
- Internal documentation, runbooks, incident notes
- Commit history (this is a fresh-init repo; the closed-source history stays closed)

If reading any of the included files raises a question about how a primitive is wired into the broader system, ask via the [pilot application form](https://iamorchestrator.com/) — happy to walk through it on a call.

## Runnable parts

### OPA policy tests (recommended)

The Rego policies are byte-identical to what runs in production. You can run the full test suite yourself:

```bash
# Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa
opa test policies/ -v
```

Expected: all tests pass. Each test exercises a specific allow / HITL / block case (legal hold, privileged account, production owner, low-risk terminated, etc.).

### Python excerpts (read-only)

The `.py` files under `signing/`, `audit/`, and `policy-helpers/` are excerpts. They reference `shared.utils.*` and `services.*` modules that aren't included here, so they will not import cleanly in isolation. They're meant for code review, not execution.

If you want to see them running, request a screen-share demo via the [pilot application form](https://iamorchestrator.com/).

## Dev/prod boundary

A few files contain conditional fail-open behaviour for local development. Each is gated on the `ENVIRONMENT` setting (`development` vs `production`):

- `policy-helpers/auth.py` — dev returns silently from the API-key check; prod refuses to boot with empty keys (via `config_validation.py`) and 401s on mismatch.
- `audit/audit_logger.py` line 70 — dev falls back to a literal `"dev-insecure-key"` for HMAC pseudonymisation when `WORM_PSEUDONYM_KEY` is unset. **This string is intentionally weak and public.** Production deployments fail fast at boot if the real key is unset.

The dev/prod boundary is enforced at startup, not in the request hot path, so a prod deployment cannot accidentally fall back to dev behaviour at runtime.

## License

Source-available, evaluation-only. See [LICENSE](./LICENSE). Briefly:

- **You may** read this code to evaluate Orchestrator as a prospective customer.
- **You may not** reproduce, redistribute, modify, or use this code outside of an evaluation context.
- For any other use, contact the maintainer for a written agreement.

## Contributing

This repository does not accept pull requests — it is a published view of the upstream closed-source codebase, not a community project.

**Security findings** should be reported privately via the [pilot application form](https://iamorchestrator.com/) with the subject "security disclosure". We acknowledge within 72 hours and follow a coordinated disclosure process.

## Related

- **Marketing site:** https://iamorchestrator.com/
- **How it works:** https://iamorchestrator.com/how-it-works
- **Security model:** https://iamorchestrator.com/security
- **Integrations:** https://iamorchestrator.com/integrations
- **Pricing:** https://iamorchestrator.com/pricing
