package iam.policy

import future.keywords.if
import future.keywords.in

default allow := false
default requires_hitl := false
default risk_level := "low"

# ── Tenant guard — every decision requires a tenant_id ────
# In single-tenant deployments this is always "default".
# In multi-tenant SaaS the calling service passes the real tenant_id.
tenant_ok if { input.tenant_id != "" }
tenant_ok if { input.tenant_id == "default" }

# ── Allow low/medium risk standard operations ─────────────
allow if {
    tenant_ok
    input.intent_type in {"offboard", "provision", "modify"}
    input.risk_score < 0.75
    input.metadata.employment_status == "terminated"
    input.metadata.legal_hold == false
    input.metadata.is_privileged_account == false
    input.metadata.owns_production_services == false
}

# Allow medium risk non-privileged terminated users (dev + prod)
allow if {
    tenant_ok
    input.intent_type in {"offboard", "provision", "modify"}
    input.risk_score < 0.75
    input.metadata.employment_status == "terminated"
    input.metadata.legal_hold == false
}

allow if {
    tenant_ok
    input.intent_type == "audit"
    input.metadata.legal_hold == false
}

# ── Require HITL for high-risk (0.75–0.94) ────────────────
requires_hitl if {
    input.risk_score >= 0.75
    input.risk_score < 0.95
    input.metadata.legal_hold == false
}

requires_hitl if {
    input.metadata.is_privileged_account == true
    input.risk_score < 0.95
    input.metadata.legal_hold == false
}

requires_hitl if {
    input.metadata.owns_production_services == true
    input.risk_score < 0.95
    input.metadata.legal_hold == false
}

# ── Risk level classification ─────────────────────────────
risk_level := "critical" if { input.risk_score >= 0.95 }
risk_level := "high"     if { input.risk_score >= 0.75; input.risk_score < 0.95 }
risk_level := "medium"   if { input.risk_score >= 0.40; input.risk_score < 0.75 }
risk_level := "low"      if { input.risk_score < 0.40 }

# ── Hard blocks ───────────────────────────────────────────
block_reasons[reason] if {
    input.metadata.legal_hold == true
    reason := "user_under_legal_hold"
}

block_reasons[reason] if {
    input.risk_score >= 0.95
    input.metadata.is_privileged_account == true
    input.involuntary_separation == true
    reason := "critical_risk_privileged_involuntary_separation"
}

block_reasons[reason] if {
    input.metadata.employment_status != "terminated"
    input.intent_type == "offboard"
    reason := "user_not_confirmed_terminated_in_hris"
}
