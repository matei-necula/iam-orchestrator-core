package iam.policy

import future.keywords.if
import future.keywords.in

# ─────────────────────────────────────────────────────────────
# Fixture helpers
# ─────────────────────────────────────────────────────────────

# Base input for a low-risk, terminated, non-privileged offboard.
# Individual tests override fields via object.union.
base_input := {
    "tenant_id":             "default",
    "intent_type":           "offboard",
    "risk_score":            0.30,
    "involuntary_separation": false,
    "metadata": {
        "employment_status":       "terminated",
        "legal_hold":              false,
        "is_privileged_account":   false,
        "owns_production_services": false,
    },
}

with_metadata(overrides) := result if {
    result := object.union(
        base_input,
        {"metadata": object.union(base_input.metadata, overrides)},
    )
}

# ─────────────────────────────────────────────────────────────
# allow — happy path + blocking conditions
# ─────────────────────────────────────────────────────────────

test_allow_low_risk_terminated_offboard if {
    allow with input as base_input
}

test_allow_provision_for_terminated if {
    allow with input as object.union(base_input, {"intent_type": "provision"})
}

test_allow_audit_when_no_legal_hold if {
    allow with input as object.union(
        base_input,
        {"intent_type": "audit", "risk_score": 0.90},
    )
}

test_deny_when_legal_hold if {
    not allow with input as with_metadata({"legal_hold": true})
}

test_deny_offboard_when_not_terminated if {
    not allow with input as with_metadata({"employment_status": "active"})
}

test_deny_when_high_risk_score if {
    not allow with input as object.union(base_input, {"risk_score": 0.80})
}

test_deny_when_tenant_id_blank if {
    not allow with input as object.union(base_input, {"tenant_id": ""})
}

# ─────────────────────────────────────────────────────────────
# requires_hitl — high-risk / privileged / prod-owner paths
# ─────────────────────────────────────────────────────────────

test_requires_hitl_on_high_risk_score if {
    requires_hitl with input as object.union(base_input, {"risk_score": 0.80})
}

test_requires_hitl_on_privileged_account if {
    requires_hitl with input as with_metadata({"is_privileged_account": true})
}

test_requires_hitl_on_production_owner if {
    requires_hitl with input as with_metadata({"owns_production_services": true})
}

test_no_hitl_on_low_risk_standard_user if {
    not requires_hitl with input as base_input
}

test_no_hitl_when_critical_risk if {
    # critical (≥0.95) should be blocked outright, not routed through HITL
    not requires_hitl with input as object.union(base_input, {"risk_score": 0.96})
}

test_no_hitl_under_legal_hold if {
    # legal_hold short-circuits; HITL should not apply either
    not requires_hitl with input as object.union(
        with_metadata({"legal_hold": true}),
        {"risk_score": 0.80},
    )
}

# ─────────────────────────────────────────────────────────────
# risk_level — boundary classification
# ─────────────────────────────────────────────────────────────

test_risk_level_low if {
    risk_level == "low"
    with input as object.union(base_input, {"risk_score": 0.39})
}

test_risk_level_medium_lower_bound if {
    risk_level == "medium"
    with input as object.union(base_input, {"risk_score": 0.40})
}

test_risk_level_medium_upper_bound if {
    risk_level == "medium"
    with input as object.union(base_input, {"risk_score": 0.74})
}

test_risk_level_high_lower_bound if {
    risk_level == "high"
    with input as object.union(base_input, {"risk_score": 0.75})
}

test_risk_level_high_upper_bound if {
    risk_level == "high"
    with input as object.union(base_input, {"risk_score": 0.94})
}

test_risk_level_critical if {
    risk_level == "critical"
    with input as object.union(base_input, {"risk_score": 0.95})
}

# ─────────────────────────────────────────────────────────────
# block_reasons — hard blocks
# ─────────────────────────────────────────────────────────────

test_block_on_legal_hold if {
    block_reasons["user_under_legal_hold"] with input as {
        "tenant_id": "default",
        "intent_type": "offboard",
        "risk_score": 0.30,
        "involuntary_separation": false,
        "metadata": {
            "employment_status": "terminated",
            "legal_hold": true,
            "is_privileged_account": false,
            "owns_production_services": false,
        },
    }
}

test_block_offboard_when_not_terminated_in_hris if {
    block_reasons["user_not_confirmed_terminated_in_hris"] with input as {
        "tenant_id": "default",
        "intent_type": "offboard",
        "risk_score": 0.30,
        "involuntary_separation": false,
        "metadata": {
            "employment_status": "active",
            "legal_hold": false,
            "is_privileged_account": false,
            "owns_production_services": false,
        },
    }
}

test_block_critical_privileged_involuntary if {
    block_reasons["critical_risk_privileged_involuntary_separation"] with input as {
        "tenant_id": "default",
        "intent_type": "offboard",
        "risk_score": 0.96,
        "involuntary_separation": true,
        "metadata": {
            "employment_status": "terminated",
            "legal_hold": false,
            "is_privileged_account": true,
            "owns_production_services": false,
        },
    }
}

test_no_block_reasons_on_happy_path if {
    count(block_reasons) == 0 with input as base_input
}
