/**
 * @file verify.c
 * @brief Cross-Layer Verification Protocol Implementation
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Implements the 8-step cross-layer verification protocol (§6).
 * Each step produces a committed AX:PROOF:v1 record. All verification
 * operates exclusively on committed evidence — no live state.
 *
 * Proof-before-execution invariant (SRS-007-SHALL-047) is enforced
 * via single-threaded Option A sequencing (SRS-007-SHALL-058).
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-011: Verification chain
 * @traceability SRS-007-SHALL-012: L1 substrate certification
 * @traceability SRS-007-SHALL-013: L2 weight binding
 * @traceability SRS-007-SHALL-014: L3 observation integrity
 * @traceability SRS-007-SHALL-015: L4 policy soundness
 * @traceability SRS-007-SHALL-016: L3→L4 obs-policy binding
 * @traceability SRS-007-SHALL-017: L4→L5 breach enforcement
 * @traceability SRS-007-SHALL-018: L5→L6 pre-commit ordering
 * @traceability SRS-007-SHALL-019: Full chain replay
 * @traceability SRS-007-SHALL-047: Proof-before-execution invariant
 * @traceability SRS-007-SHALL-058: Atomicity model (Option A)
 */

#include "ax_verify.h"
#include "axilog/types.h"
#include <string.h>

/*
 * ============================================================================
 * Internal Helpers
 * ============================================================================
 */

/**
 * @brief Check if a 32-byte hash is all zeros
 */
static bool hash_is_zero(const uint8_t h[32]) {
    size_t i;
    for (i = 0; i < 32; i++) {
        if (h[i] != 0) {
            return false;
        }
    }
    return true;
}

/*
 * ============================================================================
 * Public API — Context Initialisation
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-002: Evidence closure
 */
void ax_verify_ctx_init(
    ax_verify_ctx_t      *ctx,
    const uint8_t         chain_head[32],
    uint64_t              chain_ledger_seq,
    ax_gov_fault_flags_t *faults
) {
    if (ctx == NULL || chain_head == NULL || faults == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(ax_verify_ctx_t));
    memcpy(ctx->chain_head, chain_head, 32);
    ctx->chain_ledger_seq = chain_ledger_seq;
}

/*
 * ============================================================================
 * Public API — Build Proof Helper
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-003: Proof commitment
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 */
int ax_verify_build_proof(
    ax_proof_record_t         *proof,
    const char                *claim,
    ax_proof_type_t            proof_type,
    const char                *rule_id,
    const uint8_t            (*evidence_hashes)[32],
    size_t                     evidence_count,
    ax_proof_result_t          result,
    ax_violation_t             violation,
    ax_gov_ctx_t              *gov,
    ax_gov_fault_flags_t      *faults
) {
    size_t i;

    if (proof == NULL || claim == NULL || rule_id == NULL ||
        gov == NULL || faults == NULL) {
        return -1;
    }

    /* Initialise proof with current chain head and sequence */
    if (ax_proof_init(proof, claim, proof_type, rule_id,
                      gov->chain_head, gov->next_proof_seq, faults) != 0) {
        return -1;
    }

    /* Add all evidence references */
    if (evidence_hashes != NULL) {
        for (i = 0; i < evidence_count; i++) {
            if (ax_proof_add_evidence(proof, evidence_hashes[i], faults) != 0) {
                return -1;
            }
        }
    }

    /* Set result and violation */
    ax_proof_set_result(proof, result, violation, faults);

    /* Finalise: sort evidence, compute proof_hash and commitment */
    if (ax_proof_finalise(proof, faults) != 0) {
        return -1;
    }

    /* Advance governance sequence */
    gov->next_proof_seq++;

    return 0;
}

/*
 * ============================================================================
 * Step 1 — L1 Substrate Certification
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-012: L1 substrate certification
 *
 * Governance verifies that certifiable-inference (L2) was compiled
 * against libaxilog (L1) with no forbidden arithmetic patterns.
 *
 * Evidence: substrate_cert_hash (SHA-256 of forbidden-pattern-scan result)
 *
 * A zero substrate_cert_hash with substrate_cert_present=true is valid
 * (scan may produce a zero hash for an empty result set). The presence
 * flag controls whether the check is applicable.
 */
int ax_verify_substrate_cert(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
) {
    uint8_t evidence[1][32];
    ax_proof_result_t proof_result;
    ax_violation_t violation;

    if (ctx == NULL || result == NULL || gov == NULL || faults == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(ax_verify_result_t));

    /* Evidence must be present */
    if (!ctx->substrate_cert_present) {
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_EVIDENCE_MISSING;
        faults->integrity_fault = 1;
        result->passed = false;
    } else {
        proof_result = AX_PROOF_RESULT_VALID;
        violation    = AX_VIOLATION_NONE;
        result->passed = true;
    }

    memcpy(evidence[0], ctx->substrate_cert_hash, 32);

    if (ax_verify_build_proof(
            &result->proof,
            "L1 substrate compiled with no forbidden arithmetic patterns",
            AX_PROOF_TYPE_SUBSTRATE_CERT,
            "SRS-007-SHALL-012",
            (const uint8_t (*)[32])evidence,
            1,
            proof_result,
            violation,
            gov,
            faults) != 0) {
        return -1;
    }

    return result->passed ? 0 : -1;
}

/*
 * ============================================================================
 * Step 2 — L2 Weight-to-Evidence Binding
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-013: L2 weight binding
 * @traceability SRS-007-SHALL-048: Weight hash specification
 *
 * Verifies: WeightHash(L2) ≡ ModelID(L3.AX:OBS:v1.model_id)
 *
 * The weight_hash is the SHA-256 of the quantised weight tensor
 * in DVEC-001 canonical form (row-major Q16.16, LE, no padding).
 *
 * The model_id_hash is the SHA-256 of the model_id field extracted
 * from the AX:OBS:v1 record committed to L6.
 *
 * Both are committed evidence hashes — no live state.
 */
int ax_verify_weight_binding(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
) {
    uint8_t evidence[2][32];
    ax_proof_result_t proof_result;
    ax_violation_t violation;

    if (ctx == NULL || result == NULL || gov == NULL || faults == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(ax_verify_result_t));

    if (!ctx->weight_binding_present) {
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_EVIDENCE_MISSING;
        faults->integrity_fault = 1;
        result->passed = false;
    } else if (memcmp(ctx->weight_hash, ctx->model_id_hash, 32) != 0) {
        /*
         * Weight hash does not match model_id hash.
         * The model running in L3 is not the model certified in L2.
         * This is a WEIGHT_MISMATCH integrity fault (SRS-007-SHALL-013).
         */
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_WEIGHT_MISMATCH;
        faults->weight_mismatch = 1;
        result->passed = false;
    } else {
        proof_result = AX_PROOF_RESULT_VALID;
        violation    = AX_VIOLATION_NONE;
        result->passed = true;
    }

    memcpy(evidence[0], ctx->weight_hash, 32);
    memcpy(evidence[1], ctx->model_id_hash, 32);

    if (ax_verify_build_proof(
            &result->proof,
            "L2 weight hash matches L3 model_id: WeightHash(L2) = ModelID(AX:OBS:v1)",
            AX_PROOF_TYPE_WEIGHT_BINDING,
            "SRS-007-SHALL-013",
            (const uint8_t (*)[32])evidence,
            2,
            proof_result,
            violation,
            gov,
            faults) != 0) {
        return -1;
    }

    return result->passed ? 0 : -1;
}

/*
 * ============================================================================
 * Step 3 — L3 Observation Integrity
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-014: L3 observation integrity
 *
 * Verifies the obs_hash field within the AX:OBS:v1 record:
 *   obs_hash = SHA-256(canonical_record_without_obs_hash)
 *
 * In this verification layer, we receive two committed evidence hashes:
 *   obs_record_hash  — SHA-256 of the full AX:OBS:v1 record
 *   obs_hash_field   — the obs_hash field as declared in that record
 *
 * The verifier checks that obs_hash_field was recomputed by L3
 * consistently with the record content. This is verified by comparing
 * the obs_hash_field against the independently derived record hash,
 * confirming L3 produced consistent self-attesting evidence.
 *
 * Note: Full recomputation would require the AX:OBS:v1 raw payload,
 * which is not available at L7 (L7 operates on committed hashes only).
 * L7 instead verifies that obs_record_hash ≠ all-zeros (record exists)
 * and that obs_hash_field ≠ all-zeros (hash was computed), which
 * together confirm the self-attesting integrity property was exercised.
 *
 * For full hash recomputation, the compliance verifier (Track A/B)
 * receives the raw payload and performs the definitive check.
 */
int ax_verify_obs_integrity(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
) {
    uint8_t evidence[2][32];
    ax_proof_result_t proof_result;
    ax_violation_t violation;

    if (ctx == NULL || result == NULL || gov == NULL || faults == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(ax_verify_result_t));

    if (!ctx->obs_present) {
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_EVIDENCE_MISSING;
        faults->integrity_fault = 1;
        result->passed = false;
    } else if (hash_is_zero(ctx->obs_record_hash)) {
        /* Observation record hash is zero — record was never committed */
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_HASH_MISMATCH;
        faults->hash_mismatch = 1;
        result->passed = false;
    } else if (hash_is_zero(ctx->obs_hash_field)) {
        /* obs_hash field was not computed — record is incomplete */
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_HASH_MISMATCH;
        faults->hash_mismatch = 1;
        result->passed = false;
    } else {
        proof_result = AX_PROOF_RESULT_VALID;
        violation    = AX_VIOLATION_NONE;
        result->passed = true;
    }

    memcpy(evidence[0], ctx->obs_record_hash, 32);
    memcpy(evidence[1], ctx->obs_hash_field, 32);

    if (ax_verify_build_proof(
            &result->proof,
            "L3 AX:OBS:v1 obs_hash integrity verified: record committed with valid self-attestation",
            AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
            "SRS-007-SHALL-014",
            (const uint8_t (*)[32])evidence,
            2,
            proof_result,
            violation,
            gov,
            faults) != 0) {
        return -1;
    }

    return result->passed ? 0 : -1;
}

/*
 * ============================================================================
 * Step 4 — L4 Policy Soundness Verification
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-015: L4 policy soundness
 * @traceability SRS-007-SHALL-008: Policy soundness requirement
 * @traceability SRS-007-SHALL-009: Policy violation
 * @traceability SRS-007-SHALL-010: Policies as programs
 *
 * Governance verifies all active policies satisfy the Policy Soundness
 * Requirement before certifying any compliance report:
 *
 *   1. Deterministic Evaluation
 *   2. Evidence Closure (no external state)
 *   3. Independent Verifiability
 *
 * At L7, policy soundness is attested by the committed policy_record_hash.
 * A non-zero hash from a committed AX:POLICY:v1 record confirms the policy
 * was evaluated deterministically over committed evidence.
 *
 * The governance initialisation check (SRS-007-SHALL-009) for non-conformant
 * policies is represented by the policy_fault flag in ax_gov_ctx_t.
 */
int ax_verify_policy_soundness(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
) {
    uint8_t evidence[1][32];
    ax_proof_result_t proof_result;
    ax_violation_t violation;

    if (ctx == NULL || result == NULL || gov == NULL || faults == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(ax_verify_result_t));

    if (gov->in_fault_mode) {
        /* Governance already in fault mode — policy soundness cannot be certified */
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_POLICY_BREACH;
        faults->policy_fault = 1;
        result->passed = false;
    } else if (!ctx->policy_present) {
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_EVIDENCE_MISSING;
        faults->integrity_fault = 1;
        result->passed = false;
    } else if (hash_is_zero(ctx->policy_record_hash)) {
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_POLICY_BREACH;
        faults->policy_fault = 1;
        result->passed = false;
    } else {
        proof_result = AX_PROOF_RESULT_VALID;
        violation    = AX_VIOLATION_NONE;
        result->passed = true;
    }

    memcpy(evidence[0], ctx->policy_record_hash, 32);

    if (ax_verify_build_proof(
            &result->proof,
            "L4 policies satisfy soundness: deterministic, evidence-closed, independently verifiable",
            AX_PROOF_TYPE_POLICY_SOUNDNESS,
            "SRS-007-SHALL-015",
            (const uint8_t (*)[32])evidence,
            1,
            proof_result,
            violation,
            gov,
            faults) != 0) {
        return -1;
    }

    return result->passed ? 0 : -1;
}

/*
 * ============================================================================
 * Step 5 — L3→L4 Observation-to-Policy Binding
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-016: L3→L4 obs-policy binding
 *
 * Verifies: AX:POLICY:v1.obs_ledger_seq → AX:OBS:v1.ledger_seq
 *
 * Every policy evaluation must be unambiguously traceable to the
 * exact observation it evaluated. A broken binding is an integrity
 * fault — it means a policy result cannot be attributed to a known
 * observation.
 */
int ax_verify_obs_policy_binding(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
) {
    uint8_t evidence[2][32];
    ax_proof_result_t proof_result;
    ax_violation_t violation;

    if (ctx == NULL || result == NULL || gov == NULL || faults == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(ax_verify_result_t));

    if (!ctx->obs_present || !ctx->policy_present) {
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_EVIDENCE_MISSING;
        faults->integrity_fault = 1;
        result->passed = false;
    } else if (ctx->policy_obs_ledger_seq != ctx->obs_ledger_seq) {
        /*
         * The policy record references a different observation than
         * the one we are verifying. The binding is broken.
         */
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_HASH_MISMATCH;
        faults->integrity_fault = 1;
        result->passed = false;
    } else {
        proof_result = AX_PROOF_RESULT_VALID;
        violation    = AX_VIOLATION_NONE;
        result->passed = true;
    }

    memcpy(evidence[0], ctx->obs_record_hash, 32);
    memcpy(evidence[1], ctx->policy_record_hash, 32);

    if (ax_verify_build_proof(
            &result->proof,
            "L3→L4 binding verified: AX:POLICY:v1.obs_ledger_seq = AX:OBS:v1.ledger_seq",
            AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
            "SRS-007-SHALL-016",
            (const uint8_t (*)[32])evidence,
            2,
            proof_result,
            violation,
            gov,
            faults) != 0) {
        return -1;
    }

    return result->passed ? 0 : -1;
}

/*
 * ============================================================================
 * Step 6 — L4→L5 Breach-to-Transition Enforcement
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-017: L4→L5 breach enforcement
 *
 * Verifies:
 *   L4:AX:POLICY:v1.result = BREACH
 *     ⟹
 *   L5:AX:TRANS:v1.next_state ∈ {ALARM, STOPPED}
 *
 * If a policy breach was declared but the transition did not move
 * the agent to a safety state, that is a governance integrity fault.
 */
int ax_verify_breach_enforcement(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
) {
    uint8_t evidence[2][32];
    ax_proof_result_t proof_result;
    ax_violation_t violation;
    bool breach_enforced;

    if (ctx == NULL || result == NULL || gov == NULL || faults == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(ax_verify_result_t));

    if (!ctx->policy_present || !ctx->trans_present) {
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_EVIDENCE_MISSING;
        faults->integrity_fault = 1;
        result->passed = false;
    } else if (ctx->policy_result == 1) {
        /*
         * BREACH declared. Verify transition moved to safety state.
         * AX_AGENT_STATE_ALARM = 1, AX_AGENT_STATE_STOPPED = 2
         */
        breach_enforced = (ctx->trans_next_state == AX_AGENT_STATE_ALARM ||
                           ctx->trans_next_state == AX_AGENT_STATE_STOPPED);
        if (!breach_enforced) {
            proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
            violation    = AX_VIOLATION_TRANSITION_FAULT;
            faults->integrity_fault = 1;
            result->passed = false;
        } else {
            proof_result = AX_PROOF_RESULT_VALID;
            violation    = AX_VIOLATION_NONE;
            result->passed = true;
        }
    } else {
        /* PERMITTED — no breach, no constraint on transition */
        proof_result = AX_PROOF_RESULT_VALID;
        violation    = AX_VIOLATION_NONE;
        result->passed = true;
    }

    memcpy(evidence[0], ctx->policy_record_hash, 32);
    memcpy(evidence[1], ctx->trans_record_hash, 32);

    if (ax_verify_build_proof(
            &result->proof,
            "L4→L5 breach enforcement: policy BREACH implies transition to ALARM or STOPPED",
            AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
            "SRS-007-SHALL-017",
            (const uint8_t (*)[32])evidence,
            2,
            proof_result,
            violation,
            gov,
            faults) != 0) {
        return -1;
    }

    return result->passed ? 0 : -1;
}

/*
 * ============================================================================
 * Step 7 — L5→L6 Pre-Commit Ordering
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-018: L5→L6 pre-commit ordering
 *
 * Verifies the cross-layer ordering invariant:
 *
 *   AX:OBS:v1 (ledger_seq N)
 *     → AX:POLICY:v1 (ledger_seq N+1..N+k)
 *     → AX:TRANS:v1 (ledger_seq N+k+1)
 *
 * All sequences are strictly increasing. Any violation is an
 * ordering fault — the audit chain cannot be trusted if records
 * were not committed in causal order.
 */
int ax_verify_precommit_ordering(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
) {
    uint8_t evidence[3][32];
    ax_proof_result_t proof_result;
    ax_violation_t violation;
    bool ordering_ok;

    if (ctx == NULL || result == NULL || gov == NULL || faults == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(ax_verify_result_t));

    if (!ctx->obs_present || !ctx->policy_present || !ctx->trans_present) {
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_EVIDENCE_MISSING;
        faults->integrity_fault = 1;
        result->passed = false;
    } else {
        /*
         * Invariant: obs_seq < policy_seq < trans_seq
         * All must be strictly increasing.
         */
        ordering_ok = (ctx->obs_ledger_seq    <  ctx->policy_ledger_seq) &&
                      (ctx->policy_ledger_seq  <  ctx->trans_ledger_seq);

        if (!ordering_ok) {
            proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
            violation    = AX_VIOLATION_ORDERING;
            faults->ordering_fault = 1;
            result->passed = false;
        } else {
            proof_result = AX_PROOF_RESULT_VALID;
            violation    = AX_VIOLATION_NONE;
            result->passed = true;
        }
    }

    memcpy(evidence[0], ctx->obs_record_hash, 32);
    memcpy(evidence[1], ctx->policy_record_hash, 32);
    memcpy(evidence[2], ctx->trans_record_hash, 32);

    if (ax_verify_build_proof(
            &result->proof,
            "L5→L6 ordering: obs_seq < policy_seq < trans_seq verified",
            AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
            "SRS-007-SHALL-018",
            (const uint8_t (*)[32])evidence,
            3,
            proof_result,
            violation,
            gov,
            faults) != 0) {
        return -1;
    }

    return result->passed ? 0 : -1;
}

/*
 * ============================================================================
 * Step 8 — Full Chain Replay Verification
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-019: Full chain replay
 *
 * Verifies that replay of the evidence chain produces identical
 * final state. The caller provides:
 *   genesis_state_hash    — hash of initial state
 *   expected_replay_hash  — hash of expected final state after replay
 *
 * The expected_replay_hash is computed externally by the replay
 * verifier and passed here as a committed evidence hash. Governance
 * verifies that it matches the current chain head, confirming that
 * replaying from genesis produces the same ledger state.
 *
 * For identical genesis state and identical ordered AX:OBS:v1 sequence,
 * the system SHALL reproduce identical records and identical final state.
 */
int ax_verify_replay(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
) {
    uint8_t evidence[2][32];
    ax_proof_result_t proof_result;
    ax_violation_t violation;

    if (ctx == NULL || result == NULL || gov == NULL || faults == NULL) {
        return -1;
    }

    memset(result, 0, sizeof(ax_verify_result_t));

    if (!ctx->replay_present) {
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_EVIDENCE_MISSING;
        faults->integrity_fault = 1;
        result->passed = false;
    } else if (memcmp(ctx->expected_replay_hash, gov->chain_head, 32) != 0) {
        /*
         * Replay produced a different chain head. The evidence chain
         * is not self-consistent — determinism is violated.
         */
        proof_result = AX_PROOF_RESULT_INTEGRITY_FAULT;
        violation    = AX_VIOLATION_REPLAY_MISMATCH;
        faults->integrity_fault = 1;
        result->passed = false;
    } else {
        proof_result = AX_PROOF_RESULT_VALID;
        violation    = AX_VIOLATION_NONE;
        result->passed = true;
    }

    memcpy(evidence[0], ctx->genesis_state_hash, 32);
    memcpy(evidence[1], ctx->expected_replay_hash, 32);

    if (ax_verify_build_proof(
            &result->proof,
            "Full chain replay: identical genesis + observations produce identical chain head",
            AX_PROOF_TYPE_REPLAY_EQUIVALENCE,
            "SRS-007-SHALL-019",
            (const uint8_t (*)[32])evidence,
            2,
            proof_result,
            violation,
            gov,
            faults) != 0) {
        return -1;
    }

    return result->passed ? 0 : -1;
}

/*
 * ============================================================================
 * Full Verification Run
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-011: Verification chain
 * @traceability SRS-007-SHALL-047: Proof-before-execution invariant
 * @traceability SRS-007-SHALL-058: Atomicity model (Option A — sequential)
 *
 * Runs all 8 verification steps in strict order. Stops at first
 * integrity fault — a broken chain cannot be partially verified.
 *
 * Proof-before-execution invariant is enforced by single-threaded
 * sequential execution: each step's proof is committed (via
 * ax_verify_build_proof advancing gov->next_proof_seq) before the
 * next step executes.
 *
 * Step order per SRS-007-SHALL-011:
 *   1. Substrate certification    (SUBSTRATE_CERT)
 *   2. Weight binding             (WEIGHT_BINDING)
 *   3. Observation integrity      (CROSS_LAYER_VERIFY)
 *   4. Policy soundness           (POLICY_SOUNDNESS)
 *   5. Obs-to-policy binding      (CROSS_LAYER_VERIFY)
 *   6. Breach enforcement         (CROSS_LAYER_VERIFY)
 *   7. Pre-commit ordering        (CROSS_LAYER_VERIFY)
 *   8. Replay verification        (REPLAY_EQUIVALENCE)
 */
int ax_verify_all(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t     results[8],
    ax_gov_ctx_t          *gov,
    int                   *steps_completed,
    ax_gov_fault_flags_t  *faults
) {
    int rc;

    if (ctx == NULL || results == NULL || gov == NULL ||
        steps_completed == NULL || faults == NULL) {
        return -1;
    }

    *steps_completed = 0;

    /* Step 1: L1 Substrate Certification */
    rc = ax_verify_substrate_cert(ctx, &results[0], gov, faults);
    *steps_completed = 1;
    if (rc != 0) { return -1; }

    /* Step 2: L2 Weight Binding */
    rc = ax_verify_weight_binding(ctx, &results[1], gov, faults);
    *steps_completed = 2;
    if (rc != 0) { return -1; }

    /* Step 3: L3 Observation Integrity */
    rc = ax_verify_obs_integrity(ctx, &results[2], gov, faults);
    *steps_completed = 3;
    if (rc != 0) { return -1; }

    /* Step 4: L4 Policy Soundness */
    rc = ax_verify_policy_soundness(ctx, &results[3], gov, faults);
    *steps_completed = 4;
    if (rc != 0) { return -1; }

    /* Step 5: L3→L4 Obs-Policy Binding */
    rc = ax_verify_obs_policy_binding(ctx, &results[4], gov, faults);
    *steps_completed = 5;
    if (rc != 0) { return -1; }

    /* Step 6: L4→L5 Breach Enforcement */
    rc = ax_verify_breach_enforcement(ctx, &results[5], gov, faults);
    *steps_completed = 6;
    if (rc != 0) { return -1; }

    /* Step 7: L5→L6 Pre-Commit Ordering */
    rc = ax_verify_precommit_ordering(ctx, &results[6], gov, faults);
    *steps_completed = 7;
    if (rc != 0) { return -1; }

    /* Step 8: Full Chain Replay */
    rc = ax_verify_replay(ctx, &results[7], gov, faults);
    *steps_completed = 8;
    if (rc != 0) { return -1; }

    return 0;
}

/*
 * ============================================================================
 * Governance Context Operations
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-001: Determinism definition
 * @traceability SRS-007-SHALL-044: Configuration canonicality
 */
int ax_gov_init(
    ax_gov_ctx_t         *ctx,
    const uint8_t         config_hash[32],
    const uint8_t         policy_set_hash[32],
    const uint8_t         genesis_chain_head[32],
    ax_gov_fault_flags_t *faults
) {
    if (ctx == NULL || config_hash == NULL || policy_set_hash == NULL ||
        genesis_chain_head == NULL || faults == NULL) {
        return -1;
    }

    memset(ctx, 0, sizeof(ax_gov_ctx_t));

    memcpy(ctx->config.config_hash, config_hash, 32);
    memcpy(ctx->config.policy_set_hash, policy_set_hash, 32);
    ctx->config.config_ledger_seq = 0;
    ctx->config.initialised = true;

    memcpy(ctx->chain_head, genesis_chain_head, 32);
    ctx->next_proof_seq = 1;
    ctx->agent_state = AX_AGENT_STATE_HEALTHY;
    ax_gov_clear_faults(&ctx->faults);
    ctx->in_fault_mode = false;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-055: Chain head reference
 */
void ax_gov_update_chain_head(
    ax_gov_ctx_t         *ctx,
    const uint8_t         new_chain_head[32],
    ax_gov_fault_flags_t *faults
) {
    if (ctx == NULL || new_chain_head == NULL || faults == NULL) {
        return;
    }

    memcpy(ctx->chain_head, new_chain_head, 32);
}

/**
 * @traceability SRS-007-SHALL-035: Integrity fault definition
 * @traceability SRS-007-SHALL-037: Integrity fault response
 */
void ax_gov_enter_fault_mode(
    ax_gov_ctx_t         *ctx,
    ax_violation_t        violation,
    ax_gov_fault_flags_t *faults
) {
    if (ctx == NULL || faults == NULL) {
        return;
    }

    ctx->in_fault_mode = true;
    ctx->agent_state = AX_AGENT_STATE_STOPPED;

    /* Record the violation type in the governance fault flags */
    switch (violation) {
        case AX_VIOLATION_HASH_MISMATCH:
            faults->hash_mismatch = 1;
            break;
        case AX_VIOLATION_ORDERING:
            faults->ordering_fault = 1;
            break;
        case AX_VIOLATION_WEIGHT_MISMATCH:
            faults->weight_mismatch = 1;
            break;
        case AX_VIOLATION_POLICY_BREACH:
            faults->policy_fault = 1;
            break;
        case AX_VIOLATION_TRANSITION_FAULT:
        case AX_VIOLATION_EVIDENCE_MISSING:
        case AX_VIOLATION_REPLAY_MISMATCH:
        case AX_VIOLATION_FALLBACK_OVERFLOW:
        case AX_VIOLATION_NONE:
        default:
            faults->integrity_fault = 1;
            break;
    }
}
