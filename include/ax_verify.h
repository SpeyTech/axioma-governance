/**
 * @file ax_verify.h
 * @brief Cross-Layer Verification Protocol — L7 Governance
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Implements the 8-step cross-layer verification protocol (§6).
 * Each step produces a committed AX:PROOF:v1 record. All proofs
 * must be committed before dependent execution proceeds
 * (proof-before-execution invariant, SRS-007-SHALL-047).
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-011: Verification chain
 * @traceability SRS-007-SHALL-047: Proof-before-execution invariant
 * @traceability SRS-007-SHALL-058: Atomicity model
 */

#ifndef AX_VERIFY_H
#define AX_VERIFY_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ax_governance.h"
#include "ax_proof.h"
#include "ax_trace.h"

/**
 * @brief Cross-layer verification context
 *
 * Carries the inputs required for each verification step.
 * All fields are committed evidence hashes — no live state.
 *
 * @traceability SRS-007-SHALL-002: Evidence closure
 */
typedef struct {
    /* L1 substrate */
    uint8_t  substrate_cert_hash[32];   /**< Hash of forbidden-pattern-scan result */
    bool     substrate_cert_present;

    /* L2 weight binding */
    uint8_t  weight_hash[32];           /**< SHA-256 of quantised weight tensor */
    uint8_t  model_id_hash[32];         /**< Hash of model_id from AX:OBS:v1 */
    bool     weight_binding_present;

    /* L3 observation */
    uint8_t  obs_record_hash[32];       /**< SHA-256 of AX:OBS:v1 record */
    uint8_t  obs_hash_field[32];        /**< obs_hash field extracted from record */
    uint64_t obs_ledger_seq;            /**< ledger_seq from AX:OBS:v1 */
    bool     obs_present;

    /* L4 policy */
    uint8_t  policy_record_hash[32];    /**< SHA-256 of AX:POLICY:v1 record */
    uint64_t policy_obs_ledger_seq;     /**< obs_ledger_seq from AX:POLICY:v1 */
    uint64_t policy_ledger_seq;         /**< ledger_seq of AX:POLICY:v1 */
    int      policy_result;             /**< 0 = PERMITTED, 1 = BREACH */
    bool     policy_present;

    /* L5 transition */
    uint8_t  trans_record_hash[32];     /**< SHA-256 of AX:TRANS:v1 record */
    uint64_t trans_ledger_seq;          /**< ledger_seq of AX:TRANS:v1 */
    int      trans_next_state;          /**< AX_AGENT_STATE_* value */
    bool     trans_present;

    /* L6 chain */
    uint8_t  chain_head[32];            /**< Current L6 chain head */
    uint64_t chain_ledger_seq;          /**< Current ledger_seq */

    /* Replay verification */
    uint8_t  genesis_state_hash[32];    /**< Initial state hash */
    uint8_t  expected_replay_hash[32];  /**< Expected final state after replay */
    bool     replay_present;
} ax_verify_ctx_t;

/**
 * @brief Verification step result
 *
 * @traceability SRS-007-SHALL-011: Each step produces AX:PROOF:v1
 */
typedef struct {
    ax_proof_record_t proof;    /**< Committed AX:PROOF:v1 for this step */
    bool              passed;   /**< Whether step passed */
} ax_verify_result_t;

/**
 * @brief Initialise verification context
 *
 * @param ctx Context to initialise
 * @param chain_head Current L6 chain head
 * @param chain_ledger_seq Current ledger sequence
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-002: Evidence closure
 */
void ax_verify_ctx_init(
    ax_verify_ctx_t      *ctx,
    const uint8_t         chain_head[32],
    uint64_t              chain_ledger_seq,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Step 1 — L1 Substrate Certification (SRS-007-SHALL-012)
 *
 * Verifies certifiable-inference was compiled against libaxilog
 * with no forbidden arithmetic patterns.
 *
 * @param ctx Verification context
 * @param result Output proof record
 * @param gov Governance context (chain head, seq)
 * @param faults Fault context
 * @return 0 on success, -1 on integrity fault
 *
 * @traceability SRS-007-SHALL-012: L1 substrate certification
 */
int ax_verify_substrate_cert(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Step 2 — L2 Weight-to-Evidence Binding (SRS-007-SHALL-013)
 *
 * Verifies: WeightHash(L2) ≡ ModelID(L3.AX:OBS:v1.model_id)
 *
 * @param ctx Verification context
 * @param result Output proof record
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 on integrity fault (weight mismatch)
 *
 * @traceability SRS-007-SHALL-013: L2 weight binding
 * @traceability SRS-007-SHALL-048: Weight hash specification
 */
int ax_verify_weight_binding(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Step 3 — L3 Observation Integrity (SRS-007-SHALL-014)
 *
 * Verifies obs_hash = SHA-256(canonical_record_without_obs_hash).
 *
 * @param ctx Verification context
 * @param result Output proof record
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 on hash mismatch (integrity fault)
 *
 * @traceability SRS-007-SHALL-014: L3 observation integrity
 */
int ax_verify_obs_integrity(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Step 4 — L4 Policy Soundness Verification (SRS-007-SHALL-015)
 *
 * Verifies all active policies satisfy the Policy Soundness
 * Requirement (deterministic, evidence-closed, independently
 * verifiable).
 *
 * @param ctx Verification context
 * @param result Output proof record
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 if policy non-conformant
 *
 * @traceability SRS-007-SHALL-015: L4 policy soundness
 * @traceability SRS-007-SHALL-008: Policy soundness requirement
 */
int ax_verify_policy_soundness(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Step 5 — L3→L4 Observation-to-Policy Binding (SRS-007-SHALL-016)
 *
 * Verifies: AX:POLICY:v1.obs_ledger_seq → AX:OBS:v1.ledger_seq
 *
 * @param ctx Verification context
 * @param result Output proof record
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 on broken binding (integrity fault)
 *
 * @traceability SRS-007-SHALL-016: L3→L4 obs-policy binding
 */
int ax_verify_obs_policy_binding(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Step 6 — L4→L5 Breach-to-Transition Enforcement (SRS-007-SHALL-017)
 *
 * Verifies: if L4 result = BREACH, then L5 next_state ∈ {ALARM, STOPPED}
 *
 * @param ctx Verification context
 * @param result Output proof record
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 if transition enforcement violated
 *
 * @traceability SRS-007-SHALL-017: L4→L5 breach enforcement
 */
int ax_verify_breach_enforcement(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Step 7 — L5→L6 Pre-Commit Ordering (SRS-007-SHALL-018)
 *
 * Verifies ordering invariant:
 *   AX:OBS:v1 (N) → AX:POLICY:v1 (N+1..N+k) → AX:TRANS:v1 (N+k+1)
 *
 * @param ctx Verification context
 * @param result Output proof record
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 on ordering violation (integrity fault)
 *
 * @traceability SRS-007-SHALL-018: L5→L6 pre-commit ordering
 */
int ax_verify_precommit_ordering(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Step 8 — Full Chain Replay Verification (SRS-007-SHALL-019)
 *
 * Verifies that replay of the evidence chain produces identical
 * records and final state.
 *
 * @param ctx Verification context
 * @param result Output proof record
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 if replay mismatch
 *
 * @traceability SRS-007-SHALL-019: Full chain replay
 */
int ax_verify_replay(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t    *result,
    ax_gov_ctx_t          *gov,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Run all 8 verification steps in sequence
 *
 * Stops at first integrity fault. Each passing step's proof is
 * committed to the provided proof array (must have capacity >= 8).
 *
 * This function enforces the proof-before-execution invariant
 * (SRS-007-SHALL-047) by requiring single-threaded sequencing
 * (Option A atomicity model, SRS-007-SHALL-058).
 *
 * @param ctx Verification context
 * @param results Output array (8 entries)
 * @param gov Governance context
 * @param steps_completed Number of steps completed (output)
 * @param faults Fault context
 * @return 0 if all steps pass, -1 if any step fails
 *
 * @traceability SRS-007-SHALL-011: Verification chain
 * @traceability SRS-007-SHALL-047: Proof-before-execution invariant
 * @traceability SRS-007-SHALL-058: Atomicity model (Option A)
 */
int ax_verify_all(
    const ax_verify_ctx_t *ctx,
    ax_verify_result_t     results[8],
    ax_gov_ctx_t          *gov,
    int                   *steps_completed,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Build a verification proof record
 *
 * Internal helper: initialise, add evidence, set result, finalise.
 *
 * @param proof Output proof record
 * @param claim Governance claim string
 * @param proof_type Proof classification
 * @param rule_id SRS requirement being proven
 * @param evidence_hashes Array of evidence hashes
 * @param evidence_count Number of evidence hashes
 * @param result VALID | INVALID | INTEGRITY_FAULT
 * @param violation Violation type (if not VALID)
 * @param gov Governance context (provides chain head and seq)
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-003: Proof commitment
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
);

#ifdef __cplusplus
}
#endif

#endif /* AX_VERIFY_H */
