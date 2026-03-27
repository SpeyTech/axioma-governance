/**
 * @file ax_trace.h
 * @brief Mathematical Trace — Cross-Layer Evidence Chain
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * A Mathematical Trace links the complete evidence chain from oracle
 * input through policy evaluation and agent transition to the committed
 * ledger entry, with all intermediate evidence citations.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-020: Mathematical trace requirement
 * @traceability SRS-007-SHALL-021: Trace required fields
 * @traceability SRS-007-SHALL-022: Trace canonicality
 */

#ifndef AX_TRACE_H
#define AX_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ax_governance.h"

/**
 * @brief Mathematical Trace record structure
 *
 * Fields appear in lexicographic order per RFC 8785 (JCS):
 *   chain_head, obs_hash, obs_ledger_seq, policy_results, policy_seqs,
 *   proof_ledger_seq, trace_hash, trans_ledger_seq, trans_next_state,
 *   weight_hash
 *
 * @traceability SRS-007-SHALL-021: Trace required fields
 * @traceability SRS-007-SHALL-049: Trace array ordering
 */
typedef struct ax_math_trace {
    /* --- chain_head --- */
    uint8_t           chain_head[32];         /**< L6 chain head after all commits */

    /* --- obs_hash --- */
    uint8_t           obs_hash[32];           /**< AX:OBS:v1 observation hash */

    /* --- obs_ledger_seq --- */
    uint64_t          obs_ledger_seq;         /**< L3 oracle observation sequence */

    /* --- policy_results --- */
    ax_policy_result_t policy_results[AX_MAX_POLICIES]; /**< PERMITTED/BREACH per policy */
    size_t            policy_results_count;   /**< Number of policy results */

    /* --- policy_seqs --- */
    uint64_t          policy_seqs[AX_MAX_POLICIES];     /**< L4 policy sequences (ascending) */
    size_t            policy_seqs_count;      /**< Number of policy sequences */

    /* --- proof_ledger_seq --- */
    uint64_t          proof_ledger_seq;       /**< This proof record sequence */

    /* --- trace_hash --- */
    uint8_t           trace_hash[32];         /**< SHA-256 of canonical trace */
    bool              trace_hash_computed;    /**< Whether trace_hash is valid */

    /* --- trans_ledger_seq --- */
    uint64_t          trans_ledger_seq;       /**< L5 transition sequence */

    /* --- trans_next_state --- */
    ax_agent_state_t  trans_next_state;       /**< Resulting agent health state */

    /* --- weight_hash --- */
    uint8_t           weight_hash[32];        /**< L2 model fingerprint */
} ax_math_trace_t;

/**
 * @brief Initialise a Mathematical Trace record
 *
 * @param trace Trace record to initialise
 * @param obs_hash AX:OBS:v1 observation hash
 * @param obs_ledger_seq L3 oracle observation sequence
 * @param weight_hash L2 model fingerprint
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-020: Mathematical trace requirement
 * @traceability SRS-007-SHALL-021: Trace required fields
 */
int ax_trace_init(
    ax_math_trace_t      *trace,
    const uint8_t         obs_hash[32],
    uint64_t              obs_ledger_seq,
    const uint8_t         weight_hash[32],
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Add policy evaluation result to trace
 *
 * Policy sequences must be added in ascending order.
 *
 * @param trace Trace record
 * @param policy_seq L4 policy evaluation sequence
 * @param result Policy result (PERMITTED or BREACH)
 * @param faults Fault context
 * @return 0 on success, -1 if full or ordering violation
 *
 * @traceability SRS-007-SHALL-021: Trace required fields
 * @traceability SRS-007-SHALL-049: Trace array ordering
 */
int ax_trace_add_policy(
    ax_math_trace_t      *trace,
    uint64_t              policy_seq,
    ax_policy_result_t    result,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Set transition information
 *
 * @param trace Trace record
 * @param trans_ledger_seq L5 transition sequence
 * @param trans_next_state Resulting agent health state
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-021: Trace required fields
 */
void ax_trace_set_transition(
    ax_math_trace_t      *trace,
    uint64_t              trans_ledger_seq,
    ax_agent_state_t      trans_next_state,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Set chain head after all commits
 *
 * @param trace Trace record
 * @param chain_head L6 chain head hash
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-021: Trace required fields
 */
void ax_trace_set_chain_head(
    ax_math_trace_t      *trace,
    const uint8_t         chain_head[32],
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Set proof ledger sequence
 *
 * @param trace Trace record
 * @param proof_ledger_seq Proof record sequence number
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-021: Trace required fields
 */
void ax_trace_set_proof_seq(
    ax_math_trace_t      *trace,
    uint64_t              proof_ledger_seq,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Verify policy sequences are in ascending order
 *
 * @param trace Trace record
 * @param faults Fault context
 * @return 0 if valid, -1 if ordering violated
 *
 * @traceability SRS-007-SHALL-049: Trace array ordering
 */
int ax_trace_verify_ordering(
    const ax_math_trace_t *trace,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Serialise trace to RFC 8785 (JCS) canonical JSON
 *
 * The trace_hash field is set to empty string during serialisation
 * for hash computation, then filled with the computed hash.
 *
 * @param trace Trace record
 * @param buffer Output buffer
 * @param buffer_size Buffer size in bytes
 * @param out_size Actual bytes written
 * @param include_trace_hash If true, include trace_hash; if false, use ""
 * @param faults Fault context
 * @return 0 on success, -1 on error (buffer too small)
 *
 * @traceability SRS-007-SHALL-022: Trace canonicality
 */
int ax_trace_to_canonical_json(
    const ax_math_trace_t *trace,
    char                  *buffer,
    size_t                 buffer_size,
    size_t                *out_size,
    bool                   include_trace_hash,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Compute trace_hash over canonical trace
 *
 * The trace_hash is computed as:
 *   trace_hash = SHA-256(canonical_trace_with_trace_hash_empty)
 *
 * @param trace Trace record (trace_hash field will be set)
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-050: Trace hash computation
 */
int ax_trace_compute_hash(
    ax_math_trace_t      *trace,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Finalise trace (verify ordering and compute hash)
 *
 * @param trace Trace record
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-020: Mathematical trace requirement
 * @traceability SRS-007-SHALL-050: Trace hash computation
 */
int ax_trace_finalise(
    ax_math_trace_t      *trace,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Validate trace record structure
 *
 * Checks:
 * - obs_hash is non-zero
 * - weight_hash is non-zero
 * - at least one policy result
 * - policy_seqs in ascending order
 * - trans_ledger_seq > last policy_seq
 *
 * @param trace Trace record to validate
 * @param faults Fault context
 * @return 0 if valid, -1 if invalid
 *
 * @traceability SRS-007-SHALL-021: Trace required fields
 * @traceability SRS-007-SHALL-049: Trace array ordering
 */
int ax_trace_validate(
    const ax_math_trace_t *trace,
    ax_gov_fault_flags_t  *faults
);

#ifdef __cplusplus
}
#endif

#endif /* AX_TRACE_H */
