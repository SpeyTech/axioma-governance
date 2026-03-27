/**
 * @file trace.c
 * @brief Mathematical Trace Implementation
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Implements the Mathematical Trace structure that proves the full
 * verification chain from observation through policy to state transition.
 * Uses strict RFC 8785 JCS encoding via ax_jcs.h.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-020: Mathematical trace structure
 * @traceability SRS-007-SHALL-021: Trace required fields
 * @traceability SRS-007-SHALL-022: Trace canonicality
 * @traceability SRS-007-SHALL-049: Trace array ordering
 * @traceability SRS-007-SHALL-050: Trace hash computation
 */

#include "ax_trace.h"
#include "ax_jcs.h"
#include "axilog/types.h"
#include <string.h>

/*
 * ============================================================================
 * Public API — Trace Operations
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-020: Mathematical trace structure
 * @traceability SRS-007-SHALL-021: Trace required fields
 */
int ax_trace_init(
    ax_math_trace_t      *trace,
    const uint8_t         obs_hash[32],
    uint64_t              obs_ledger_seq,
    const uint8_t         weight_hash[32],
    ax_gov_fault_flags_t *faults
) {
    if (trace == NULL || obs_hash == NULL || weight_hash == NULL ||
        faults == NULL) {
        return -1;
    }

    /* Clear trace */
    memset(trace, 0, sizeof(ax_math_trace_t));

    /* Set observation */
    memcpy(trace->obs_hash, obs_hash, 32);
    trace->obs_ledger_seq = obs_ledger_seq;

    /* Set weight binding */
    memcpy(trace->weight_hash, weight_hash, 32);

    /* Initialise counts */
    trace->policy_results_count = 0;
    trace->policy_seqs_count = 0;
    trace->trace_hash_computed = false;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-021: Trace required fields
 * @traceability SRS-007-SHALL-049: Trace array ordering
 */
int ax_trace_add_policy(
    ax_math_trace_t      *trace,
    uint64_t              policy_seq,
    ax_policy_result_t    result,
    ax_gov_fault_flags_t *faults
) {
    if (trace == NULL || faults == NULL) {
        return -1;
    }

    if (trace->policy_seqs_count >= AX_MAX_POLICIES) {
        faults->overflow = 1;
        return -1;
    }

    /* Validate ordering: policy_seqs must be monotonically increasing */
    if (trace->policy_seqs_count > 0) {
        if (policy_seq <= trace->policy_seqs[trace->policy_seqs_count - 1]) {
            faults->ordering_fault = 1;
            return -1;
        }
    } else {
        /* First policy must come after observation */
        if (policy_seq <= trace->obs_ledger_seq) {
            faults->ordering_fault = 1;
            return -1;
        }
    }

    trace->policy_results[trace->policy_results_count] = result;
    trace->policy_results_count++;

    trace->policy_seqs[trace->policy_seqs_count] = policy_seq;
    trace->policy_seqs_count++;

    trace->trace_hash_computed = false;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-021: Trace required fields
 */
void ax_trace_set_transition(
    ax_math_trace_t      *trace,
    uint64_t              trans_ledger_seq,
    ax_agent_state_t      trans_next_state,
    ax_gov_fault_flags_t *faults
) {
    if (trace == NULL || faults == NULL) {
        return;
    }

    trace->trans_ledger_seq = trans_ledger_seq;
    trace->trans_next_state = trans_next_state;
    trace->trace_hash_computed = false;
}

/**
 * @traceability SRS-007-SHALL-021: Trace required fields
 */
void ax_trace_set_chain_head(
    ax_math_trace_t      *trace,
    const uint8_t         chain_head[32],
    ax_gov_fault_flags_t *faults
) {
    if (trace == NULL || chain_head == NULL || faults == NULL) {
        return;
    }

    memcpy(trace->chain_head, chain_head, 32);
    trace->trace_hash_computed = false;
}

/**
 * @traceability SRS-007-SHALL-021: Trace required fields
 */
void ax_trace_set_proof_seq(
    ax_math_trace_t      *trace,
    uint64_t              proof_ledger_seq,
    ax_gov_fault_flags_t *faults
) {
    if (trace == NULL || faults == NULL) {
        return;
    }

    trace->proof_ledger_seq = proof_ledger_seq;
    trace->trace_hash_computed = false;
}

/**
 * @traceability SRS-007-SHALL-049: Trace array ordering
 */
int ax_trace_verify_ordering(
    const ax_math_trace_t *trace,
    ax_gov_fault_flags_t  *faults
) {
    size_t i;

    if (trace == NULL || faults == NULL) {
        return -1;
    }

    /* Full ordering chain:
     * obs_ledger_seq < policy_seqs[0] < ... < policy_seqs[n-1] <
     * trans_ledger_seq < proof_ledger_seq
     */

    /* Check observation is first */
    if (trace->policy_seqs_count > 0) {
        if (trace->obs_ledger_seq >= trace->policy_seqs[0]) {
            faults->ordering_fault = 1;
            return -1;
        }
    }

    /* Check policy ordering is strictly increasing */
    for (i = 1; i < trace->policy_seqs_count; i++) {
        if (trace->policy_seqs[i] <= trace->policy_seqs[i - 1]) {
            faults->ordering_fault = 1;
            return -1;
        }
    }

    /* Check transition comes after last policy (or observation if no policies) */
    if (trace->policy_seqs_count > 0) {
        if (trace->trans_ledger_seq <= trace->policy_seqs[trace->policy_seqs_count - 1]) {
            faults->ordering_fault = 1;
            return -1;
        }
    } else {
        if (trace->trans_ledger_seq <= trace->obs_ledger_seq) {
            faults->ordering_fault = 1;
            return -1;
        }
    }

    /* Check proof comes after transition */
    if (trace->proof_ledger_seq <= trace->trans_ledger_seq) {
        faults->ordering_fault = 1;
        return -1;
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-022: Trace canonicality
 *
 * Wrapper for jcs_trace_to_canonical that returns char* buffer
 * for backward compatibility.
 */
int ax_trace_to_canonical_json(
    const ax_math_trace_t *trace,
    char                  *buffer,
    size_t                 buffer_size,
    size_t                *out_size,
    bool                   include_trace_hash,
    ax_gov_fault_flags_t  *faults
) {
    /* Delegate to strict JCS encoder (byte-level) */
    return jcs_trace_to_canonical(
        trace,
        (uint8_t *)buffer,
        buffer_size,
        out_size,
        include_trace_hash,
        faults
    );
}

/**
 * @traceability SRS-007-SHALL-050: Trace hash computation
 *
 * trace_hash = SHA-256(canonical_trace_with_trace_hash_OMITTED)
 *
 * Critical: trace_hash field is OMITTED (not empty, not null)
 * during hash computation per SRS-007-SHALL-050.
 */
int ax_trace_compute_hash(
    ax_math_trace_t      *trace,
    ax_gov_fault_flags_t *faults
) {
    uint8_t buffer[8192];  /* Bounded buffer for canonical JSON */
    size_t json_len;

    if (trace == NULL || faults == NULL) {
        return -1;
    }

    /* Serialise without trace_hash (field OMITTED entirely) */
    if (jcs_trace_to_canonical(trace, buffer, sizeof(buffer),
                               &json_len, false, faults) != 0) {
        return -1;
    }

    /* Compute trace_hash = SHA-256(canonical_payload_with_trace_hash_omitted) */
    ax_sha256(buffer, json_len, trace->trace_hash);
    trace->trace_hash_computed = true;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-020: Mathematical trace structure
 * @traceability SRS-007-SHALL-050: Trace hash computation
 */
int ax_trace_finalise(
    ax_math_trace_t      *trace,
    ax_gov_fault_flags_t *faults
) {
    if (trace == NULL || faults == NULL) {
        return -1;
    }

    /* Step 1: Verify ordering constraints */
    if (ax_trace_verify_ordering(trace, faults) != 0) {
        return -1;
    }

    /* Step 2: Compute trace_hash */
    if (ax_trace_compute_hash(trace, faults) != 0) {
        return -1;
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-021: Trace required fields
 * @traceability SRS-007-SHALL-049: Trace array ordering
 */
int ax_trace_validate(
    const ax_math_trace_t *trace,
    ax_gov_fault_flags_t  *faults
) {
    size_t i;
    bool is_zero;

    if (trace == NULL || faults == NULL) {
        return -1;
    }

    /* obs_hash must be non-zero */
    is_zero = true;
    for (i = 0; i < 32; i++) {
        if (trace->obs_hash[i] != 0) {
            is_zero = false;
            break;
        }
    }
    if (is_zero) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* weight_hash must be non-zero */
    is_zero = true;
    for (i = 0; i < 32; i++) {
        if (trace->weight_hash[i] != 0) {
            is_zero = false;
            break;
        }
    }
    if (is_zero) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* policy counts must match */
    if (trace->policy_results_count != trace->policy_seqs_count) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* policy_count within bounds */
    if (trace->policy_results_count > AX_MAX_POLICIES) {
        faults->overflow = 1;
        return -1;
    }

    /* trans_next_state must be valid */
    if (trace->trans_next_state > AX_AGENT_STATE_FAILED) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* Verify ordering */
    if (ax_trace_verify_ordering(trace, faults) != 0) {
        return -1;
    }

    return 0;
}
