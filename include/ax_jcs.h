/**
 * @file ax_jcs.h
 * @brief RFC 8785 JSON Canonicalization Scheme (JCS) Encoder
 *
 * DVEC: v1.3
 * DETERMINISM: D1 — Strict Deterministic
 * MEMORY: Zero Dynamic Allocation
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Provides strict RFC 8785 canonical JSON encoding for governance records.
 * All operations are byte-exact with no reliance on C string semantics.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-007: Canonical format (RFC 8785)
 */

#ifndef AX_JCS_H
#define AX_JCS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ax_governance.h"
#include "ax_proof.h"
#include "ax_trace.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Serialise AX:PROOF:v1 record to RFC 8785 canonical JSON
 *
 * Field order is strictly lexicographic per RFC 8785:
 *   claim, commitment, evidence_ordering, evidence_refs, ledger_seq,
 *   ordering_metadata, prev_chain_head, proof_hash (optional), proof_type,
 *   result, rule_id, schema_version, violation
 *
 * Key RFC 8785 guarantees:
 * - Strict lexicographic key ordering
 * - Canonical string escaping (only required escapes)
 * - Canonical number formatting (no insignificant digits)
 * - No whitespace
 * - UTF-8 byte-level encoding
 *
 * @param record Proof record to serialise
 * @param buffer Output buffer (byte array, NOT null-terminated)
 * @param buffer_size Buffer capacity in bytes
 * @param out_size Actual bytes written (no null terminator)
 * @param include_proof_hash If false, proof_hash field is OMITTED entirely
 *                           (not empty, not null — absent from JSON)
 * @param faults Fault context (overflow flag set on buffer exceeded)
 * @return 0 on success, -1 on error (no partial output on failure)
 *
 * @traceability SRS-007-SHALL-007: Canonical format (RFC 8785)
 * @traceability SRS-007-SHALL-045: proof_hash OMITTED during hash computation
 */
int jcs_proof_to_canonical(
    const ax_proof_record_t *record,
    uint8_t                 *buffer,
    size_t                   buffer_size,
    size_t                  *out_size,
    bool                     include_proof_hash,
    ax_gov_fault_flags_t    *faults
);

/**
 * @brief Serialise Mathematical Trace to RFC 8785 canonical JSON
 *
 * Field order is strictly lexicographic per RFC 8785:
 *   chain_head, obs_hash, obs_ledger_seq, policy_results, policy_seqs,
 *   proof_ledger_seq, trace_hash (optional), trans_ledger_seq,
 *   trans_next_state, weight_hash
 *
 * @param trace Trace record to serialise
 * @param buffer Output buffer (byte array, NOT null-terminated)
 * @param buffer_size Buffer capacity in bytes
 * @param out_size Actual bytes written (no null terminator)
 * @param include_trace_hash If false, trace_hash field is OMITTED entirely
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-022: Trace canonicality
 * @traceability SRS-007-SHALL-050: trace_hash OMITTED during hash computation
 */
int jcs_trace_to_canonical(
    const ax_math_trace_t   *trace,
    uint8_t                 *buffer,
    size_t                   buffer_size,
    size_t                  *out_size,
    bool                     include_trace_hash,
    ax_gov_fault_flags_t    *faults
);

#ifdef __cplusplus
}
#endif

#endif /* AX_JCS_H */
