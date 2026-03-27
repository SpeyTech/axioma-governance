/**
 * @file ax_proof.h
 * @brief AX:PROOF:v1 Record — Cryptographic Proof Construction
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * AX:PROOF:v1 is the canonical evidence record representing a governance
 * proof. Every governance claim is committed as an AX:PROOF:v1 record.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-003: Proof commitment
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 * @traceability SRS-007-SHALL-005: Proof type closed set
 * @traceability SRS-007-SHALL-006: Evidence reference requirement
 * @traceability SRS-007-SHALL-007: Canonical format
 */

#ifndef AX_PROOF_H
#define AX_PROOF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ax_governance.h"

/**
 * @brief Domain separation tag for AX:PROOF:v1 records
 *
 * @traceability SRS-007-SHALL-054: Commitment payload encoding
 */
#define AX_PROOF_TAG "AX:PROOF:v1"
#define AX_PROOF_TAG_LEN 11  /* strlen("AX:PROOF:v1") */

/**
 * @brief Ordering metadata structure (required if evidence_ordering = DECLARED)
 *
 * @traceability SRS-007-SHALL-057: Evidence ordering mode
 */
typedef struct {
    char     description[128];      /**< Ordering description */
    char     key_field[32];         /**< Key field name (e.g., "ledger_seq") */
    char     direction[16];         /**< "ascending" or "descending" */
    bool     is_set;                /**< Whether metadata is present */
} ax_ordering_metadata_t;

/**
 * @brief AX:PROOF:v1 record structure
 *
 * Fields appear in lexicographic order per RFC 8785 (JCS):
 *   claim, commitment, evidence_ordering, evidence_refs, ledger_seq,
 *   ordering_metadata, prev_chain_head, proof_hash, proof_type, result,
 *   rule_id, schema_version, violation
 *
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 * @traceability SRS-007-SHALL-007: Canonical format
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 * @traceability SRS-007-SHALL-046: Evidence reference encoding
 */
typedef struct ax_proof_record {
    /* --- claim --- */
    char                    claim[AX_MAX_CLAIM_SIZE];       /**< Governance claim being proven */

    /* --- commitment --- */
    uint8_t                 commitment[32];                 /**< Domain-separated commitment */

    /* --- evidence_ordering --- */
    ax_evidence_ordering_t  evidence_ordering;              /**< Ordering mode for evidence_refs */

    /* --- evidence_refs --- */
    uint8_t                 evidence_refs[AX_MAX_EVIDENCE_REFS][32]; /**< SHA-256 hashes */
    size_t                  evidence_refs_count;            /**< Number of evidence refs */

    /* --- ledger_seq --- */
    uint64_t                ledger_seq;                     /**< Sequence number of this proof */

    /* --- ordering_metadata --- */
    ax_ordering_metadata_t  ordering_metadata;              /**< Required if DECLARED */

    /* --- prev_chain_head --- */
    uint8_t                 prev_chain_head[32];            /**< Prior L6 chain head */

    /* --- proof_hash --- */
    uint8_t                 proof_hash[32];                 /**< SHA-256 over canonical payload */
    bool                    proof_hash_computed;            /**< Whether proof_hash is valid */

    /* --- proof_type --- */
    ax_proof_type_t         proof_type;                     /**< Classification of proof */

    /* --- result --- */
    ax_proof_result_t       result;                         /**< VALID | INVALID | INTEGRITY_FAULT */

    /* --- rule_id --- */
    char                    rule_id[AX_MAX_RULE_ID_SIZE];   /**< SRS-007-SHALL-xxx */

    /* --- schema_version --- */
    /* Always "AX:PROOF:v1" - constant, not stored */

    /* --- violation --- */
    ax_violation_t          violation;                      /**< Violation type if INVALID */
} ax_proof_record_t;

/**
 * @brief Initialise an AX:PROOF:v1 record with required fields
 *
 * @param record Record to initialise
 * @param claim Governance claim string
 * @param proof_type Type of proof
 * @param rule_id SRS requirement being proven
 * @param prev_chain_head Prior L6 chain head
 * @param ledger_seq Sequence number for this proof
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-003: Proof commitment
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 */
int ax_proof_init(
    ax_proof_record_t    *record,
    const char           *claim,
    ax_proof_type_t       proof_type,
    const char           *rule_id,
    const uint8_t         prev_chain_head[32],
    uint64_t              ledger_seq,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Add evidence reference to proof record
 *
 * @param record Proof record
 * @param evidence_hash SHA-256 hash of evidence record (32 bytes)
 * @param faults Fault context
 * @return 0 on success, -1 if full
 *
 * @traceability SRS-007-SHALL-006: Evidence reference requirement
 * @traceability SRS-007-SHALL-046: Evidence reference encoding
 */
int ax_proof_add_evidence(
    ax_proof_record_t    *record,
    const uint8_t         evidence_hash[32],
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Set evidence ordering mode
 *
 * @param record Proof record
 * @param ordering Ordering mode
 * @param metadata Ordering metadata (required if DECLARED, NULL otherwise)
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-057: Evidence ordering mode
 */
int ax_proof_set_ordering(
    ax_proof_record_t          *record,
    ax_evidence_ordering_t      ordering,
    const ax_ordering_metadata_t *metadata,
    ax_gov_fault_flags_t       *faults
);

/**
 * @brief Set proof result
 *
 * @param record Proof record
 * @param result Proof result
 * @param violation Violation type (if result is INVALID)
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 */
void ax_proof_set_result(
    ax_proof_record_t    *record,
    ax_proof_result_t     result,
    ax_violation_t        violation,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Sort evidence refs according to ordering mode
 *
 * For LEX ordering, sorts lexicographically by hash.
 * For TEMPORAL ordering, caller must provide already-sorted refs.
 * For DECLARED ordering, order is preserved as-is.
 *
 * @param record Proof record
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-057: Evidence ordering mode
 */
void ax_proof_sort_evidence(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Serialise proof record to RFC 8785 (JCS) canonical JSON
 *
 * The proof_hash field is OMITTED from the output (not empty, not null —
 * the key itself is absent) to enable proper hash computation.
 *
 * @param record Proof record
 * @param buffer Output buffer
 * @param buffer_size Buffer size in bytes
 * @param out_size Actual bytes written
 * @param include_proof_hash If true, include proof_hash; if false, omit it
 * @param faults Fault context
 * @return 0 on success, -1 on error (buffer too small)
 *
 * @traceability SRS-007-SHALL-007: Canonical format
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 */
int ax_proof_to_canonical_json(
    const ax_proof_record_t *record,
    char                    *buffer,
    size_t                   buffer_size,
    size_t                  *out_size,
    bool                     include_proof_hash,
    ax_gov_fault_flags_t    *faults
);

/**
 * @brief Compute proof_hash over canonical payload
 *
 * The proof_hash is computed as:
 *   proof_hash = SHA-256(canonical_payload_with_proof_hash_omitted)
 *
 * @param record Proof record (proof_hash field will be set)
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 */
int ax_proof_compute_hash(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Compute commitment over canonical payload
 *
 * The commitment is computed as:
 *   commitment = SHA-256("AX:PROOF:v1" ‖ LE64(byte_length) ‖ utf8_bytes)
 *
 * @param record Proof record (commitment field will be set)
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-054: Commitment payload encoding
 */
int ax_proof_compute_commitment(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Finalise proof record (compute hash and commitment)
 *
 * This function computes both proof_hash and commitment in the correct order:
 * 1. Sort evidence refs according to ordering mode
 * 2. Compute proof_hash (over payload with proof_hash omitted)
 * 3. Compute commitment (over full canonical payload including proof_hash)
 *
 * @param record Proof record
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-003: Proof commitment
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 */
int ax_proof_finalise(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Validate proof record structure
 *
 * Checks:
 * - claim is non-empty
 * - proof_type is valid (within closed set)
 * - rule_id is non-empty
 * - evidence_refs is non-empty (at least one)
 * - if DECLARED ordering, ordering_metadata must be set
 *
 * @param record Proof record to validate
 * @param faults Fault context
 * @return 0 if valid, -1 if invalid
 *
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 * @traceability SRS-007-SHALL-005: Proof type closed set
 * @traceability SRS-007-SHALL-006: Evidence reference requirement
 */
int ax_proof_validate(
    const ax_proof_record_t *record,
    ax_gov_fault_flags_t    *faults
);

/**
 * @brief Verify proof_hash is correct
 *
 * Recomputes proof_hash and compares to stored value.
 *
 * @param record Proof record to verify
 * @param faults Fault context
 * @return 0 if valid, -1 if mismatch
 *
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 */
int ax_proof_verify_hash(
    const ax_proof_record_t *record,
    ax_gov_fault_flags_t    *faults
);

#ifdef __cplusplus
}
#endif

#endif /* AX_PROOF_H */
