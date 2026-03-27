/**
 * @file proof.c
 * @brief AX:PROOF:v1 Record Implementation
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Implements AX:PROOF:v1 record construction and cryptographic binding.
 * Uses strict RFC 8785 JCS encoding via ax_jcs.h.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-003: Proof commitment
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 * @traceability SRS-007-SHALL-007: Canonical format
 */

#include "ax_proof.h"
#include "ax_jcs.h"
#include "axilog/types.h"
#include <string.h>

/*
 * ============================================================================
 * String Conversion Tables
 * ============================================================================
 */

static const char *PROOF_TYPE_STRINGS[] = {
    "ANCHOR_PUBLICATION",
    "COMPLIANCE_SUMMARY",
    "CROSS_LAYER_VERIFY",
    "POLICY_SOUNDNESS",
    "REPLAY_EQUIVALENCE",
    "SUBSTRATE_CERT",
    "WEIGHT_BINDING"
};

static const char *EVIDENCE_ORDERING_STRINGS[] = {
    "LEX",
    "TEMPORAL",
    "DECLARED"
};

static const char *PROOF_RESULT_STRINGS[] = {
    "VALID",
    "INVALID",
    "INTEGRITY_FAULT"
};

static const char *VIOLATION_STRINGS[] = {
    "NONE",
    "HASH_MISMATCH",
    "ORDERING",
    "WEIGHT_MISMATCH",
    "POLICY_BREACH",
    "TRANSITION_FAULT",
    "EVIDENCE_MISSING",
    "REPLAY_MISMATCH",
    "FALLBACK_OVERFLOW"
};

/*
 * ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * @brief Lexicographic comparison of two 32-byte hashes
 */
static int hash_compare(const uint8_t a[32], const uint8_t b[32]) {
    return memcmp(a, b, 32);
}

/*
 * ============================================================================
 * Public API — String Conversion
 * ============================================================================
 */

const char *ax_proof_type_to_string(ax_proof_type_t proof_type) {
    if (proof_type >= AX_PROOF_TYPE_COUNT) {
        return "UNKNOWN";
    }
    return PROOF_TYPE_STRINGS[proof_type];
}

const char *ax_evidence_ordering_to_string(ax_evidence_ordering_t ordering) {
    if (ordering > AX_EVIDENCE_ORDER_DECLARED) {
        return "UNKNOWN";
    }
    return EVIDENCE_ORDERING_STRINGS[ordering];
}

const char *ax_proof_result_to_string(ax_proof_result_t result) {
    if (result > AX_PROOF_RESULT_INTEGRITY_FAULT) {
        return "UNKNOWN";
    }
    return PROOF_RESULT_STRINGS[result];
}

const char *ax_violation_to_string(ax_violation_t violation) {
    if (violation > AX_VIOLATION_FALLBACK_OVERFLOW) {
        return "UNKNOWN";
    }
    return VIOLATION_STRINGS[violation];
}

/*
 * ============================================================================
 * Public API — Proof Record Operations
 * ============================================================================
 */

/**
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
) {
    size_t claim_len, rule_len;

    if (record == NULL || claim == NULL || rule_id == NULL ||
        prev_chain_head == NULL || faults == NULL) {
        return -1;
    }

    /* Validate proof_type is within closed set */
    if (!ax_proof_type_valid(proof_type)) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* Clear record */
    memset(record, 0, sizeof(ax_proof_record_t));

    /* Set claim — HARD FAIL on truncation (no silent truncation) */
    claim_len = strlen(claim);
    if (claim_len >= AX_MAX_CLAIM_SIZE) {
        faults->overflow = 1;
        return -1;
    }
    memcpy(record->claim, claim, claim_len);
    record->claim[claim_len] = '\0';

    /* Set rule_id — HARD FAIL on truncation */
    rule_len = strlen(rule_id);
    if (rule_len >= AX_MAX_RULE_ID_SIZE) {
        faults->overflow = 1;
        return -1;
    }
    memcpy(record->rule_id, rule_id, rule_len);
    record->rule_id[rule_len] = '\0';

    /* Set other fields */
    record->proof_type = proof_type;
    memcpy(record->prev_chain_head, prev_chain_head, 32);
    record->ledger_seq = ledger_seq;

    /* Default values */
    record->evidence_ordering = AX_EVIDENCE_ORDER_LEX;
    record->evidence_refs_count = 0;
    record->result = AX_PROOF_RESULT_VALID;
    record->violation = AX_VIOLATION_NONE;
    record->proof_hash_computed = false;
    record->ordering_metadata.is_set = false;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-006: Evidence reference requirement
 * @traceability SRS-007-SHALL-046: Evidence reference encoding
 */
int ax_proof_add_evidence(
    ax_proof_record_t    *record,
    const uint8_t         evidence_hash[32],
    ax_gov_fault_flags_t *faults
) {
    if (record == NULL || evidence_hash == NULL || faults == NULL) {
        return -1;
    }

    if (record->evidence_refs_count >= AX_MAX_EVIDENCE_REFS) {
        faults->overflow = 1;
        return -1;
    }

    memcpy(record->evidence_refs[record->evidence_refs_count], evidence_hash, 32);
    record->evidence_refs_count++;

    /* Invalidate proof_hash since evidence changed */
    record->proof_hash_computed = false;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-057: Evidence ordering mode
 */
int ax_proof_set_ordering(
    ax_proof_record_t          *record,
    ax_evidence_ordering_t      ordering,
    const ax_ordering_metadata_t *metadata,
    ax_gov_fault_flags_t       *faults
) {
    if (record == NULL || faults == NULL) {
        return -1;
    }

    if (ordering > AX_EVIDENCE_ORDER_DECLARED) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* DECLARED requires metadata */
    if (ordering == AX_EVIDENCE_ORDER_DECLARED) {
        if (metadata == NULL || !metadata->is_set) {
            faults->integrity_fault = 1;
            return -1;
        }
        memcpy(&record->ordering_metadata, metadata, sizeof(ax_ordering_metadata_t));
    } else {
        record->ordering_metadata.is_set = false;
    }

    record->evidence_ordering = ordering;
    record->proof_hash_computed = false;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 */
void ax_proof_set_result(
    ax_proof_record_t    *record,
    ax_proof_result_t     result,
    ax_violation_t        violation,
    ax_gov_fault_flags_t *faults
) {
    if (record == NULL || faults == NULL) {
        return;
    }

    record->result = result;
    record->violation = (result == AX_PROOF_RESULT_INVALID ||
                         result == AX_PROOF_RESULT_INTEGRITY_FAULT)
                        ? violation : AX_VIOLATION_NONE;
    record->proof_hash_computed = false;
}

/**
 * @traceability SRS-007-SHALL-057: Evidence ordering mode
 *
 * Implements:
 * - LEX: Lexicographic sort by hash bytes
 * - TEMPORAL: Requires external ledger_seq mapping (not sorted here)
 * - DECLARED: Order preserved as-is (metadata validated)
 */
void ax_proof_sort_evidence(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
) {
    size_t i, j;
    uint8_t temp[32];

    if (record == NULL || faults == NULL) {
        return;
    }

    /* Only sort for LEX ordering */
    if (record->evidence_ordering != AX_EVIDENCE_ORDER_LEX) {
        /* TEMPORAL and DECLARED ordering are not sorted by this function.
         * TEMPORAL requires external ledger_seq data.
         * DECLARED uses explicit ordering from metadata.
         */
        return;
    }

    /* Insertion sort (deterministic, bounded O(n²)) */
    for (i = 1; i < record->evidence_refs_count; i++) {
        memcpy(temp, record->evidence_refs[i], 32);
        j = i;
        while (j > 0 && hash_compare(record->evidence_refs[j - 1], temp) > 0) {
            memcpy(record->evidence_refs[j], record->evidence_refs[j - 1], 32);
            j--;
        }
        memcpy(record->evidence_refs[j], temp, 32);
    }

    record->proof_hash_computed = false;
}

/**
 * @traceability SRS-007-SHALL-007: Canonical format
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 *
 * Wrapper for jcs_proof_to_canonical that returns char* buffer
 * for backward compatibility with existing test code.
 */
int ax_proof_to_canonical_json(
    const ax_proof_record_t *record,
    char                    *buffer,
    size_t                   buffer_size,
    size_t                  *out_size,
    bool                     include_proof_hash,
    ax_gov_fault_flags_t    *faults
) {
    /* Delegate to strict JCS encoder (byte-level) */
    return jcs_proof_to_canonical(
        record,
        (uint8_t *)buffer,
        buffer_size,
        out_size,
        include_proof_hash,
        faults
    );
}

/**
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 *
 * proof_hash = SHA-256(canonical_payload_with_proof_hash_OMITTED)
 *
 * Critical: proof_hash field is OMITTED (not empty, not null)
 * during hash computation per SRS-007-SHALL-045.
 */
int ax_proof_compute_hash(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
) {
    uint8_t buffer[16384];  /* Bounded buffer for canonical JSON */
    size_t json_len;

    if (record == NULL || faults == NULL) {
        return -1;
    }

    /* Serialise without proof_hash (field OMITTED entirely) */
    if (jcs_proof_to_canonical(record, buffer, sizeof(buffer),
                               &json_len, false, faults) != 0) {
        return -1;
    }

    /* Compute proof_hash = SHA-256(canonical_payload_with_proof_hash_omitted) */
    ax_sha256(buffer, json_len, record->proof_hash);
    record->proof_hash_computed = true;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-054: Commitment payload encoding
 *
 * commitment = SHA-256("AX:PROOF:v1" || LE64(byte_length) || utf8_bytes)
 *
 * Where:
 * - "AX:PROOF:v1" is 11 ASCII bytes
 * - LE64(byte_length) is 8 bytes, little-endian
 * - utf8_bytes is the canonical JSON with proof_hash included
 */
int ax_proof_compute_commitment(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
) {
    uint8_t json_buffer[16384];  /* Bounded buffer for canonical JSON */
    size_t json_len;
    uint8_t commitment_input[11 + 8 + 16384];  /* tag + length + payload */
    size_t input_len;
    uint64_t byte_len;

    if (record == NULL || faults == NULL) {
        return -1;
    }

    /* Ensure proof_hash is computed first */
    if (!record->proof_hash_computed) {
        if (ax_proof_compute_hash(record, faults) != 0) {
            return -1;
        }
    }

    /* Serialise with proof_hash included */
    if (jcs_proof_to_canonical(record, json_buffer, sizeof(json_buffer),
                               &json_len, true, faults) != 0) {
        return -1;
    }

    /* Build commitment input:
     * "AX:PROOF:v1" (11 bytes) || LE64(byte_length) || utf8_bytes
     */
    memcpy(commitment_input, AX_PROOF_TAG, AX_PROOF_TAG_LEN);
    input_len = AX_PROOF_TAG_LEN;

    /* LE64 byte length — explicit byte-by-byte encoding */
    byte_len = (uint64_t)json_len;
    commitment_input[input_len++] = (uint8_t)(byte_len);
    commitment_input[input_len++] = (uint8_t)(byte_len >> 8);
    commitment_input[input_len++] = (uint8_t)(byte_len >> 16);
    commitment_input[input_len++] = (uint8_t)(byte_len >> 24);
    commitment_input[input_len++] = (uint8_t)(byte_len >> 32);
    commitment_input[input_len++] = (uint8_t)(byte_len >> 40);
    commitment_input[input_len++] = (uint8_t)(byte_len >> 48);
    commitment_input[input_len++] = (uint8_t)(byte_len >> 56);

    /* UTF-8 payload (json_buffer is byte array, not C string) */
    memcpy(commitment_input + input_len, json_buffer, json_len);
    input_len += json_len;

    /* Compute commitment = SHA-256(commitment_input) */
    ax_sha256(commitment_input, input_len, record->commitment);

    return 0;
}

/**
 * @traceability SRS-007-SHALL-003: Proof commitment
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 */
int ax_proof_finalise(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
) {
    if (record == NULL || faults == NULL) {
        return -1;
    }

    /* Step 1: Sort evidence refs according to ordering mode */
    ax_proof_sort_evidence(record, faults);
    if (ax_gov_has_fault(faults)) {
        return -1;
    }

    /* Step 2: Compute proof_hash */
    if (ax_proof_compute_hash(record, faults) != 0) {
        return -1;
    }

    /* Step 3: Compute commitment */
    if (ax_proof_compute_commitment(record, faults) != 0) {
        return -1;
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 * @traceability SRS-007-SHALL-005: Proof type closed set
 * @traceability SRS-007-SHALL-006: Evidence reference requirement
 */
int ax_proof_validate(
    const ax_proof_record_t *record,
    ax_gov_fault_flags_t    *faults
) {
    if (record == NULL || faults == NULL) {
        return -1;
    }

    /* claim must be non-empty */
    if (record->claim[0] == '\0') {
        faults->integrity_fault = 1;
        return -1;
    }

    /* proof_type must be valid */
    if (!ax_proof_type_valid(record->proof_type)) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* rule_id must be non-empty */
    if (record->rule_id[0] == '\0') {
        faults->integrity_fault = 1;
        return -1;
    }

    /* evidence_refs must be non-empty (SRS-007-SHALL-006) */
    if (record->evidence_refs_count == 0) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* If DECLARED ordering, metadata must be set */
    if (record->evidence_ordering == AX_EVIDENCE_ORDER_DECLARED &&
        !record->ordering_metadata.is_set) {
        faults->integrity_fault = 1;
        return -1;
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 */
int ax_proof_verify_hash(
    const ax_proof_record_t *record,
    ax_gov_fault_flags_t    *faults
) {
    ax_proof_record_t temp;
    uint8_t computed_hash[32];
    uint8_t buffer[16384];
    size_t json_len;

    if (record == NULL || faults == NULL) {
        return -1;
    }

    if (!record->proof_hash_computed) {
        faults->hash_mismatch = 1;
        return -1;
    }

    /* Copy record and recompute hash */
    memcpy(&temp, record, sizeof(ax_proof_record_t));
    temp.proof_hash_computed = false;

    if (jcs_proof_to_canonical(&temp, buffer, sizeof(buffer),
                               &json_len, false, faults) != 0) {
        return -1;
    }

    ax_sha256(buffer, json_len, computed_hash);

    /* Compare */
    if (memcmp(computed_hash, record->proof_hash, 32) != 0) {
        faults->hash_mismatch = 1;
        return -1;
    }

    return 0;
}
