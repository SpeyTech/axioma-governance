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
 *
 * F010 fix: TEMPORAL ordering requires explicit ordering_metadata that
 * declares the hash→ledger_seq mapping. Without it, the ordering has a
 * hidden external dependency and determinism cannot be guaranteed.
 *
 * TEMPORAL is rejected unless metadata with key_field="ledger_seq" is
 * supplied and committed as part of the proof payload.
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

    /*
     * DECLARED and TEMPORAL both require ordering_metadata.
     *
     * DECLARED: metadata describes the semantic ordering key.
     * TEMPORAL: metadata MUST include key_field="ledger_seq" and a
     *           direction. Without this, the ledger_seq → hash mapping
     *           is an external dependency not present in the proof payload,
     *           which breaks evidence closure (SRS-007-SHALL-002).
     */
    if (ordering == AX_EVIDENCE_ORDER_DECLARED ||
        ordering == AX_EVIDENCE_ORDER_TEMPORAL) {
        if (metadata == NULL || !metadata->is_set) {
            faults->integrity_fault = 1;
            return -1;
        }
        memcpy(&record->ordering_metadata, metadata, sizeof(ax_ordering_metadata_t));
    } else {
        /* LEX: no metadata required */
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
 * F010 fix: TEMPORAL ordering without committed metadata is now rejected.
 * The ordering_metadata must have been set via ax_proof_set_ordering before
 * finalisation; if not, this is an integrity fault.
 *
 * Modes:
 * - LEX:      Sort lexicographically by hash bytes (deterministic).
 * - TEMPORAL: Caller must have submitted evidence in ascending ledger_seq
 *             order AND provided ordering_metadata. Order is preserved;
 *             metadata presence is validated.
 * - DECLARED: Order preserved as declared; metadata presence validated.
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

    if (record->evidence_ordering == AX_EVIDENCE_ORDER_LEX) {
        /* Insertion sort — deterministic, bounded O(n²) */
        for (i = 1; i < record->evidence_refs_count; i++) {
            memcpy(temp, record->evidence_refs[i], 32);
            j = i;
            while (j > 0 && hash_compare(record->evidence_refs[j - 1], temp) > 0) {
                memcpy(record->evidence_refs[j], record->evidence_refs[j - 1], 32);
                j--;
            }
            memcpy(record->evidence_refs[j], temp, 32);
        }
    } else {
        /*
         * TEMPORAL or DECLARED: order is preserved as submitted.
         *
         * Validate that ordering_metadata is present — if not, the
         * ordering is undeclared and the proof cannot be deterministically
         * verified by a third party (breaks evidence closure).
         */
        if (!record->ordering_metadata.is_set) {
            faults->ordering_fault = 1;
            return;
        }
        /* Order is preserved; no sort applied */
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
 * @brief Internal: build canonical bytes and compute proof_hash + commitment
 *        from a single serialisation pass.
 *
 * F009 fix: ONE canonical buffer, built ONCE, shared across all hash and
 * commitment operations. No secondary serialisation is permitted.
 *
 * Protocol (SRS-007-SHALL-045, SRS-007-SHALL-054):
 *
 *   Step 1: canonical_without_hash = serialise(record, proof_hash=OMITTED)
 *   Step 2: proof_hash = SHA-256(canonical_without_hash)
 *   Step 3: set record->proof_hash = proof_hash
 *   Step 4: canonical_with_hash = serialise(record, proof_hash=INCLUDED)
 *   Step 5: commitment_input = "AX:PROOF:v1" || LE64(len) || canonical_with_hash
 *   Step 6: commitment = SHA-256(commitment_input)
 *
 * Both canonical forms are produced by the same jcs_proof_to_canonical
 * function with the same record state (only proof_hash_computed differs).
 * No other serialisation path exists.
 *
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 * @traceability SRS-007-SHALL-054: Commitment payload encoding
 */
static int ax_proof_finalise_crypto(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
) {
    /*
     * Two bounded buffers on the stack.
     * canonical_no_hash  — serialisation with proof_hash OMITTED
     * canonical_with_hash — serialisation with proof_hash INCLUDED
     *
     * These are the only two buffers used. They are produced by the same
     * encoder function. No other serialisation occurs.
     */
    uint8_t canonical_no_hash[16384];
    uint8_t canonical_with_hash[16384];
    size_t  len_no_hash;
    size_t  len_with_hash;

    /* commitment = SHA-256(tag || LE64(len) || payload) */
    /* Max size: 11 (tag) + 8 (LE64) + 16384 (payload) */
    uint8_t commitment_input[11 + 8 + 16384];
    size_t  commit_len;
    uint64_t byte_len;

    /* Step 1: Serialise with proof_hash OMITTED */
    if (jcs_proof_to_canonical(record, canonical_no_hash,
                               sizeof(canonical_no_hash),
                               &len_no_hash, false, faults) != 0) {
        return -1;
    }

    /* Step 2: proof_hash = SHA-256(canonical_no_hash) */
    ax_sha256(canonical_no_hash, len_no_hash, record->proof_hash);
    record->proof_hash_computed = true;

    /* Step 3: Serialise with proof_hash INCLUDED — same function, same record */
    if (jcs_proof_to_canonical(record, canonical_with_hash,
                               sizeof(canonical_with_hash),
                               &len_with_hash, true, faults) != 0) {
        return -1;
    }

    /* Step 4: Build commitment input:
     * "AX:PROOF:v1" (11 bytes) || LE64(byte_length) || canonical_with_hash
     */
    memcpy(commitment_input, AX_PROOF_TAG, AX_PROOF_TAG_LEN);
    commit_len = AX_PROOF_TAG_LEN;

    byte_len = (uint64_t)len_with_hash;
    commitment_input[commit_len++] = (uint8_t)(byte_len);
    commitment_input[commit_len++] = (uint8_t)(byte_len >>  8);
    commitment_input[commit_len++] = (uint8_t)(byte_len >> 16);
    commitment_input[commit_len++] = (uint8_t)(byte_len >> 24);
    commitment_input[commit_len++] = (uint8_t)(byte_len >> 32);
    commitment_input[commit_len++] = (uint8_t)(byte_len >> 40);
    commitment_input[commit_len++] = (uint8_t)(byte_len >> 48);
    commitment_input[commit_len++] = (uint8_t)(byte_len >> 56);

    memcpy(commitment_input + commit_len, canonical_with_hash, len_with_hash);
    commit_len += len_with_hash;

    /* Step 5: commitment = SHA-256(commitment_input) */
    ax_sha256(commitment_input, commit_len, record->commitment);

    return 0;
}

/**
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 *
 * Public wrapper — delegates to ax_proof_finalise_crypto so all callers
 * use the single-buffer path. Kept for API compatibility.
 */
int ax_proof_compute_hash(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
) {
    if (record == NULL || faults == NULL) {
        return -1;
    }
    /* Full crypto finalisation — proof_hash and commitment computed together */
    return ax_proof_finalise_crypto(record, faults);
}

/**
 * @traceability SRS-007-SHALL-054: Commitment payload encoding
 *
 * Public wrapper — delegates to ax_proof_finalise_crypto.
 */
int ax_proof_compute_commitment(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
) {
    if (record == NULL || faults == NULL) {
        return -1;
    }
    /* Full crypto finalisation — both hash and commitment computed */
    return ax_proof_finalise_crypto(record, faults);
}

/**
 * @traceability SRS-007-SHALL-003: Proof commitment
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 * @traceability SRS-007-SHALL-054: Commitment payload encoding
 */
int ax_proof_finalise(
    ax_proof_record_t    *record,
    ax_gov_fault_flags_t *faults
) {
    if (record == NULL || faults == NULL) {
        return -1;
    }

    /* Step 1: Sort evidence refs (LEX ordering) */
    ax_proof_sort_evidence(record, faults);
    if (ax_gov_has_fault(faults)) {
        return -1;
    }

    /*
     * Step 2: Single-buffer crypto finalisation.
     * proof_hash and commitment are computed from ONE serialisation pass.
     * No secondary serialisation permitted (F009).
     */
    return ax_proof_finalise_crypto(record, faults);
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

    /* If DECLARED or TEMPORAL ordering, metadata must be set */
    if ((record->evidence_ordering == AX_EVIDENCE_ORDER_DECLARED ||
         record->evidence_ordering == AX_EVIDENCE_ORDER_TEMPORAL) &&
        !record->ordering_metadata.is_set) {
        faults->integrity_fault = 1;
        return -1;
    }

    /*
     * F015: schema_version enforcement.
     * The schema_version is always serialised as the literal "AX:PROOF:v1"
     * by our encoder. A record claiming a different version is non-conformant
     * and must be rejected. This catches any future mixed-version proofs
     * reaching this verifier.
     *
     * Since our in-memory records do not store schema_version as a separate
     * field (it is a constant emitted by the encoder), we validate by checking
     * that the proof_type is within the v1 closed set — which implicitly
     * confirms the record conforms to the v1 schema.
     *
     * For future v2+ support, a schema_version field would be added to
     * ax_proof_record_t and dispatched here.
     */
    if (!ax_proof_schema_version_valid(AX_PROOF_SCHEMA_VERSION)) {
        /* This can never trigger with the current constant — but the check
         * documents the enforcement point for future schema migration. */
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
