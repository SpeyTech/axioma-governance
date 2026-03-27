/**
 * @file anchor.c
 * @brief External Anchor Publication Implementation
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Implements periodic cryptographic anchor publication.
 * The anchor hash is the deterministic canonical proof.
 * GPG signing is an external attestation step — NOT part of
 * the deterministic payload (SRS-007-SHALL-060).
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-029: Anchor requirement
 * @traceability SRS-007-SHALL-030: Anchor computation
 * @traceability SRS-007-SHALL-032: Anchor commitment
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 * @traceability SRS-007-SHALL-034: Anchor verification
 * @traceability SRS-007-SHALL-052: Anchor time as oracle
 * @traceability SRS-007-SHALL-060: GPG signature determinism boundary
 */

#include "ax_anchor.h"
#include "ax_verify.h"
#include "axilog/types.h"
#include <string.h>

/*
 * ============================================================================
 * Internal Constants
 * ============================================================================
 */

/** Domain separation tag for anchor computation (SRS-007-SHALL-030) */
static const uint8_t ANCHOR_TAG[]  = {'A','X',':','A','N','C','H','O','R',':','v','1'};
#define ANCHOR_TAG_LEN 12U

/*
 * ============================================================================
 * Public API
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 */
int ax_anchor_config_init(
    ax_anchor_config_t   *cfg,
    uint64_t              interval_seq_count,
    uint64_t              current_ledger_seq,
    ax_gov_fault_flags_t *faults
) {
    if (cfg == NULL || faults == NULL) {
        return -1;
    }

    if (interval_seq_count == 0) {
        /* Zero interval is not permitted — anchor would fire on every commit */
        faults->integrity_fault = 1;
        return -1;
    }

    cfg->interval_seq_count = interval_seq_count;
    cfg->next_anchor_seq    = current_ledger_seq + interval_seq_count;
    cfg->initialised        = true;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 */
bool ax_anchor_is_due(
    const ax_anchor_config_t *cfg,
    uint64_t                  current_ledger_seq
) {
    if (cfg == NULL || !cfg->initialised) {
        return false;
    }
    return current_ledger_seq >= cfg->next_anchor_seq;
}

/**
 * @traceability SRS-007-SHALL-030: Anchor computation
 * @traceability SRS-007-SHALL-052: Anchor time as oracle
 *
 * anchor = SHA-256("AX:ANCHOR:v1" ‖ LE64(anchor_time_seq) ‖ chain_head)
 *
 * Input layout (44 bytes total):
 *   [0..11]  "AX:ANCHOR:v1"  (12 bytes ASCII)
 *   [12..19] anchor_time_seq (8 bytes little-endian uint64)
 *   [20..51] chain_head      (32 bytes)
 */
void ax_anchor_compute_hash(
    const uint8_t         chain_head[32],
    uint64_t              anchor_time_seq,
    uint8_t               anchor_hash_out[32],
    ax_gov_fault_flags_t *faults
) {
    /* 12 (tag) + 8 (LE64) + 32 (chain head) = 52 bytes */
    uint8_t payload[52];
    size_t offset = 0;

    if (chain_head == NULL || anchor_hash_out == NULL || faults == NULL) {
        return;
    }

    /* Tag */
    memcpy(payload + offset, ANCHOR_TAG, ANCHOR_TAG_LEN);
    offset += ANCHOR_TAG_LEN;

    /* LE64(anchor_time_seq) */
    payload[offset + 0] = (uint8_t)( anchor_time_seq        & 0xFF);
    payload[offset + 1] = (uint8_t)((anchor_time_seq >>  8) & 0xFF);
    payload[offset + 2] = (uint8_t)((anchor_time_seq >> 16) & 0xFF);
    payload[offset + 3] = (uint8_t)((anchor_time_seq >> 24) & 0xFF);
    payload[offset + 4] = (uint8_t)((anchor_time_seq >> 32) & 0xFF);
    payload[offset + 5] = (uint8_t)((anchor_time_seq >> 40) & 0xFF);
    payload[offset + 6] = (uint8_t)((anchor_time_seq >> 48) & 0xFF);
    payload[offset + 7] = (uint8_t)((anchor_time_seq >> 56) & 0xFF);
    offset += 8;

    /* chain_head */
    memcpy(payload + offset, chain_head, 32);

    ax_sha256(payload, sizeof(payload), anchor_hash_out);
}

/**
 * @traceability SRS-007-SHALL-029: Anchor requirement
 * @traceability SRS-007-SHALL-030: Anchor computation
 * @traceability SRS-007-SHALL-032: Anchor commitment
 * @traceability SRS-007-SHALL-052: Anchor time as oracle
 *
 * Evidence refs in the AX:PROOF:v1:
 *   [0] anchor_hash      — the computed anchor (canonical proof)
 *   [1] time_obs_hash    — Time Oracle AX:OBS:v1 (binds time to ledger)
 */
int ax_anchor_build(
    ax_anchor_record_t   *record,
    const uint8_t         chain_head[32],
    uint64_t              anchor_time_seq,
    const uint8_t         time_obs_hash[32],
    ax_gov_ctx_t         *gov,
    ax_gov_fault_flags_t *faults
) {
    uint8_t evidence[2][32];

    if (record == NULL || chain_head == NULL || time_obs_hash == NULL ||
        gov == NULL || faults == NULL) {
        return -1;
    }

    memset(record, 0, sizeof(ax_anchor_record_t));

    /* Store inputs */
    memcpy(record->chain_head, chain_head, 32);
    record->anchor_time_seq   = anchor_time_seq;
    record->anchor_ledger_seq = gov->next_proof_seq;

    /* Step 1: Compute deterministic anchor hash */
    ax_anchor_compute_hash(chain_head, anchor_time_seq,
                           record->anchor_hash, faults);
    if (ax_gov_has_fault(faults)) {
        return -1;
    }

    /*
     * Step 2: Build AX:PROOF:v1 commitment.
     *
     * GPG signature determinism boundary (SRS-007-SHALL-060):
     * The GPG signature is NOT included here. It is computed
     * externally after the anchor_hash is committed to the ledger,
     * and appended to latest-anchor.txt as an external attestation.
     */
    memcpy(evidence[0], record->anchor_hash, 32);
    memcpy(evidence[1], time_obs_hash, 32);

    if (ax_verify_build_proof(
            &record->proof,
            "External anchor published: SHA-256(AX:ANCHOR:v1 || LE64(time_seq) || chain_head)",
            AX_PROOF_TYPE_ANCHOR_PUBLICATION,
            "SRS-007-SHALL-030",
            (const uint8_t (*)[32])evidence,
            2,
            AX_PROOF_RESULT_VALID,
            AX_VIOLATION_NONE,
            gov,
            faults) != 0) {
        return -1;
    }

    record->proof_built = true;
    return 0;
}

/**
 * @traceability SRS-007-SHALL-034: Anchor verification
 *
 * Recomputes anchor hash from stored chain_head and anchor_time_seq,
 * then compares to the committed anchor_hash. Any mismatch means the
 * anchor record has been tampered with or corrupted.
 */
int ax_anchor_verify(
    const ax_anchor_record_t *record,
    ax_gov_fault_flags_t     *faults
) {
    uint8_t recomputed[32];

    if (record == NULL || faults == NULL) {
        return -1;
    }

    ax_anchor_compute_hash(record->chain_head, record->anchor_time_seq,
                           recomputed, faults);
    if (ax_gov_has_fault(faults)) {
        return -1;
    }

    if (memcmp(recomputed, record->anchor_hash, 32) != 0) {
        faults->hash_mismatch = 1;
        return -1;
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 */
void ax_anchor_advance(
    ax_anchor_config_t   *cfg,
    uint64_t              published_at_seq,
    ax_gov_fault_flags_t *faults
) {
    if (cfg == NULL || faults == NULL || !cfg->initialised) {
        return;
    }

    cfg->next_anchor_seq = published_at_seq + cfg->interval_seq_count;
}
