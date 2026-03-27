/**
 * @file fault.c
 * @brief Governance Integrity Fault Handling Implementation
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * No governance failure is silent (SRS-007-SHALL-038).
 * Every integrity fault is committed as AX:PROOF:v1.
 * When the L6 ledger is unavailable, faults are written to the
 * bounded fallback log (Option A, SRS-007-SHALL-053).
 * On fallback log overflow, OVERFLOW_MARKER is written and
 * the system halts (Option A.1, SRS-007-SHALL-061).
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-035: Integrity fault definition
 * @traceability SRS-007-SHALL-036: Integrity fault recording
 * @traceability SRS-007-SHALL-037: Integrity fault response
 * @traceability SRS-007-SHALL-038: No silent governance failure
 * @traceability SRS-007-SHALL-053: Ledger failure mode (Option A)
 * @traceability SRS-007-SHALL-061: Fallback log overflow (Option A.1)
 */

#include "ax_fault.h"
#include "ax_verify.h"
#include "axilog/types.h"
#include <string.h>

/*
 * ============================================================================
 * Overflow Marker Constants (SRS-007-SHALL-061)
 * ============================================================================
 *
 * Overflow marker record fields per SRS-007-SHALL-061:
 *   claim         = "FALLBACK_LOG_OVERFLOW"
 *   proof_type    = INTEGRITY_FAULT  (no enum for this; use CROSS_LAYER_VERIFY
 *                   with result=INTEGRITY_FAULT, violation=FALLBACK_OVERFLOW)
 *   result        = INTEGRITY_FAULT
 *   rule_id       = "SRS-007-SHALL-061"
 *   violation     = FALLBACK_OVERFLOW
 */
#define OVERFLOW_CLAIM   "FALLBACK_LOG_OVERFLOW"
#define OVERFLOW_RULE_ID "SRS-007-SHALL-061"

/*
 * ============================================================================
 * Public API — Fallback Log
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-053: Ledger failure mode (Option A)
 */
void ax_fallback_log_init(
    ax_fallback_log_t    *log,
    ax_gov_fault_flags_t *faults
) {
    if (log == NULL || faults == NULL) {
        return;
    }

    memset(log, 0, sizeof(ax_fallback_log_t));
    log->state       = AX_FALLBACK_STATE_IDLE;
    log->entry_count = 0;
    log->overflow_flag = false;
    log->initialised = true;
}

/**
 * @traceability SRS-007-SHALL-053: Ledger failure mode (Option A)
 * @traceability SRS-007-SHALL-061: Fallback log overflow (Option A.1)
 *
 * Write integrity fault to fallback log. On overflow:
 *   1. Write OVERFLOW_MARKER as final entry
 *   2. Set overflow_flag
 *   3. Transition to HALTED state
 *   4. Return -1 (no further writes accepted)
 *
 * Forbidden (SRS-007-SHALL-061):
 *   - Silent truncation without marker
 *   - Wrap-around / circular buffer
 *   - Undefined overflow behaviour
 */
int ax_fallback_log_write(
    ax_fallback_log_t    *log,
    ax_violation_t        violation,
    const uint8_t         evidence_hash[32],
    const char           *rule_id,
    ax_gov_ctx_t         *gov,
    ax_gov_fault_flags_t *faults
) {
    ax_proof_record_t *entry;
    uint8_t zero_head[32] = {0};
    const uint8_t *chain_head_ptr;
    uint64_t seq;

    if (log == NULL || evidence_hash == NULL || rule_id == NULL ||
        faults == NULL) {
        return -1;
    }

    /* Refuse writes after overflow or halt — no further records accepted */
    if (log->state == AX_FALLBACK_STATE_OVERFLOW ||
        log->state == AX_FALLBACK_STATE_HALTED) {
        return -1;
    }

    /*
     * F012: Atomicity model — Option A (SRS-007-SHALL-058).
     *
     * All governance operations execute in a single thread with deterministic
     * sequencing. The STOPPED barrier is enforced by the governance context:
     * once gov->in_fault_mode is set, the only permitted operation is writing
     * the fault record to the fallback log. No other execution path proceeds.
     *
     * The entry_count increment happens ONLY after the complete proof record
     * has been written and finalised (see end of this function). A partial
     * write cannot be observed by any reader — entry_count is the commit point.
     *
     * Overflow marker is written as a single, atomic unit before entry_count
     * is incremented, ensuring it cannot be partially observed.
     */

    /* Mark as active on first write */
    if (log->state == AX_FALLBACK_STATE_IDLE) {
        log->state = AX_FALLBACK_STATE_ACTIVE;
    }

    /* Check capacity — one slot reserved for OVERFLOW_MARKER */
    if (log->entry_count >= AX_FALLBACK_LOG_MAX_ENTRIES - 1U) {
        /*
         * One slot remaining. Write OVERFLOW_MARKER into the last
         * slot, then transition to OVERFLOW/HALTED.
         * The fault that triggered this write is lost — that is
         * acceptable per Option A.1: stop appending, write marker.
         */
        entry = &log->entries[log->entry_count];

        chain_head_ptr = (gov != NULL) ? gov->chain_head : zero_head;
        seq = (gov != NULL) ? gov->next_proof_seq : 0;

        /* Build overflow marker proof record */
        if (ax_proof_init(entry, OVERFLOW_CLAIM,
                          AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
                          OVERFLOW_RULE_ID,
                          chain_head_ptr, seq, faults) != 0) {
            /* Cannot even write the marker — hard halt */
            log->state = AX_FALLBACK_STATE_HALTED;
            log->overflow_flag = true;
            faults->overflow = 1;
            return -1;
        }

        /* Overflow marker has no evidence refs — empty is allowed here
         * because this is a system state record, not a governance proof.
         * We add a zero sentinel to satisfy the non-empty requirement. */
        {
            uint8_t sentinel[32] = {0};
            (void)ax_proof_add_evidence(entry, sentinel, faults);
        }

        ax_proof_set_result(entry, AX_PROOF_RESULT_INTEGRITY_FAULT,
                            AX_VIOLATION_FALLBACK_OVERFLOW, faults);
        (void)ax_proof_finalise(entry, faults);

        log->entry_count++;
        log->overflow_flag = true;
        log->state = AX_FALLBACK_STATE_OVERFLOW;

        /* Transition to HALTED after overflow marker is written */
        log->state = AX_FALLBACK_STATE_HALTED;
        faults->overflow = 1;
        return -1;
    }

    /* Normal write path */
    entry = &log->entries[log->entry_count];
    chain_head_ptr = (gov != NULL) ? gov->chain_head : zero_head;
    seq = (gov != NULL) ? gov->next_proof_seq : 0;

    /*
     * Use a clean local faults struct for proof construction.
     * The caller's faults may already have governance flags set
     * (e.g. from ax_gov_enter_fault_mode). ax_proof_finalise bails
     * if any flag is pre-set, so we isolate and merge back.
     */
    {
        ax_gov_fault_flags_t local_faults;
        ax_gov_clear_faults(&local_faults);

        if (ax_proof_init(entry, "Governance integrity fault recorded to fallback log",
                          AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
                          rule_id,
                          chain_head_ptr, seq, &local_faults) != 0) {
            return -1;
        }

        if (ax_proof_add_evidence(entry, evidence_hash, &local_faults) != 0) {
            return -1;
        }

        ax_proof_set_result(entry, AX_PROOF_RESULT_INTEGRITY_FAULT,
                            violation, &local_faults);

        if (ax_proof_finalise(entry, &local_faults) != 0) {
            return -1;
        }

        /* Merge construction faults back */
        if (local_faults.overflow) { faults->overflow = 1; }
    }

    log->entry_count++;

    /* Advance governance sequence if gov is available */
    if (gov != NULL) {
        gov->next_proof_seq++;
    }

    return 0;
}

/*
 * ============================================================================
 * Public API — Fault Recording
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-035: Integrity fault definition
 * @traceability SRS-007-SHALL-036: Integrity fault recording
 * @traceability SRS-007-SHALL-037: Integrity fault response
 * @traceability SRS-007-SHALL-038: No silent governance failure
 * @traceability SRS-007-SHALL-053: Ledger failure mode
 *
 * Routing:
 *   ledger_available = true  → build proof via ax_verify_build_proof (to L6)
 *   ledger_available = false → write to fallback_log
 *
 * In both cases, governance enters fault mode and agent transitions
 * to STOPPED (SRS-007-SHALL-037).
 */
int ax_fault_record(
    ax_proof_record_t    *proof,
    ax_violation_t        violation,
    const uint8_t         evidence_hash[32],
    const char           *rule_id,
    bool                  ledger_available,
    ax_fallback_log_t    *fallback_log,
    ax_gov_ctx_t         *gov,
    ax_gov_fault_flags_t *faults
) {
    uint8_t evidence[1][32];
    ax_gov_fault_flags_t local_faults;
    int rc;

    if (evidence_hash == NULL || rule_id == NULL ||
        gov == NULL || faults == NULL) {
        return -1;
    }

    /* Step 1: Transition governance to fault mode (SRS-007-SHALL-037) */
    ax_gov_enter_fault_mode(gov, violation, faults);

    if (ledger_available) {
        /*
         * L6 ledger available: commit AX:PROOF:v1 result=INTEGRITY_FAULT.
         *
         * Use a clean local faults struct for proof construction.
         * ax_proof_finalise bails early if any fault flag is already
         * set. The flags from ax_gov_enter_fault_mode are governance
         * state, not proof-construction errors. Merge back afterward.
         */
        if (proof == NULL) {
            return -1;
        }

        ax_gov_clear_faults(&local_faults);
        memcpy(evidence[0], evidence_hash, 32);

        rc = ax_verify_build_proof(
            proof,
            "Governance integrity fault detected and recorded",
            AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
            rule_id,
            (const uint8_t (*)[32])evidence,
            1,
            AX_PROOF_RESULT_INTEGRITY_FAULT,
            violation,
            gov,
            &local_faults);

        /* Merge any new construction faults into caller flags */
        if (local_faults.overflow)       { faults->overflow       = 1; }
        if (local_faults.hash_mismatch)  { faults->hash_mismatch  = 1; }
        if (local_faults.ordering_fault) { faults->ordering_fault = 1; }

        return rc;
    } else {
        /*
         * L6 ledger unavailable: write to fallback log (Option A).
         * SRS-007-SHALL-053: fallback log format identical to AX:PROOF:v1.
         */
        if (fallback_log == NULL) {
            faults->ledger_fault = 1;
            return -1;
        }

        /* Same isolation for the fallback write path */
        ax_gov_clear_faults(&local_faults);
        rc = ax_fallback_log_write(fallback_log, violation, evidence_hash,
                                   rule_id, gov, &local_faults);
        if (local_faults.overflow) { faults->overflow = 1; }
        return rc;
    }
}

/*
 * ============================================================================
 * Public API — Fallback Log Queries
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-061: Fallback log overflow
 */
bool ax_fallback_log_is_overflow(const ax_fallback_log_t *log) {
    if (log == NULL) { return false; }
    return log->overflow_flag;
}

/**
 * @traceability SRS-007-SHALL-061: Fallback log overflow
 */
bool ax_fallback_log_is_halted(const ax_fallback_log_t *log) {
    if (log == NULL) { return false; }
    return log->state == AX_FALLBACK_STATE_HALTED;
}

size_t ax_fallback_log_entry_count(const ax_fallback_log_t *log) {
    if (log == NULL) { return 0; }
    return log->entry_count;
}

const ax_proof_record_t *ax_fallback_log_get_entry(
    const ax_fallback_log_t *log,
    size_t                   index
) {
    if (log == NULL || index >= log->entry_count) {
        return NULL;
    }
    return &log->entries[index];
}
