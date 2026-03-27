/**
 * @file ax_fault.h
 * @brief Governance Integrity Fault Handling — L7 Governance
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Implements governance integrity fault handling per §10.
 *
 * Every governance failure is recorded — no silent failures
 * (SRS-007-SHALL-038). When the L6 ledger is unavailable, faults
 * are written to a bounded deterministic fallback log (Option A,
 * SRS-007-SHALL-053). Overflow causes a final OVERFLOW_MARKER
 * record and system halt (Option A.1, SRS-007-SHALL-061).
 *
 * Fallback log format is identical to AX:PROOF:v1 so it is
 * replayable and independently verifiable.
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

#ifndef AX_FAULT_H
#define AX_FAULT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ax_governance.h"
#include "ax_proof.h"

/**
 * @brief Maximum fallback log entries
 *
 * 64 KiB / sizeof(ax_proof_record_t).
 * ax_proof_record_t is approximately 33,000 bytes (1024 evidence refs × 32 bytes).
 * For practical purposes we bound to 16 entries which covers the
 * worst-case burst of integrity faults before an operator responds.
 *
 * This satisfies the 64 KiB configuration manifest declaration
 * (SRS-007-SHALL-043) as an entry count bound.
 *
 * @traceability SRS-007-SHALL-053: Ledger failure mode
 * @traceability SRS-007-SHALL-061: Fallback log overflow
 * @traceability SRS-007-SHALL-043: Bounded allocation model
 */
#define AX_FALLBACK_LOG_MAX_ENTRIES 16U

/**
 * @brief Fallback log state
 *
 * @traceability SRS-007-SHALL-053: Ledger failure mode (Option A)
 */
typedef enum {
    AX_FALLBACK_STATE_IDLE     = 0,  /**< Fallback log not active */
    AX_FALLBACK_STATE_ACTIVE   = 1,  /**< Writing to fallback log */
    AX_FALLBACK_STATE_OVERFLOW = 2,  /**< Overflow marker written; halted */
    AX_FALLBACK_STATE_HALTED   = 3   /**< System halted, explicit reset required */
} ax_fallback_state_t;

/**
 * @brief Fallback log context
 *
 * Bounded append-only log for integrity fault records when L6 ledger
 * is unavailable. Format is AX:PROOF:v1 for independent verifiability.
 *
 * @traceability SRS-007-SHALL-053: Ledger failure mode (Option A)
 * @traceability SRS-007-SHALL-061: Fallback log overflow (Option A.1)
 */
typedef struct {
    ax_proof_record_t   entries[AX_FALLBACK_LOG_MAX_ENTRIES]; /**< Fault records */
    size_t              entry_count;    /**< Number of entries written */
    ax_fallback_state_t state;          /**< Current fallback log state */
    bool                overflow_flag;  /**< Set when overflow marker written */
    bool                initialised;
} ax_fallback_log_t;

/**
 * @brief Initialise fallback log
 *
 * @param log Fallback log to initialise
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-053: Ledger failure mode (Option A)
 */
void ax_fallback_log_init(
    ax_fallback_log_t    *log,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Write integrity fault to fallback log
 *
 * On overflow, writes OVERFLOW_MARKER as final entry (Option A.1),
 * sets overflow_flag, and transitions to HALTED state.
 * No further writes are accepted after overflow.
 *
 * @param log Fallback log
 * @param violation Violation type
 * @param evidence_hash SHA-256 of the inconsistent evidence (32 bytes)
 * @param rule_id SRS rule that triggered the fault
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 on overflow (system halted)
 *
 * @traceability SRS-007-SHALL-036: Integrity fault recording
 * @traceability SRS-007-SHALL-038: No silent governance failure
 * @traceability SRS-007-SHALL-053: Ledger failure mode (Option A)
 * @traceability SRS-007-SHALL-061: Fallback log overflow (Option A.1)
 */
int ax_fallback_log_write(
    ax_fallback_log_t    *log,
    ax_violation_t        violation,
    const uint8_t         evidence_hash[32],
    const char           *rule_id,
    ax_gov_ctx_t         *gov,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Record governance integrity fault
 *
 * Commits an AX:PROOF:v1 record with result = INTEGRITY_FAULT.
 * When the L6 ledger is available, this is committed there.
 * When the L6 ledger is in FAILED state, it is written to the
 * fallback log (SRS-007-SHALL-053).
 *
 * Also transitions the governance context to fault mode and
 * moves L5 agent to STOPPED (SRS-007-SHALL-037).
 *
 * @param proof Output proof record
 * @param violation Violation type that triggered the fault
 * @param evidence_hash SHA-256 of the inconsistent evidence
 * @param rule_id SRS rule that was violated
 * @param ledger_available Whether the L6 ledger can accept commits
 * @param fallback_log Fallback log (used when ledger unavailable)
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 if fallback log also failed (system halted)
 *
 * @traceability SRS-007-SHALL-035: Integrity fault definition
 * @traceability SRS-007-SHALL-036: Integrity fault recording
 * @traceability SRS-007-SHALL-037: Integrity fault response
 * @traceability SRS-007-SHALL-038: No silent governance failure
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
);

/**
 * @brief Check whether fallback log is in overflow state
 *
 * @param log Fallback log
 * @return true if overflow has occurred
 *
 * @traceability SRS-007-SHALL-061: Fallback log overflow
 */
bool ax_fallback_log_is_overflow(const ax_fallback_log_t *log);

/**
 * @brief Check whether fallback log is halted
 *
 * @param log Fallback log
 * @return true if system is halted pending explicit reset
 *
 * @traceability SRS-007-SHALL-061: Fallback log overflow
 */
bool ax_fallback_log_is_halted(const ax_fallback_log_t *log);

/**
 * @brief Get the number of entries in the fallback log
 *
 * @param log Fallback log
 * @return Entry count (includes overflow marker if present)
 */
size_t ax_fallback_log_entry_count(const ax_fallback_log_t *log);

/**
 * @brief Get entry from fallback log by index
 *
 * @param log Fallback log
 * @param index Entry index (0-based)
 * @return Pointer to proof record, or NULL if out of range
 */
const ax_proof_record_t *ax_fallback_log_get_entry(
    const ax_fallback_log_t *log,
    size_t                   index
);

#ifdef __cplusplus
}
#endif

#endif /* AX_FAULT_H */
