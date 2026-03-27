/**
 * @file ax_anchor.h
 * @brief External Anchor Publication — L7 Governance
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Periodic cryptographic anchors committed to a public append-only
 * transparency log. The anchor hash is the canonical deterministic
 * proof. The GPG signature is an external, non-deterministic
 * attestation of that proof (SRS-007-SHALL-060).
 *
 * Anchor computation (SRS-007-SHALL-030):
 *   anchor = SHA-256("AX:ANCHOR:v1" ‖ LE64(anchor_time_seq) ‖ chain_head_hash)
 *
 * Anchor time is bound to a Time Oracle AX:OBS:v1 record
 * (SRS-007-SHALL-052), not a raw timestamp.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-029: Anchor requirement
 * @traceability SRS-007-SHALL-030: Anchor computation
 * @traceability SRS-007-SHALL-031: Anchor signing
 * @traceability SRS-007-SHALL-032: Anchor commitment
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 * @traceability SRS-007-SHALL-034: Anchor verification
 * @traceability SRS-007-SHALL-052: Anchor time as oracle
 * @traceability SRS-007-SHALL-060: GPG signature determinism boundary
 */

#ifndef AX_ANCHOR_H
#define AX_ANCHOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ax_governance.h"
#include "ax_proof.h"

/**
 * @brief Anchor record structure
 *
 * The anchor_hash is the canonical deterministic proof.
 * The GPG signature (if present) is an external attestation only —
 * it is NOT part of the deterministic payload and MUST NOT be
 * included in any AX:PROOF:v1 record or commitment computation.
 *
 * @traceability SRS-007-SHALL-030: Anchor computation
 * @traceability SRS-007-SHALL-052: Anchor time as oracle
 * @traceability SRS-007-SHALL-060: GPG signature determinism boundary
 */
typedef struct {
    /* Deterministic fields — part of canonical proof */
    uint8_t  anchor_hash[32];       /**< SHA-256("AX:ANCHOR:v1" ‖ LE64(time_seq) ‖ chain_head) */
    uint8_t  chain_head[32];        /**< L6 chain head at time of anchor */
    uint64_t anchor_time_seq;       /**< ledger_seq of Time Oracle AX:OBS:v1 */
    uint64_t anchor_ledger_seq;     /**< ledger_seq of AX:PROOF:v1 commitment */

    /* External attestation — NOT deterministic, NOT in proof payload */
    /* GPG signature is stored externally (latest-anchor.txt).        */
    /* It is appended after anchor_hash is committed to the ledger.   */

    /* Proof record for ledger commitment */
    ax_proof_record_t proof;        /**< AX:PROOF:v1 with proof_type = ANCHOR_PUBLICATION */
    bool              proof_built;  /**< Whether proof has been built */
} ax_anchor_record_t;

/**
 * @brief Anchor configuration
 *
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 */
typedef struct {
    uint64_t interval_seq_count;    /**< Anchor every N ledger sequences */
    uint64_t next_anchor_seq;       /**< Ledger seq at which next anchor fires */
    bool     initialised;
} ax_anchor_config_t;

/**
 * @brief Initialise anchor configuration
 *
 * The interval must be declared at system initialisation and committed
 * to the configuration manifest.
 *
 * @param cfg Anchor configuration to initialise
 * @param interval_seq_count Anchor every N ledger sequences (must be > 0)
 * @param current_ledger_seq Current ledger sequence
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 */
int ax_anchor_config_init(
    ax_anchor_config_t   *cfg,
    uint64_t              interval_seq_count,
    uint64_t              current_ledger_seq,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Check whether an anchor is due
 *
 * @param cfg Anchor configuration
 * @param current_ledger_seq Current ledger sequence
 * @return true if anchor should be published now
 *
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 */
bool ax_anchor_is_due(
    const ax_anchor_config_t *cfg,
    uint64_t                  current_ledger_seq
);

/**
 * @brief Compute anchor hash
 *
 * anchor = SHA-256("AX:ANCHOR:v1" ‖ LE64(anchor_time_seq) ‖ chain_head_hash)
 *
 * The anchor_time_seq is the ledger_seq of the committed Time Oracle
 * AX:OBS:v1 record, NOT a raw system timestamp.
 *
 * @param chain_head Current L6 chain head (32 bytes)
 * @param anchor_time_seq ledger_seq of Time Oracle AX:OBS:v1
 * @param anchor_hash_out Output buffer for anchor hash (32 bytes)
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-030: Anchor computation
 * @traceability SRS-007-SHALL-052: Anchor time as oracle
 */
void ax_anchor_compute_hash(
    const uint8_t         chain_head[32],
    uint64_t              anchor_time_seq,
    uint8_t               anchor_hash_out[32],
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Build anchor record (compute hash and construct proof)
 *
 * Computes the anchor hash and builds the AX:PROOF:v1 commitment
 * record. Does NOT perform GPG signing — the GPG signature is an
 * external attestation step (SRS-007-SHALL-060).
 *
 * @param record Anchor record to populate
 * @param chain_head Current L6 chain head
 * @param anchor_time_seq ledger_seq of Time Oracle AX:OBS:v1
 * @param time_obs_hash SHA-256 of the Time Oracle AX:OBS:v1 record
 * @param gov Governance context (chain head, sequence)
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-029: Anchor requirement
 * @traceability SRS-007-SHALL-030: Anchor computation
 * @traceability SRS-007-SHALL-032: Anchor commitment
 * @traceability SRS-007-SHALL-052: Anchor time as oracle
 */
int ax_anchor_build(
    ax_anchor_record_t   *record,
    const uint8_t         chain_head[32],
    uint64_t              anchor_time_seq,
    const uint8_t         time_obs_hash[32],
    ax_gov_ctx_t         *gov,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Verify an anchor record
 *
 * Recomputes the anchor hash from the stored fields and verifies
 * it matches the committed anchor_hash. A third party holding only
 * the public key and the transparency log can use this to verify
 * system state has not been modified since the anchor.
 *
 * @param record Anchor record to verify
 * @param faults Fault context
 * @return 0 if valid, -1 if hash mismatch
 *
 * @traceability SRS-007-SHALL-034: Anchor verification
 */
int ax_anchor_verify(
    const ax_anchor_record_t *record,
    ax_gov_fault_flags_t     *faults
);

/**
 * @brief Advance anchor configuration after publication
 *
 * Updates next_anchor_seq so the following anchor fires at the
 * correct interval.
 *
 * @param cfg Anchor configuration
 * @param published_at_seq Ledger seq at which anchor was published
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 */
void ax_anchor_advance(
    ax_anchor_config_t   *cfg,
    uint64_t              published_at_seq,
    ax_gov_fault_flags_t *faults
);

#ifdef __cplusplus
}
#endif

#endif /* AX_ANCHOR_H */
