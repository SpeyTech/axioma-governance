/**
 * @file compliance.c
 * @brief Compliance Report Generation Implementation
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Generates Track A and Track B compliance reports, each with:
 *  - Bounded evidence array
 *  - Evidence closure proof (Merkle root)
 *  - AX:PROOF:v1 commitment
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-023: Track A evidence package
 * @traceability SRS-007-SHALL-024: Track B evidence package
 * @traceability SRS-007-SHALL-025: Report trigger conditions
 * @traceability SRS-007-SHALL-026: Report canonical format
 * @traceability SRS-007-SHALL-027: Report independence
 * @traceability SRS-007-SHALL-028: Golden reference inclusion
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */

#include "ax_compliance.h"
#include "ax_verify.h"
#include "axilog/types.h"
#include <string.h>

/*
 * ============================================================================
 * String Tables
 * ============================================================================
 */

static const char *TRACK_STRINGS[] = {
    "TRACK_A",
    "TRACK_B"
};

static const char *TRIGGER_STRINGS[] = {
    "AGENT_STOPPED",
    "POLICY_BREACH",
    "ANCHOR_INTERVAL",
    "ON_DEMAND",
    "RECOVERY"
};

/*
 * ============================================================================
 * Public API — String Conversion
 * ============================================================================
 */

const char *ax_compliance_track_to_string(ax_compliance_track_t track) {
    if ((int)track > AX_COMPLIANCE_TRACK_B) {
        return "UNKNOWN";
    }
    return TRACK_STRINGS[(int)track];
}

const char *ax_compliance_trigger_to_string(ax_report_trigger_t trigger) {
    if ((int)trigger > AX_REPORT_TRIGGER_RECOVERY) {
        return "UNKNOWN";
    }
    return TRIGGER_STRINGS[(int)trigger];
}

/*
 * ============================================================================
 * Public API — Report Lifecycle
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-025: Report trigger conditions
 * @traceability SRS-007-SHALL-026: Report canonical format
 */
int ax_compliance_report_init(
    ax_compliance_report_t *report,
    ax_compliance_track_t   track,
    ax_report_trigger_t     trigger,
    const uint8_t           chain_head[32],
    uint64_t                chain_seq,
    ax_gov_fault_flags_t   *faults
) {
    if (report == NULL || chain_head == NULL || faults == NULL) {
        return -1;
    }

    memset(report, 0, sizeof(ax_compliance_report_t));

    report->track   = track;
    report->trigger = trigger;
    memcpy(report->chain_head, chain_head, 32);
    report->chain_seq       = chain_seq;
    report->evidence_count  = 0;
    report->closure_computed = false;
    report->proof_built     = false;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 */
int ax_compliance_add_evidence(
    ax_compliance_report_t *report,
    const uint8_t           evidence_hash[32],
    ax_gov_fault_flags_t   *faults
) {
    if (report == NULL || evidence_hash == NULL || faults == NULL) {
        return -1;
    }

    if (report->evidence_count >= AX_COMPLIANCE_MAX_EVIDENCE) {
        faults->overflow = 1;
        return -1;
    }

    memcpy(report->evidence[report->evidence_count], evidence_hash, 32);
    report->evidence_count++;
    report->closure_computed = false;  /* invalidate on new evidence */

    return 0;
}

/**
 * @traceability SRS-007-SHALL-023: Track A evidence package
 * @traceability SRS-007-SHALL-028: Golden reference inclusion
 *
 * Track A requires: Merkle provenance chains, 368-byte golden reference,
 * quantisation error bounds, conformance results, substrate cert, weight fingerprint.
 *
 * The golden reference (SRS-007-SHALL-028) proves the production model
 * is byte-identical to the audited and certified model.
 */
int ax_compliance_add_track_a_evidence(
    ax_compliance_report_t        *report,
    const ax_track_a_evidence_t   *evidence,
    ax_gov_fault_flags_t          *faults
) {
    if (report == NULL || evidence == NULL || faults == NULL) {
        return -1;
    }

    if (report->track != AX_COMPLIANCE_TRACK_A) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* Add each present evidence field */
    if (evidence->merkle_provenance_present) {
        if (ax_compliance_add_evidence(report, evidence->merkle_provenance_hash, faults) != 0) {
            return -1;
        }
    }

    /* Golden reference — required by SRS-007-SHALL-028 for Track A */
    if (evidence->golden_reference_present) {
        if (ax_compliance_add_evidence(report, evidence->golden_reference_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->quant_error_bounds_present) {
        if (ax_compliance_add_evidence(report, evidence->quant_error_bounds_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->conformance_results_present) {
        if (ax_compliance_add_evidence(report, evidence->conformance_results_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->substrate_cert_present) {
        if (ax_compliance_add_evidence(report, evidence->substrate_cert_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->weight_fingerprint_present) {
        if (ax_compliance_add_evidence(report, evidence->weight_fingerprint_hash, faults) != 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-024: Track B evidence package
 */
int ax_compliance_add_track_b_evidence(
    ax_compliance_report_t        *report,
    const ax_track_b_evidence_t   *evidence,
    ax_gov_fault_flags_t          *faults
) {
    if (report == NULL || evidence == NULL || faults == NULL) {
        return -1;
    }

    if (report->track != AX_COMPLIANCE_TRACK_B) {
        faults->integrity_fault = 1;
        return -1;
    }

    if (evidence->audit_ledger_present) {
        if (ax_compliance_add_evidence(report, evidence->audit_ledger_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->oracle_records_present) {
        if (ax_compliance_add_evidence(report, evidence->oracle_records_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->drift_reports_present) {
        if (ax_compliance_add_evidence(report, evidence->drift_reports_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->policy_records_present) {
        if (ax_compliance_add_evidence(report, evidence->policy_records_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->math_traces_present) {
        if (ax_compliance_add_evidence(report, evidence->math_traces_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->anchor_log_present) {
        if (ax_compliance_add_evidence(report, evidence->anchor_log_hash, faults) != 0) {
            return -1;
        }
    }

    if (evidence->evidence_closure_present) {
        if (ax_compliance_add_evidence(report, evidence->evidence_closure_hash, faults) != 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 *
 * Constructs the left-balanced binary Merkle tree over all evidence
 * hashes and stores the root in report->evidence_closure_root.
 *
 * Input hashes are sorted lexicographically before tree construction
 * to ensure deterministic ordering regardless of insertion order.
 */
int ax_compliance_compute_closure(
    ax_compliance_report_t *report,
    ax_gov_fault_flags_t   *faults
) {
    ax_merkle_ctx_t merkle;

    if (report == NULL || faults == NULL) {
        return -1;
    }

    ax_merkle_init(&merkle, faults);

    if (report->evidence_count == 0) {
        /* Empty tree: root = 32 zero bytes (SRS-007-SHALL-059) */
        memset(report->evidence_closure_root, 0, 32);
        report->closure_computed = true;
        return 0;
    }

    /* ax_merkle_add_leaves sorts lexicographically before adding */
    if (ax_merkle_add_leaves(&merkle,
                             (const uint8_t (*)[32])report->evidence,
                             report->evidence_count,
                             faults) != 0) {
        return -1;
    }

    if (ax_merkle_compute_root(&merkle, faults) != 0) {
        return -1;
    }

    if (ax_merkle_get_root(&merkle, report->evidence_closure_root, faults) != 0) {
        return -1;
    }

    report->closure_computed = true;
    return 0;
}

/**
 * @traceability SRS-007-SHALL-026: Report canonical format
 * @traceability SRS-007-SHALL-027: Report independence
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 *
 * Finalisation sequence:
 *   1. Compute evidence closure (Merkle root)
 *   2. Add closure root as evidence reference in the AX:PROOF:v1
 *   3. Build and finalise AX:PROOF:v1 with proof_type = COMPLIANCE_SUMMARY
 *
 * The proof carries the chain head (prev_chain_head) and the evidence
 * closure root, making it independently verifiable.
 */
int ax_compliance_finalise(
    ax_compliance_report_t *report,
    ax_gov_ctx_t           *gov,
    ax_gov_fault_flags_t   *faults
) {
    uint8_t evidence[2][32];
    const char *claim;

    if (report == NULL || gov == NULL || faults == NULL) {
        return -1;
    }

    if (report->proof_built) {
        /* Idempotent — already finalised */
        return 0;
    }

    /* Step 1: Compute evidence closure Merkle root */
    if (ax_compliance_compute_closure(report, faults) != 0) {
        return -1;
    }

    /* Step 2: Build AX:PROOF:v1
     * Evidence refs:
     *   [0] evidence_closure_root — Merkle root proves completeness
     *   [1] chain_head            — binds report to ledger state
     */
    memcpy(evidence[0], report->evidence_closure_root, 32);
    memcpy(evidence[1], report->chain_head, 32);

    claim = (report->track == AX_COMPLIANCE_TRACK_A)
        ? "Track A compliance report: safety-critical evidence package (DO-178C, IEC 62304, ISO 26262)"
        : "Track B compliance report: enterprise governance evidence package (EU AI Act Art 9, ISO/IEC 42001)";

    if (ax_verify_build_proof(
            &report->proof,
            claim,
            AX_PROOF_TYPE_COMPLIANCE_SUMMARY,
            "SRS-007-SHALL-026",
            (const uint8_t (*)[32])evidence,
            2,
            AX_PROOF_RESULT_VALID,
            AX_VIOLATION_NONE,
            gov,
            faults) != 0) {
        return -1;
    }

    report->proof_built = true;
    return 0;
}

/**
 * @traceability SRS-007-SHALL-027: Report independence
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 *
 * Recomputes the Merkle root over all evidence in the report and
 * checks it matches the committed evidence_closure_root. Any mismatch
 * means the evidence set has been modified after finalisation.
 */
int ax_compliance_verify_closure(
    ax_compliance_report_t *report,
    ax_gov_fault_flags_t   *faults
) {
    uint8_t stored_root[32];
    ax_merkle_ctx_t merkle;
    uint8_t recomputed_root[32];

    if (report == NULL || faults == NULL) {
        return -1;
    }

    if (!report->closure_computed) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* Save stored root before recomputing */
    memcpy(stored_root, report->evidence_closure_root, 32);

    /* Recompute */
    ax_merkle_init(&merkle, faults);

    if (report->evidence_count > 0) {
        if (ax_merkle_add_leaves(&merkle,
                                 (const uint8_t (*)[32])report->evidence,
                                 report->evidence_count,
                                 faults) != 0) {
            return -1;
        }
        if (ax_merkle_compute_root(&merkle, faults) != 0) {
            return -1;
        }
        if (ax_merkle_get_root(&merkle, recomputed_root, faults) != 0) {
            return -1;
        }
    } else {
        memset(recomputed_root, 0, 32);
    }

    if (memcmp(recomputed_root, stored_root, 32) != 0) {
        faults->hash_mismatch = 1;
        return -1;
    }

    return 0;
}
