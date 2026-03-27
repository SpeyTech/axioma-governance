/**
 * @file ax_compliance.h
 * @brief Compliance Report Generation — L7 Governance
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Generates independently verifiable compliance reports for Track A
 * (safety-critical: DO-178C, IEC 62304, ISO 26262) and Track B
 * (enterprise governance: EU AI Act Article 9, ISO/IEC 42001,
 * FCA PS22/3, MHRA AI/ML).
 *
 * Every report includes:
 *  - Evidence closure proof (Merkle root over all cited evidence)
 *  - AX:PROOF:v1 commitment with proof_type = COMPLIANCE_SUMMARY
 *  - Chain head at time of generation
 *
 * Reports are independently verifiable by a third party holding only:
 *  - The report document
 *  - The public GPG key for anchor verification
 *  - Access to the public ledger or evidence set
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

#ifndef AX_COMPLIANCE_H
#define AX_COMPLIANCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ax_governance.h"
#include "ax_proof.h"
#include "ax_merkle.h"

/**
 * @brief Compliance report track
 *
 * @traceability SRS-007-SHALL-023: Track A — safety-critical
 * @traceability SRS-007-SHALL-024: Track B — enterprise governance
 */
typedef enum {
    AX_COMPLIANCE_TRACK_A = 0,  /**< Safety-critical (DO-178C, IEC 62304, ISO 26262) */
    AX_COMPLIANCE_TRACK_B = 1   /**< Enterprise governance (EU AI Act Art 9 etc.) */
} ax_compliance_track_t;

/**
 * @brief Report trigger type
 *
 * Reports are triggered by events, not arbitrary sequence counts
 * (SRS-007-SHALL-025).
 *
 * @traceability SRS-007-SHALL-025: Report trigger conditions
 */
typedef enum {
    AX_REPORT_TRIGGER_AGENT_STOPPED   = 0,  /**< Agent transitioned to STOPPED */
    AX_REPORT_TRIGGER_POLICY_BREACH   = 1,  /**< Policy BREACH detected */
    AX_REPORT_TRIGGER_ANCHOR_INTERVAL = 2,  /**< External anchor interval elapsed */
    AX_REPORT_TRIGGER_ON_DEMAND       = 3,  /**< Explicit governance request */
    AX_REPORT_TRIGGER_RECOVERY        = 4   /**< System reset from STOPPED */
} ax_report_trigger_t;

/**
 * @brief Maximum evidence references per compliance report
 *
 * @traceability SRS-007-SHALL-043: Bounded allocation model
 */
#define AX_COMPLIANCE_MAX_EVIDENCE  AX_MAX_EVIDENCE_REFS  /* 1024 */

/**
 * @brief Maximum compliance report size (bytes)
 *
 * @traceability SRS-007-SHALL-043: Bounded allocation model
 */
#define AX_COMPLIANCE_MAX_REPORT_BYTES  (1024U * 1024U)  /* 1 MiB */

/**
 * @brief Track A evidence package (safety-critical)
 *
 * All fields are committed evidence hashes — no live state.
 *
 * @traceability SRS-007-SHALL-023: Track A evidence package
 * @traceability SRS-007-SHALL-028: Golden reference inclusion
 */
typedef struct {
    /* Merkle provenance chains: data → training → quantisation */
    uint8_t  merkle_provenance_hash[32];    /**< certifiable-* Merkle root */
    bool     merkle_provenance_present;

    /* 368-byte golden reference hash */
    uint8_t  golden_reference_hash[32];     /**< certifiable-harness cross-platform proof */
    bool     golden_reference_present;

    /* Quantisation error bounds */
    uint8_t  quant_error_bounds_hash[32];   /**< certifiable-quant ε₀ = 2⁻¹⁷ per layer */
    bool     quant_error_bounds_present;

    /* Conformance test results */
    uint8_t  conformance_results_hash[32];  /**< certifiable-bench correctness-gated */
    bool     conformance_results_present;

    /* Substrate certification */
    uint8_t  substrate_cert_hash[32];       /**< libaxilog no-forbidden-patterns */
    bool     substrate_cert_present;

    /* Weight fingerprint */
    uint8_t  weight_fingerprint_hash[32];   /**< model_id binding proof */
    bool     weight_fingerprint_present;
} ax_track_a_evidence_t;

/**
 * @brief Track B evidence package (enterprise governance)
 *
 * @traceability SRS-007-SHALL-024: Track B evidence package
 */
typedef struct {
    /* Typed audit ledger */
    uint8_t  audit_ledger_hash[32];         /**< axioma-audit complete AX:*:v1 set */
    bool     audit_ledger_present;

    /* Oracle call records */
    uint8_t  oracle_records_hash[32];       /**< axioma-oracle AX:OBS:v1 per interaction */
    bool     oracle_records_present;

    /* Drift detection reports */
    uint8_t  drift_reports_hash[32];        /**< certifiable-monitor TV/JSD/PSI results */
    bool     drift_reports_present;

    /* Policy assertion records */
    uint8_t  policy_records_hash[32];       /**< axioma-policy AX:POLICY:v1 per evaluation */
    bool     policy_records_present;

    /* Mathematical traces */
    uint8_t  math_traces_hash[32];          /**< axioma-governance cross-layer evidence */
    bool     math_traces_present;

    /* External anchor log */
    uint8_t  anchor_log_hash[32];           /**< GPG-signed chain head anchors */
    bool     anchor_log_present;

    /* Evidence closure proof (Merkle root) — required by SRS-007-SHALL-051 */
    uint8_t  evidence_closure_hash[32];     /**< Merkle root of included evidence */
    bool     evidence_closure_present;
} ax_track_b_evidence_t;

/**
 * @brief Compliance report record
 *
 * @traceability SRS-007-SHALL-026: Report canonical format
 * @traceability SRS-007-SHALL-027: Report independence
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 */
typedef struct {
    ax_compliance_track_t   track;          /**< Track A or Track B */
    ax_report_trigger_t     trigger;        /**< What triggered this report */

    /* Chain head at report generation time */
    uint8_t                 chain_head[32]; /**< L6 chain head */
    uint64_t                chain_seq;      /**< L6 ledger_seq at report time */

    /* Evidence closure Merkle root (SRS-007-SHALL-051) */
    uint8_t                 evidence_closure_root[32]; /**< Merkle root over all evidence */
    bool                    closure_computed;

    /* Flat evidence array for Merkle construction */
    uint8_t  evidence[AX_COMPLIANCE_MAX_EVIDENCE][32];
    size_t   evidence_count;

    /* Committed AX:PROOF:v1 (proof_type = COMPLIANCE_SUMMARY) */
    ax_proof_record_t       proof;
    bool                    proof_built;
} ax_compliance_report_t;

/**
 * @brief Initialise a compliance report
 *
 * @param report Report to initialise
 * @param track Track A or Track B
 * @param trigger What triggered this report
 * @param chain_head Current L6 chain head
 * @param chain_seq Current L6 ledger sequence
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
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
);

/**
 * @brief Add evidence hash to report
 *
 * @param report Compliance report
 * @param evidence_hash SHA-256 hash of evidence record (32 bytes)
 * @param faults Fault context
 * @return 0 on success, -1 if full
 *
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 */
int ax_compliance_add_evidence(
    ax_compliance_report_t *report,
    const uint8_t           evidence_hash[32],
    ax_gov_fault_flags_t   *faults
);

/**
 * @brief Add all Track A evidence hashes to report
 *
 * Adds all present evidence fields from the Track A package.
 *
 * @param report Compliance report (must be Track A)
 * @param evidence Track A evidence package
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-023: Track A evidence package
 * @traceability SRS-007-SHALL-028: Golden reference inclusion
 */
int ax_compliance_add_track_a_evidence(
    ax_compliance_report_t        *report,
    const ax_track_a_evidence_t   *evidence,
    ax_gov_fault_flags_t          *faults
);

/**
 * @brief Add all Track B evidence hashes to report
 *
 * @param report Compliance report (must be Track B)
 * @param evidence Track B evidence package
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-024: Track B evidence package
 */
int ax_compliance_add_track_b_evidence(
    ax_compliance_report_t        *report,
    const ax_track_b_evidence_t   *evidence,
    ax_gov_fault_flags_t          *faults
);

/**
 * @brief Compute evidence closure proof (Merkle root)
 *
 * Computes the Merkle root over all evidence hashes added to the
 * report, proving completeness of the evidence set.
 *
 * @param report Compliance report
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
int ax_compliance_compute_closure(
    ax_compliance_report_t *report,
    ax_gov_fault_flags_t   *faults
);

/**
 * @brief Finalise report: compute closure and build AX:PROOF:v1
 *
 * Steps:
 *   1. Sort evidence hashes lexicographically
 *   2. Compute Merkle root (evidence closure proof)
 *   3. Build AX:PROOF:v1 with proof_type = COMPLIANCE_SUMMARY
 *   4. Add evidence closure root as primary evidence reference
 *   5. Finalise proof (hash + commitment)
 *
 * @param report Compliance report
 * @param gov Governance context
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-026: Report canonical format
 * @traceability SRS-007-SHALL-027: Report independence
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 */
int ax_compliance_finalise(
    ax_compliance_report_t *report,
    ax_gov_ctx_t           *gov,
    ax_gov_fault_flags_t   *faults
);

/**
 * @brief Verify report evidence closure
 *
 * Recomputes the Merkle root over all evidence in the report and
 * verifies it matches the committed evidence_closure_root.
 *
 * @param report Compliance report to verify
 * @param faults Fault context
 * @return 0 if valid, -1 if mismatch
 *
 * @traceability SRS-007-SHALL-027: Report independence
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 */
int ax_compliance_verify_closure(
    ax_compliance_report_t *report,
    ax_gov_fault_flags_t   *faults
);

/**
 * @brief Get string name for report track
 *
 * @param track Track enumeration value
 * @return Static string
 */
const char *ax_compliance_track_to_string(ax_compliance_track_t track);

/**
 * @brief Get string name for report trigger
 *
 * @param trigger Trigger enumeration value
 * @return Static string
 */
const char *ax_compliance_trigger_to_string(ax_report_trigger_t trigger);

#ifdef __cplusplus
}
#endif

#endif /* AX_COMPLIANCE_H */
