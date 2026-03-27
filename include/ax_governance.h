/**
 * @file ax_governance.h
 * @brief L7 Axioma Governance — Proof-Carrying Governance Layer
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * This module provides proof-carrying governance over the Axioma stack.
 * Every governance claim becomes a cryptographically evidenced argument
 * over committed evidence records.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-001: Determinism definition
 * @traceability SRS-007-SHALL-002: Evidence closure
 * @traceability SRS-007-SHALL-019: Replay determinism
 * @traceability SRS-007-SHALL-039: Source code traceability
 * @traceability SRS-007-SHALL-042: Bounded memory allocation
 */

#ifndef AX_GOVERNANCE_H
#define AX_GOVERNANCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Forward declarations */
struct ax_proof_record;
struct ax_math_trace;
struct ax_anchor_record;
struct ax_compliance_report;

/**
 * @brief Fault flags for governance operations
 *
 * @traceability SRS-007-SHALL-035: Integrity fault definition
 * @traceability SRS-007-SHALL-036: Integrity fault recording
 */
typedef struct {
    uint32_t integrity_fault  : 1;  /**< Cross-layer verification failure */
    uint32_t hash_mismatch    : 1;  /**< Evidence hash verification failed */
    uint32_t ordering_fault   : 1;  /**< Ordering invariant violated */
    uint32_t weight_mismatch  : 1;  /**< Model weight hash mismatch */
    uint32_t policy_fault     : 1;  /**< Policy non-conformant at init */
    uint32_t ledger_fault     : 1;  /**< L6 ledger in FAILED state */
    uint32_t overflow         : 1;  /**< Buffer overflow prevented */
    uint32_t _reserved        : 25;
} ax_gov_fault_flags_t;

/**
 * @brief Check if any governance fault is set
 *
 * @param f Pointer to fault flags
 * @return true if any fault flag is set
 *
 * @traceability SRS-007-SHALL-038: No silent governance failure
 */
static inline bool ax_gov_has_fault(const ax_gov_fault_flags_t *f) {
    return f->integrity_fault || f->hash_mismatch || f->ordering_fault ||
           f->weight_mismatch || f->policy_fault || f->ledger_fault ||
           f->overflow;
}

/**
 * @brief Clear all governance fault flags
 *
 * @param f Pointer to fault flags to clear
 *
 * @traceability SRS-007-SHALL-037: Integrity fault response
 */
static inline void ax_gov_clear_faults(ax_gov_fault_flags_t *f) {
    f->integrity_fault = 0;
    f->hash_mismatch = 0;
    f->ordering_fault = 0;
    f->weight_mismatch = 0;
    f->policy_fault = 0;
    f->ledger_fault = 0;
    f->overflow = 0;
}

/**
 * @brief Proof type enumeration (closed set per SRS-007-SHALL-005)
 *
 * @traceability SRS-007-SHALL-005: Proof type closed set
 * @traceability SRS-007-SHALL-056: Proof type versioning
 */
typedef enum {
    AX_PROOF_TYPE_ANCHOR_PUBLICATION  = 0,  /**< External anchor commitment */
    AX_PROOF_TYPE_COMPLIANCE_SUMMARY  = 1,  /**< Compliance report proof */
    AX_PROOF_TYPE_CROSS_LAYER_VERIFY  = 2,  /**< Cross-layer chain verification */
    AX_PROOF_TYPE_POLICY_SOUNDNESS    = 3,  /**< Policy evaluation over evidence */
    AX_PROOF_TYPE_REPLAY_EQUIVALENCE  = 4,  /**< Replay produces identical results */
    AX_PROOF_TYPE_SUBSTRATE_CERT      = 5,  /**< L1 substrate certification */
    AX_PROOF_TYPE_WEIGHT_BINDING      = 6,  /**< L2 model identity verification */

    AX_PROOF_TYPE_COUNT               = 7   /**< Total count for validation */
} ax_proof_type_t;

/**
 * @brief Proof result enumeration
 *
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 */
typedef enum {
    AX_PROOF_RESULT_VALID           = 0,  /**< Proof verification passed */
    AX_PROOF_RESULT_INVALID         = 1,  /**< Proof verification failed */
    AX_PROOF_RESULT_INTEGRITY_FAULT = 2   /**< Integrity violation detected */
} ax_proof_result_t;

/**
 * @brief Violation type enumeration (when result is INVALID)
 *
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 * @traceability SRS-007-SHALL-035: Integrity fault definition
 */
typedef enum {
    AX_VIOLATION_NONE               = 0,  /**< No violation */
    AX_VIOLATION_HASH_MISMATCH      = 1,  /**< Hash verification failed */
    AX_VIOLATION_ORDERING           = 2,  /**< Ordering invariant violated */
    AX_VIOLATION_WEIGHT_MISMATCH    = 3,  /**< Weight hash mismatch */
    AX_VIOLATION_POLICY_BREACH      = 4,  /**< Policy breach detected */
    AX_VIOLATION_TRANSITION_FAULT   = 5,  /**< Invalid state transition */
    AX_VIOLATION_EVIDENCE_MISSING   = 6,  /**< Required evidence not found */
    AX_VIOLATION_REPLAY_MISMATCH    = 7,  /**< Replay produced different result */
    AX_VIOLATION_FALLBACK_OVERFLOW  = 8   /**< Fallback log overflow */
} ax_violation_t;

/**
 * @brief Evidence ordering mode
 *
 * @traceability SRS-007-SHALL-057: Evidence ordering mode
 */
typedef enum {
    AX_EVIDENCE_ORDER_LEX       = 0,  /**< Lexicographic sort by hash */
    AX_EVIDENCE_ORDER_TEMPORAL  = 1,  /**< Ascending by ledger_seq */
    AX_EVIDENCE_ORDER_DECLARED  = 2   /**< Order matches ordering_metadata */
} ax_evidence_ordering_t;

/**
 * @brief Policy result enumeration
 *
 * @traceability SRS-007-SHALL-021: Trace required fields
 */
typedef enum {
    AX_POLICY_RESULT_PERMITTED = 0,  /**< Policy permits the action */
    AX_POLICY_RESULT_BREACH    = 1   /**< Policy breach detected */
} ax_policy_result_t;

/**
 * @brief Agent health state (mirrors L5 axioma-agent)
 *
 * @traceability SRS-007-SHALL-017: L4→L5 breach enforcement
 * @traceability SRS-007-SHALL-037: Integrity fault response
 */
typedef enum {
    AX_AGENT_STATE_HEALTHY  = 0,  /**< Normal operation */
    AX_AGENT_STATE_ALARM    = 1,  /**< Degraded operation */
    AX_AGENT_STATE_STOPPED  = 2,  /**< Halted, requires reset */
    AX_AGENT_STATE_FAILED   = 3   /**< Terminal failure */
} ax_agent_state_t;

/**
 * @brief Maximum sizes for bounded allocation (compile-time constants)
 *
 * @traceability SRS-007-SHALL-043: Bounded allocation model
 */
#define AX_MAX_EVIDENCE_REFS      1024      /**< Max evidence refs per proof */
#define AX_MAX_TRACE_SIZE         4096      /**< Max mathematical trace bytes */
#define AX_MAX_CLAIM_SIZE         256       /**< Max claim string bytes */
#define AX_MAX_RULE_ID_SIZE       64        /**< Max rule_id string bytes */
#define AX_MAX_POLICIES           32        /**< Max policies per trace */
#define AX_MAX_ORDERING_META_SIZE 512       /**< Max ordering_metadata bytes */

/**
 * @brief Governance configuration context
 *
 * @traceability SRS-007-SHALL-044: Configuration canonicality
 * @traceability SRS-007-SHALL-002: Evidence closure
 */
typedef struct {
    uint8_t  config_hash[32];           /**< SHA-256 of canonical config */
    uint8_t  policy_set_hash[32];       /**< SHA-256 of canonical policy set */
    uint64_t config_ledger_seq;         /**< Ledger seq of config commit */
    bool     initialised;               /**< Config committed to ledger */
} ax_gov_config_t;

/**
 * @brief Governance context (main runtime state)
 *
 * @traceability SRS-007-SHALL-001: Determinism definition
 * @traceability SRS-007-SHALL-002: Evidence closure
 */
typedef struct {
    ax_gov_config_t      config;        /**< Configuration state */
    uint8_t              chain_head[32];/**< Current L6 chain head */
    uint64_t             next_proof_seq;/**< Next proof ledger_seq */
    ax_agent_state_t     agent_state;   /**< Current agent health state */
    ax_gov_fault_flags_t faults;        /**< Accumulated fault flags */
    bool                 in_fault_mode; /**< System in integrity fault mode */
} ax_gov_ctx_t;

/**
 * @brief Initialise governance context
 *
 * @param ctx Context to initialise
 * @param config_hash SHA-256 of canonical configuration
 * @param policy_set_hash SHA-256 of canonical policy set
 * @param genesis_chain_head Initial L6 chain head
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-001: Determinism definition
 * @traceability SRS-007-SHALL-044: Configuration canonicality
 */
int ax_gov_init(
    ax_gov_ctx_t         *ctx,
    const uint8_t         config_hash[32],
    const uint8_t         policy_set_hash[32],
    const uint8_t         genesis_chain_head[32],
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Update chain head after L6 commit
 *
 * @param ctx Governance context
 * @param new_chain_head New L6 chain head hash
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-055: Chain head reference
 */
void ax_gov_update_chain_head(
    ax_gov_ctx_t         *ctx,
    const uint8_t         new_chain_head[32],
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Transition to integrity fault mode
 *
 * @param ctx Governance context
 * @param violation Type of violation that triggered fault
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-035: Integrity fault definition
 * @traceability SRS-007-SHALL-037: Integrity fault response
 */
void ax_gov_enter_fault_mode(
    ax_gov_ctx_t         *ctx,
    ax_violation_t        violation,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Check if proof type is valid (within closed set)
 *
 * @param proof_type Proof type to validate
 * @return true if valid, false otherwise
 *
 * @traceability SRS-007-SHALL-005: Proof type closed set
 */
static inline bool ax_proof_type_valid(ax_proof_type_t proof_type) {
    return proof_type < AX_PROOF_TYPE_COUNT;
}

/**
 * @brief Get string representation of proof type
 *
 * @param proof_type Proof type enumeration value
 * @return Static string representation
 *
 * @traceability SRS-007-SHALL-005: Proof type closed set
 */
const char *ax_proof_type_to_string(ax_proof_type_t proof_type);

/**
 * @brief Get string representation of evidence ordering mode
 *
 * @param ordering Evidence ordering mode
 * @return Static string representation
 *
 * @traceability SRS-007-SHALL-057: Evidence ordering mode
 */
const char *ax_evidence_ordering_to_string(ax_evidence_ordering_t ordering);

/**
 * @brief Get string representation of proof result
 *
 * @param result Proof result enumeration value
 * @return Static string representation
 *
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 */
const char *ax_proof_result_to_string(ax_proof_result_t result);

/**
 * @brief Get string representation of violation type
 *
 * @param violation Violation type enumeration value
 * @return Static string representation
 *
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 */
const char *ax_violation_to_string(ax_violation_t violation);

#ifdef __cplusplus
}
#endif

#endif /* AX_GOVERNANCE_H */
