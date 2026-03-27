/**
 * @file ax_merkle.h
 * @brief Evidence Closure Merkle Tree
 *
 * DVEC: v1.3
 * DETERMINISM: D2 — Constrained Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Implements the Evidence Closure Merkle tree for proving completeness
 * of evidence sets in compliance reports.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */

#ifndef AX_MERKLE_H
#define AX_MERKLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ax_governance.h"

/**
 * @brief Maximum leaves for Merkle tree (compile-time bound)
 *
 * Must accommodate AX_MAX_EVIDENCE_REFS from ax_governance.h
 *
 * @traceability SRS-007-SHALL-043: Bounded allocation model
 */
#define AX_MERKLE_MAX_LEAVES 1024

/**
 * @brief Merkle tree context
 *
 * Tree structure: Binary Merkle tree, left-balanced
 *
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
typedef struct {
    uint8_t  leaves[AX_MERKLE_MAX_LEAVES][32];  /**< Leaf hashes (evidence refs) */
    size_t   leaf_count;                         /**< Number of leaves */
    uint8_t  root[32];                           /**< Computed Merkle root */
    bool     root_computed;                      /**< Whether root is valid */
} ax_merkle_ctx_t;

/**
 * @brief Merkle proof for a single leaf
 *
 * Contains the sibling hashes needed to verify inclusion.
 *
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
typedef struct {
    uint8_t  leaf_hash[32];                      /**< The leaf being proven */
    size_t   leaf_index;                         /**< Index of leaf in tree */
    uint8_t  siblings[20][32];                   /**< Sibling hashes (max depth 20 for 2^20 leaves) */
    bool     is_left[20];                        /**< true if sibling is on left */
    size_t   proof_depth;                        /**< Number of siblings */
    uint8_t  root[32];                           /**< Expected root */
} ax_merkle_proof_t;

/**
 * @brief Initialise Merkle tree context
 *
 * @param ctx Context to initialise
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 */
void ax_merkle_init(
    ax_merkle_ctx_t      *ctx,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Add leaf to Merkle tree
 *
 * Leaves must be added in lexicographically sorted order.
 *
 * @param ctx Merkle tree context
 * @param leaf_hash SHA-256 hash to add as leaf (32 bytes)
 * @param faults Fault context
 * @return 0 on success, -1 if full or out of order
 *
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
int ax_merkle_add_leaf(
    ax_merkle_ctx_t      *ctx,
    const uint8_t         leaf_hash[32],
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Add multiple leaves from an array of hashes
 *
 * Hashes will be sorted lexicographically before adding.
 *
 * @param ctx Merkle tree context
 * @param hashes Array of 32-byte hashes
 * @param count Number of hashes
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
int ax_merkle_add_leaves(
    ax_merkle_ctx_t      *ctx,
    const uint8_t        (*hashes)[32],
    size_t                count,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Compute Merkle root
 *
 * Tree Construction Algorithm (per SRS-007-SHALL-059):
 *
 * Input: Lexicographically sorted list of evidence hashes
 *
 * Leaf Computation:
 *   leaf[i] = evidence_refs[i]  (raw hash, no re-hash)
 *
 * Internal Node Computation:
 *   node = SHA-256(left_child ‖ right_child)
 *
 * Where ‖ denotes byte-wise concatenation (64 bytes total input).
 *
 * Odd Node Handling: Duplicate the last node
 *   If count(nodes) is odd:
 *     nodes.append(nodes[-1])  // duplicate last
 *
 * Tree Construction: Left-to-right, bottom-up
 *   Level 0: [leaf_0, leaf_1, leaf_2, leaf_3, ...]
 *   Level 1: [SHA-256(leaf_0 ‖ leaf_1), SHA-256(leaf_2 ‖ leaf_3), ...]
 *   ...
 *   Level N: [root]
 *
 * Empty Tree: If evidence_refs is empty, root = 32 zero bytes
 *
 * @param ctx Merkle tree context (root will be set)
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
int ax_merkle_compute_root(
    ax_merkle_ctx_t      *ctx,
    ax_gov_fault_flags_t *faults
);

/**
 * @brief Get computed Merkle root
 *
 * @param ctx Merkle tree context
 * @param root_out Output buffer for root (32 bytes)
 * @param faults Fault context
 * @return 0 on success, -1 if root not computed
 *
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 */
int ax_merkle_get_root(
    const ax_merkle_ctx_t *ctx,
    uint8_t                root_out[32],
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Generate inclusion proof for a leaf
 *
 * @param ctx Merkle tree context (must have root computed)
 * @param leaf_index Index of leaf to prove
 * @param proof Output proof structure
 * @param faults Fault context
 * @return 0 on success, -1 on error
 *
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
int ax_merkle_generate_proof(
    const ax_merkle_ctx_t *ctx,
    size_t                 leaf_index,
    ax_merkle_proof_t     *proof,
    ax_gov_fault_flags_t  *faults
);

/**
 * @brief Verify inclusion proof
 *
 * @param proof Merkle proof to verify
 * @param faults Fault context
 * @return 0 if valid, -1 if invalid
 *
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
int ax_merkle_verify_proof(
    const ax_merkle_proof_t *proof,
    ax_gov_fault_flags_t    *faults
);

/**
 * @brief Compare two hashes lexicographically
 *
 * @param a First hash (32 bytes)
 * @param b Second hash (32 bytes)
 * @return <0 if a<b, 0 if a==b, >0 if a>b
 *
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
int ax_merkle_hash_compare(
    const uint8_t a[32],
    const uint8_t b[32]
);

/**
 * @brief Sort array of hashes lexicographically
 *
 * Uses insertion sort (deterministic, O(n²) but bounded).
 *
 * @param hashes Array of 32-byte hashes (modified in place)
 * @param count Number of hashes
 * @param faults Fault context
 *
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
void ax_merkle_sort_hashes(
    uint8_t              (*hashes)[32],
    size_t                count,
    ax_gov_fault_flags_t *faults
);

#ifdef __cplusplus
}
#endif

#endif /* AX_MERKLE_H */
