/**
 * @file merkle.c
 * @brief Evidence Closure Merkle Tree Implementation
 *
 * DVEC: v1.3
 * DETERMINISM: D1 — Strict Deterministic
 * MEMORY: Bounded Allocation Model (caller-provided buffers)
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Implements Merkle tree construction for evidence closure, enabling
 * compact proof of evidence set membership.
 *
 * Algorithm (per SRS-007-SHALL-059):
 * - Binary tree, left-balanced
 * - Odd node duplication for balanced structure
 * - Leaves are raw evidence hashes (no re-hash)
 * - Internal nodes: SHA-256(left || right)
 * - Bottom-up construction
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */

#include "ax_merkle.h"
#include "axilog/types.h"
#include <string.h>

/*
 * ============================================================================
 * Internal Constants
 * ============================================================================
 */

/**
 * @brief Maximum tree depth (log2(1024) = 10, +10 for safety)
 */
#define AX_MERKLE_MAX_DEPTH 20

/*
 * ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * @brief Hash two 32-byte nodes together
 *
 * internal_node = SHA-256(left || right)
 *
 * @param left Left child hash (32 bytes)
 * @param right Right child hash (32 bytes)
 * @param out Output hash (32 bytes)
 *
 * @traceability SRS-007-SHALL-059: Internal node computation
 */
static void hash_pair(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
    uint8_t combined[64];
    memcpy(combined, left, 32);
    memcpy(combined + 32, right, 32);
    ax_sha256(combined, 64, out);
}

/*
 * ============================================================================
 * Public API — Context Management
 * ============================================================================
 */

/**
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 */
void ax_merkle_init(
    ax_merkle_ctx_t      *ctx,
    ax_gov_fault_flags_t *faults
) {
    (void)faults;  /* Not used but kept for API consistency */

    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(ax_merkle_ctx_t));
    ctx->leaf_count = 0;
    ctx->root_computed = false;
}

/**
 * @traceability SRS-007-SHALL-059: Merkle tree leaf addition
 */
int ax_merkle_add_leaf(
    ax_merkle_ctx_t      *ctx,
    const uint8_t         leaf_hash[32],
    ax_gov_fault_flags_t *faults
) {
    if (ctx == NULL || leaf_hash == NULL || faults == NULL) {
        return -1;
    }

    if (ctx->leaf_count >= AX_MERKLE_MAX_LEAVES) {
        faults->overflow = 1;
        return -1;
    }

    /* Leaves are raw hashes, no re-hashing */
    memcpy(ctx->leaves[ctx->leaf_count], leaf_hash, 32);
    ctx->leaf_count++;

    /* Invalidate root since leaves changed */
    ctx->root_computed = false;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-059: Merkle tree bulk leaf addition
 */
int ax_merkle_add_leaves(
    ax_merkle_ctx_t      *ctx,
    const uint8_t        (*hashes)[32],
    size_t                count,
    ax_gov_fault_flags_t *faults
) {
    /*
     * Sort a local copy of the input hashes lexicographically before
     * inserting. This ensures that ax_merkle_compute_root's sorted-input
     * precondition (F011) is always satisfied when leaves are added via
     * this batch path.
     *
     * The sort is on the local copy only — caller's array is unchanged.
     */
    uint8_t sorted[AX_MERKLE_MAX_LEAVES][32];
    size_t i;

    if (ctx == NULL || hashes == NULL || faults == NULL) {
        return -1;
    }

    if (count == 0) {
        return 0;
    }

    if (count > AX_MERKLE_MAX_LEAVES) {
        faults->overflow = 1;
        return -1;
    }

    /* Copy to local buffer */
    for (i = 0; i < count; i++) {
        memcpy(sorted[i], hashes[i], 32);
    }

    /* Sort lexicographically (insertion sort — deterministic, bounded) */
    ax_merkle_sort_hashes(sorted, count, faults);

    /* Insert in sorted order */
    for (i = 0; i < count; i++) {
        if (ax_merkle_add_leaf(ctx, sorted[i], faults) != 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-059: Merkle tree root computation
 *
 * Algorithm:
 * 1. Copy leaves to working buffer
 * 2. If odd number of nodes, duplicate last node
 * 3. Pairwise hash: node[i] = SHA-256(node[2i] || node[2i+1])
 * 4. Repeat until single root remains
 */
int ax_merkle_compute_root(
    ax_merkle_ctx_t      *ctx,
    ax_gov_fault_flags_t *faults
) {
    uint8_t level_a[AX_MERKLE_MAX_LEAVES][32];
    uint8_t level_b[AX_MERKLE_MAX_LEAVES][32];
    uint8_t (*current)[32] = level_a;
    uint8_t (*next)[32] = level_b;
    uint8_t (*temp)[32];
    size_t node_count;
    size_t next_count;
    size_t i;

    if (ctx == NULL || faults == NULL) {
        return -1;
    }

    /* Empty tree has zero root */
    if (ctx->leaf_count == 0) {
        memset(ctx->root, 0, 32);
        ctx->root_computed = true;
        return 0;
    }

    /* Single leaf: root = leaf (no re-hash per spec) */
    if (ctx->leaf_count == 1) {
        memcpy(ctx->root, ctx->leaves[0], 32);
        ctx->root_computed = true;
        return 0;
    }

    /*
     * F011 fix: Validate that leaves are in lexicographically sorted order.
     *
     * The Merkle root is defined over a lexicographically sorted input list
     * (SRS-007-SHALL-059). An unsorted input would produce a valid-looking
     * but incorrect root — a silent integrity failure.
     *
     * ax_merkle_add_leaves sorts before inserting, but ax_merkle_add_leaf
     * (single-leaf path) does not enforce ordering. This check catches any
     * unsorted state regardless of how leaves were added.
     */
    for (i = 1; i < ctx->leaf_count; i++) {
        if (memcmp(ctx->leaves[i - 1], ctx->leaves[i], 32) > 0) {
            faults->ordering_fault = 1;
            return -1;
        }
    }

    /* Copy leaves to working buffer */
    for (i = 0; i < ctx->leaf_count; i++) {
        memcpy(current[i], ctx->leaves[i], 32);
    }
    node_count = ctx->leaf_count;

    /* Bottom-up construction */
    while (node_count > 1) {
        next_count = 0;

        /* If odd, duplicate last node */
        if (node_count % 2 == 1) {
            memcpy(current[node_count], current[node_count - 1], 32);
            node_count++;
        }

        /* Pairwise hash */
        for (i = 0; i < node_count; i += 2) {
            hash_pair(current[i], current[i + 1], next[next_count]);
            next_count++;
        }

        /* Swap buffers */
        temp = current;
        current = next;
        next = temp;
        node_count = next_count;
    }

    /* Root is the single remaining node */
    memcpy(ctx->root, current[0], 32);
    ctx->root_computed = true;

    return 0;
}

/**
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 */
int ax_merkle_get_root(
    const ax_merkle_ctx_t *ctx,
    uint8_t                root_out[32],
    ax_gov_fault_flags_t  *faults
) {
    if (ctx == NULL || root_out == NULL || faults == NULL) {
        return -1;
    }

    if (!ctx->root_computed) {
        faults->integrity_fault = 1;
        return -1;
    }

    memcpy(root_out, ctx->root, 32);
    return 0;
}

/**
 * @traceability SRS-007-SHALL-059: Merkle proof generation
 *
 * Generates a proof path from leaf to root. The proof consists of
 * sibling hashes at each level, along with position flags indicating
 * whether the sibling is on the left (true) or right (false).
 */
int ax_merkle_generate_proof(
    const ax_merkle_ctx_t *ctx,
    size_t                 leaf_index,
    ax_merkle_proof_t     *proof,
    ax_gov_fault_flags_t  *faults
) {
    uint8_t level_a[AX_MERKLE_MAX_LEAVES][32];
    uint8_t level_b[AX_MERKLE_MAX_LEAVES][32];
    uint8_t (*current)[32] = level_a;
    uint8_t (*next)[32] = level_b;
    uint8_t (*temp)[32];
    size_t node_count;
    size_t next_count;
    size_t target_index;
    size_t sibling_index;
    size_t i;

    if (ctx == NULL || proof == NULL || faults == NULL) {
        return -1;
    }

    if (!ctx->root_computed) {
        faults->integrity_fault = 1;
        return -1;
    }

    if (leaf_index >= ctx->leaf_count) {
        faults->integrity_fault = 1;
        return -1;
    }

    /* Initialise proof */
    memset(proof, 0, sizeof(ax_merkle_proof_t));
    memcpy(proof->leaf_hash, ctx->leaves[leaf_index], 32);
    proof->leaf_index = leaf_index;
    proof->proof_depth = 0;
    memcpy(proof->root, ctx->root, 32);

    /* Single leaf: empty proof path */
    if (ctx->leaf_count == 1) {
        return 0;
    }

    /* Copy leaves to working buffer */
    for (i = 0; i < ctx->leaf_count; i++) {
        memcpy(current[i], ctx->leaves[i], 32);
    }
    node_count = ctx->leaf_count;
    target_index = leaf_index;

    /* Generate proof path (bottom-up) */
    while (node_count > 1) {
        /* If odd, duplicate last node */
        if (node_count % 2 == 1) {
            memcpy(current[node_count], current[node_count - 1], 32);
            node_count++;
        }

        /* Find sibling */
        if (target_index % 2 == 0) {
            /* Target is left child, sibling is right */
            sibling_index = target_index + 1;
            proof->is_left[proof->proof_depth] = false;  /* Sibling on right */
        } else {
            /* Target is right child, sibling is left */
            sibling_index = target_index - 1;
            proof->is_left[proof->proof_depth] = true;   /* Sibling on left */
        }

        /* Record sibling hash */
        if (proof->proof_depth >= AX_MERKLE_MAX_DEPTH) {
            faults->overflow = 1;
            return -1;
        }
        memcpy(proof->siblings[proof->proof_depth], current[sibling_index], 32);
        proof->proof_depth++;

        /* Compute next level */
        next_count = 0;
        for (i = 0; i < node_count; i += 2) {
            hash_pair(current[i], current[i + 1], next[next_count]);
            next_count++;
        }

        /* Update target index for next level */
        target_index = target_index / 2;

        /* Swap buffers */
        temp = current;
        current = next;
        next = temp;
        node_count = next_count;
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-059: Merkle proof verification
 *
 * Verifies that a leaf is included in the tree with the expected root.
 */
int ax_merkle_verify_proof(
    const ax_merkle_proof_t *proof,
    ax_gov_fault_flags_t    *faults
) {
    uint8_t computed[32];
    size_t i;

    if (proof == NULL || faults == NULL) {
        return -1;
    }

    /* Start with leaf hash */
    memcpy(computed, proof->leaf_hash, 32);

    /* Traverse proof path */
    for (i = 0; i < proof->proof_depth; i++) {
        if (proof->is_left[i]) {
            /* Sibling on left: hash(sibling || current) */
            hash_pair(proof->siblings[i], computed, computed);
        } else {
            /* Sibling on right: hash(current || sibling) */
            hash_pair(computed, proof->siblings[i], computed);
        }
    }

    /* Compare computed root with expected */
    if (memcmp(computed, proof->root, 32) != 0) {
        faults->hash_mismatch = 1;
        return -1;
    }

    return 0;
}

/**
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
int ax_merkle_hash_compare(const uint8_t a[32], const uint8_t b[32]) {
    return memcmp(a, b, 32);
}

/**
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */
void ax_merkle_sort_hashes(
    uint8_t              (*hashes)[32],
    size_t                count,
    ax_gov_fault_flags_t *faults
) {
    size_t i, j;
    uint8_t temp[32];

    (void)faults;  /* Not used but kept for API consistency */

    if (hashes == NULL || count <= 1) {
        return;
    }

    /* Insertion sort (deterministic, bounded O(n²)) */
    for (i = 1; i < count; i++) {
        memcpy(temp, hashes[i], 32);
        j = i;
        while (j > 0 && ax_merkle_hash_compare(hashes[j - 1], temp) > 0) {
            memcpy(hashes[j], hashes[j - 1], 32);
            j--;
        }
        memcpy(hashes[j], temp, 32);
    }
}
