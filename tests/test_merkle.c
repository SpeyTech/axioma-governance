/**
 * @file test_merkle.c
 * @brief Evidence Closure Merkle Tree Tests
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 * @license GPL-3.0-or-later
 *
 * @traceability SRS-007-SHALL-001: Cross-platform bit-identical execution
 * @traceability SRS-007-SHALL-040: Test traceability
 * @traceability SRS-007-SHALL-042: Bounded memory allocation
 * @traceability SRS-007-SHALL-043: Buffer overflow prevention
 * @traceability SRS-007-SHALL-051: Evidence closure proof
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */

#include "ax_governance.h"
#include "ax_merkle.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_merkle_init(void) {
    ax_merkle_ctx_t ctx;
    ax_gov_fault_flags_t faults;
    TEST("Merkle init");
    ax_gov_clear_faults(&faults);
    ax_merkle_init(&ctx, &faults);  /* void return */
    if (ctx.leaf_count != 0) { FAIL("leaf_count != 0"); return; }
    if (ctx.root_computed) { FAIL("root_computed should be false"); return; }
    PASS();
}

static void test_single_leaf(void) {
    ax_merkle_ctx_t ctx;
    ax_gov_fault_flags_t faults;
    uint8_t leaf[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    uint8_t root[32];
    TEST("Single leaf (root = leaf)");
    ax_gov_clear_faults(&faults);
    ax_merkle_init(&ctx, &faults);
    if (ax_merkle_add_leaf(&ctx, leaf, &faults) != 0) { FAIL("add_leaf failed"); return; }
    if (ax_merkle_compute_root(&ctx, &faults) != 0) { FAIL("compute_root failed"); return; }
    if (ax_merkle_get_root(&ctx, root, &faults) != 0) { FAIL("get_root failed"); return; }
    /* Single leaf: root equals leaf (no re-hash per spec) */
    if (memcmp(root, leaf, 32) != 0) { FAIL("root != leaf"); return; }
    PASS();
}

static void test_two_leaves(void) {
    ax_merkle_ctx_t ctx;
    ax_gov_fault_flags_t faults;
    uint8_t l1[32] = {0}; l1[0] = 0x01;
    uint8_t l2[32] = {0}; l2[0] = 0x02;
    uint8_t root[32];
    TEST("Two leaves");
    ax_gov_clear_faults(&faults);
    ax_merkle_init(&ctx, &faults);
    ax_merkle_add_leaf(&ctx, l1, &faults);
    ax_merkle_add_leaf(&ctx, l2, &faults);
    ax_merkle_compute_root(&ctx, &faults);
    ax_merkle_get_root(&ctx, root, &faults);
    /* Root should be SHA-256(l1 || l2), definitely not all zeros */
    bool all_zero = true;
    for (int i = 0; i < 32; i++) if (root[i] != 0) { all_zero = false; break; }
    if (all_zero) { FAIL("root all zeros"); return; }
    PASS();
}

static void test_four_leaves(void) {
    ax_merkle_ctx_t ctx;
    ax_gov_fault_flags_t faults;
    uint8_t leaves[4][32];
    uint8_t root[32];
    TEST("Four leaves");
    for (int i = 0; i < 4; i++) {
        memset(leaves[i], 0, 32);
        leaves[i][0] = (uint8_t)(i + 1);
    }
    ax_gov_clear_faults(&faults);
    ax_merkle_init(&ctx, &faults);
    for (int i = 0; i < 4; i++) {
        ax_merkle_add_leaf(&ctx, leaves[i], &faults);
    }
    ax_merkle_compute_root(&ctx, &faults);
    ax_merkle_get_root(&ctx, root, &faults);
    bool all_zero = true;
    for (int i = 0; i < 32; i++) if (root[i] != 0) { all_zero = false; break; }
    if (all_zero) { FAIL("root all zeros"); return; }
    PASS();
}

static void test_proof_generation(void) {
    ax_merkle_ctx_t ctx;
    ax_merkle_proof_t proof;
    ax_gov_fault_flags_t faults;
    uint8_t leaves[4][32];
    TEST("Proof generation");
    for (int i = 0; i < 4; i++) {
        memset(leaves[i], 0, 32);
        leaves[i][0] = (uint8_t)(i + 1);
    }
    ax_gov_clear_faults(&faults);
    ax_merkle_init(&ctx, &faults);
    for (int i = 0; i < 4; i++) ax_merkle_add_leaf(&ctx, leaves[i], &faults);
    ax_merkle_compute_root(&ctx, &faults);
    /* Generate proof for leaf 0 */
    if (ax_merkle_generate_proof(&ctx, 0, &proof, &faults) != 0) { FAIL("generate failed"); return; }
    if (memcmp(proof.leaf_hash, leaves[0], 32) != 0) { FAIL("leaf_hash mismatch"); return; }
    if (proof.leaf_index != 0) { FAIL("leaf_index != 0"); return; }
    /* For 4 leaves, proof_depth should be 2 */
    if (proof.proof_depth != 2) { FAIL("proof_depth != 2"); return; }
    PASS();
}

static void test_proof_verification(void) {
    ax_merkle_ctx_t ctx;
    ax_merkle_proof_t proof;
    ax_gov_fault_flags_t faults;
    uint8_t leaves[4][32];
    TEST("Proof verification");
    for (int i = 0; i < 4; i++) {
        memset(leaves[i], 0, 32);
        leaves[i][0] = (uint8_t)(i + 1);
    }
    ax_gov_clear_faults(&faults);
    ax_merkle_init(&ctx, &faults);
    for (int i = 0; i < 4; i++) ax_merkle_add_leaf(&ctx, leaves[i], &faults);
    ax_merkle_compute_root(&ctx, &faults);
    /* Generate and verify proof for each leaf */
    for (size_t i = 0; i < 4; i++) {
        ax_gov_clear_faults(&faults);
        if (ax_merkle_generate_proof(&ctx, i, &proof, &faults) != 0) {
            FAIL("generate failed"); return;
        }
        ax_gov_clear_faults(&faults);
        /* ax_merkle_verify_proof takes (proof, faults) - root is inside proof */
        if (ax_merkle_verify_proof(&proof, &faults) != 0) {
            FAIL("verify failed"); return;
        }
    }
    PASS();
}

static void test_invalid_proof(void) {
    ax_merkle_ctx_t ctx;
    ax_merkle_proof_t proof;
    ax_gov_fault_flags_t faults;
    uint8_t leaves[4][32];
    TEST("Invalid proof detection");
    for (int i = 0; i < 4; i++) {
        memset(leaves[i], 0, 32);
        leaves[i][0] = (uint8_t)(i + 1);
    }
    ax_gov_clear_faults(&faults);
    ax_merkle_init(&ctx, &faults);
    for (int i = 0; i < 4; i++) ax_merkle_add_leaf(&ctx, leaves[i], &faults);
    ax_merkle_compute_root(&ctx, &faults);
    ax_merkle_generate_proof(&ctx, 0, &proof, &faults);
    /* Corrupt the proof */
    proof.siblings[0][0] ^= 0xFF;
    ax_gov_clear_faults(&faults);
    if (ax_merkle_verify_proof(&proof, &faults) == 0) {
        FAIL("corrupted proof should fail"); return;
    }
    if (!faults.hash_mismatch) { FAIL("hash_mismatch not set"); return; }
    PASS();
}

static void test_determinism(void) {
    ax_merkle_ctx_t ctx1, ctx2;
    ax_gov_fault_flags_t faults;
    uint8_t leaves[8][32];
    uint8_t root1[32], root2[32];
    TEST("Merkle determinism");
    for (int i = 0; i < 8; i++) {
        memset(leaves[i], 0, 32);
        leaves[i][0] = (uint8_t)(i * 10);
    }
    ax_gov_clear_faults(&faults);
    ax_merkle_init(&ctx1, &faults);
    for (int i = 0; i < 8; i++) ax_merkle_add_leaf(&ctx1, leaves[i], &faults);
    ax_merkle_compute_root(&ctx1, &faults);
    ax_merkle_get_root(&ctx1, root1, &faults);
    ax_gov_clear_faults(&faults);
    ax_merkle_init(&ctx2, &faults);
    for (int i = 0; i < 8; i++) ax_merkle_add_leaf(&ctx2, leaves[i], &faults);
    ax_merkle_compute_root(&ctx2, &faults);
    ax_merkle_get_root(&ctx2, root2, &faults);
    if (memcmp(root1, root2, 32) != 0) { FAIL("roots differ"); return; }
    PASS();
}

static void test_hash_sort(void) {
    ax_gov_fault_flags_t faults;
    uint8_t hashes[3][32];
    TEST("Hash sorting");
    /* Create hashes out of order: 0xFF, 0x00, 0x80 */
    memset(hashes[0], 0, 32); hashes[0][0] = 0xFF;
    memset(hashes[1], 0, 32); hashes[1][0] = 0x00;
    memset(hashes[2], 0, 32); hashes[2][0] = 0x80;
    ax_gov_clear_faults(&faults);
    ax_merkle_sort_hashes(hashes, 3, &faults);
    /* Should be sorted: 0x00, 0x80, 0xFF */
    if (hashes[0][0] != 0x00) { FAIL("first != 0x00"); return; }
    if (hashes[1][0] != 0x80) { FAIL("second != 0x80"); return; }
    if (hashes[2][0] != 0xFF) { FAIL("third != 0xFF"); return; }
    PASS();
}

int main(void) {
    printf("\n================================================================================\n");
    printf("  axioma-governance: Merkle Tree Tests\n");
    printf("================================================================================\n\n");
    test_merkle_init();
    test_single_leaf();
    test_two_leaves();
    test_four_leaves();
    test_proof_generation();
    test_proof_verification();
    test_invalid_proof();
    test_determinism();
    test_hash_sort();
    printf("\n================================================================================\n");
    printf("  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("================================================================================\n\n");
    return tests_failed > 0 ? 1 : 0;
}
