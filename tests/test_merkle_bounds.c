/**
 * @file test_merkle_bounds.c
 * @brief Regression tests for proof_depth bounds in ax_merkle_verify_proof
 *
 * Finding D-03: proof_depth is caller-supplied and was used to index
 * siblings[20] / is_left[20] without a bound (UBSan from depth 21, ASan
 * heap overflow from depth 23, segfault at very large depths). These tests
 * fail on 93d75a6 under -fsanitize=address,undefined and pass with the fix.
 *
 * Scope: memory safety only. The v1 construction's soundness defects
 * (SRS-007-AMD-001) are deliberately not addressed here.
 *
 * @copyright Copyright (C) 2026 Spey Systems LTD.
 * @license AGPL-3.0-or-later
 *
 * @traceability SRS-007-SHALL-043: Buffer overflow prevention
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 */

#include "ax_governance.h"
#include "ax_merkle.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

/* Heap-allocate exactly one proof so an out-of-bounds read past the struct
 * is visible to ASan, as in the original reproduction. */
static int verify_with_depth(size_t depth, ax_gov_fault_flags_t *faults)
{
    ax_merkle_proof_t *p = calloc(1, sizeof(*p));
    int rc;

    if (p == NULL) {
        return -2;
    }
    p->proof_depth = depth;
    ax_gov_clear_faults(faults);
    rc = ax_merkle_verify_proof(p, faults);
    free(p);
    return rc;
}

static void test_depth_above_capacity_rejected(void)
{
    const size_t depths[] = { AX_MERKLE_MAX_DEPTH + 1, AX_MERKLE_MAX_DEPTH + 3,
                              1000000u, SIZE_MAX };
    ax_gov_fault_flags_t faults;
    size_t i;

    TEST("proof_depth above AX_MERKLE_MAX_DEPTH rejected with overflow fault");
    for (i = 0; i < sizeof(depths) / sizeof(depths[0]); i++) {
        if (verify_with_depth(depths[i], &faults) != -1 || !faults.overflow) {
            FAIL("oversized depth not rejected");
            return;
        }
    }
    PASS();
}

static void test_depth_at_capacity_in_bounds(void)
{
    ax_gov_fault_flags_t faults;

    TEST("proof_depth == AX_MERKLE_MAX_DEPTH is processed in bounds");
    /* All-zero proof: verdict is a mismatch, but no overflow fault and no
     * out-of-bounds access (checked by the sanitizer build). */
    if (verify_with_depth(AX_MERKLE_MAX_DEPTH, &faults) != -1 || faults.overflow) {
        FAIL("in-bounds depth mishandled");
        return;
    }
    PASS();
}

static void test_generated_proofs_still_verify(void)
{
    static ax_merkle_ctx_t ctx;
    static uint8_t leaves[AX_MERKLE_MAX_LEAVES][32];
    ax_merkle_proof_t proof;
    ax_gov_fault_flags_t faults;
    const size_t sizes[] = { 1, 2, 3, 5, 8, 33, 257, AX_MERKLE_MAX_LEAVES };
    size_t si, i, m;

    TEST("generated proofs for 1..1024 leaves still verify");
    for (i = 0; i < AX_MERKLE_MAX_LEAVES; i++) {
        memset(leaves[i], 0, 32);
        leaves[i][0] = (uint8_t)(i >> 8);
        leaves[i][1] = (uint8_t)i;
        leaves[i][31] = 0xA5;
    }
    for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        ax_gov_clear_faults(&faults);
        ax_merkle_init(&ctx, &faults);
        if (ax_merkle_add_leaves(&ctx, (const uint8_t (*)[32])leaves, sizes[si], &faults) != 0 ||
            ax_merkle_compute_root(&ctx, &faults) != 0) {
            FAIL("tree construction failed");
            return;
        }
        for (m = 0; m < sizes[si]; m += (sizes[si] > 64 ? 61 : 1)) {
            ax_gov_clear_faults(&faults);
            if (ax_merkle_generate_proof(&ctx, m, &proof, &faults) != 0 ||
                ax_merkle_verify_proof(&proof, &faults) != 0) {
                FAIL("valid proof rejected");
                return;
            }
        }
    }
    PASS();
}

int main(void)
{
    printf("\n=== Merkle proof bounds (D-03) ===\n");
    test_depth_above_capacity_rejected();
    test_depth_at_capacity_in_bounds();
    test_generated_proofs_still_verify();
    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_passed + tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
