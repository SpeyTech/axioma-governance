/**
 * @file test_proof.c
 * @brief AX:PROOF:v1 Record Tests
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 * @license GPL-3.0-or-later
 *
 * @traceability SRS-007-SHALL-003: Proof commitment
 * @traceability SRS-007-SHALL-004: AX:PROOF:v1 required fields
 * @traceability SRS-007-SHALL-005: Proof type closed set
 * @traceability SRS-007-SHALL-006: Evidence reference requirement
 * @traceability SRS-007-SHALL-007: Canonical format
 * @traceability SRS-007-SHALL-040: Test traceability
 * @traceability SRS-007-SHALL-043: Buffer overflow prevention
 * @traceability SRS-007-SHALL-045: proof_hash OMITTED during computation
 * @traceability SRS-007-SHALL-055: Schema version field
 * @traceability SRS-007-SHALL-056: Proof type string encoding
 * @traceability SRS-007-SHALL-057: Evidence ordering mode
 */

#include "ax_governance.h"
#include "ax_proof.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_proof_init(void) {
    ax_proof_record_t record;
    ax_gov_fault_flags_t faults;
    uint8_t prev_head[32] = {0};
    TEST("Proof init");
    ax_gov_clear_faults(&faults);
    if (ax_proof_init(&record, "Test claim", AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
                      "SRS-007-SHALL-001", prev_head, 100, &faults) != 0) {
        FAIL("init failed"); return;
    }
    if (ax_gov_has_fault(&faults)) { FAIL("unexpected fault"); return; }
    if (strcmp(record.claim, "Test claim") != 0) { FAIL("claim mismatch"); return; }
    if (record.proof_type != AX_PROOF_TYPE_CROSS_LAYER_VERIFY) { FAIL("type mismatch"); return; }
    PASS();
}

static void test_proof_type_closed_set(void) {
    TEST("Proof type closed set");
    if (!ax_proof_type_valid(AX_PROOF_TYPE_ANCHOR_PUBLICATION)) { FAIL("ANCHOR invalid"); return; }
    if (!ax_proof_type_valid(AX_PROOF_TYPE_WEIGHT_BINDING)) { FAIL("WEIGHT invalid"); return; }
    if (ax_proof_type_valid((ax_proof_type_t)99)) { FAIL("99 should be invalid"); return; }
    PASS();
}

static void test_evidence_addition(void) {
    ax_proof_record_t record;
    ax_gov_fault_flags_t faults;
    uint8_t prev_head[32] = {0};
    uint8_t evidence[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    TEST("Evidence addition");
    ax_gov_clear_faults(&faults);
    ax_proof_init(&record, "Test", AX_PROOF_TYPE_POLICY_SOUNDNESS, "RULE-001", prev_head, 1, &faults);
    if (ax_proof_add_evidence(&record, evidence, &faults) != 0) { FAIL("add failed"); return; }
    if (record.evidence_refs_count != 1) { FAIL("count != 1"); return; }
    if (memcmp(record.evidence_refs[0], evidence, 32) != 0) { FAIL("hash mismatch"); return; }
    PASS();
}

static void test_proof_hash(void) {
    ax_proof_record_t record;
    ax_gov_fault_flags_t faults;
    uint8_t prev_head[32] = {0};
    uint8_t evidence[32] = {0x01, 0x02, 0x03};
    TEST("Proof hash computation");
    ax_gov_clear_faults(&faults);
    ax_proof_init(&record, "Test claim", AX_PROOF_TYPE_POLICY_SOUNDNESS, "RULE-001", prev_head, 1, &faults);
    ax_proof_add_evidence(&record, evidence, &faults);
    if (ax_proof_compute_hash(&record, &faults) != 0) { FAIL("hash failed"); return; }
    if (!record.proof_hash_computed) { FAIL("flag not set"); return; }
    bool all_zero = true;
    for (int i = 0; i < 32; i++) if (record.proof_hash[i] != 0) { all_zero = false; break; }
    if (all_zero) { FAIL("hash all zeros"); return; }
    PASS();
}

static void test_proof_finalise(void) {
    ax_proof_record_t record;
    ax_gov_fault_flags_t faults;
    uint8_t prev_head[32] = {0};
    uint8_t evidence[32] = {0x01, 0x02, 0x03};
    TEST("Proof finalise");
    ax_gov_clear_faults(&faults);
    ax_proof_init(&record, "Test claim", AX_PROOF_TYPE_POLICY_SOUNDNESS, "RULE-001", prev_head, 1, &faults);
    ax_proof_add_evidence(&record, evidence, &faults);
    if (ax_proof_finalise(&record, &faults) != 0) { FAIL("finalise failed"); return; }
    if (!record.proof_hash_computed) { FAIL("hash not computed"); return; }
    PASS();
}

static void test_determinism(void) {
    ax_proof_record_t r1, r2;
    ax_gov_fault_flags_t faults;
    uint8_t prev_head[32] = {0xAA, 0xBB, 0xCC};
    uint8_t e1[32] = {1,2,3}, e2[32] = {4,5,6};
    TEST("Proof determinism");
    ax_gov_clear_faults(&faults);
    ax_proof_init(&r1, "Deterministic", AX_PROOF_TYPE_CROSS_LAYER_VERIFY, "SRS-001", prev_head, 42, &faults);
    ax_proof_add_evidence(&r1, e1, &faults);
    ax_proof_add_evidence(&r1, e2, &faults);
    ax_proof_finalise(&r1, &faults);
    ax_gov_clear_faults(&faults);
    ax_proof_init(&r2, "Deterministic", AX_PROOF_TYPE_CROSS_LAYER_VERIFY, "SRS-001", prev_head, 42, &faults);
    ax_proof_add_evidence(&r2, e1, &faults);
    ax_proof_add_evidence(&r2, e2, &faults);
    ax_proof_finalise(&r2, &faults);
    if (memcmp(r1.proof_hash, r2.proof_hash, 32) != 0) { FAIL("hashes differ"); return; }
    if (memcmp(r1.commitment, r2.commitment, 32) != 0) { FAIL("commitments differ"); return; }
    PASS();
}

int main(void) {
    printf("\n================================================================================\n");
    printf("  axioma-governance: Proof Record Tests\n");
    printf("================================================================================\n\n");
    test_proof_init();
    test_proof_type_closed_set();
    test_evidence_addition();
    test_proof_hash();
    test_proof_finalise();
    test_determinism();
    printf("\n================================================================================\n");
    printf("  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("================================================================================\n\n");
    return tests_failed > 0 ? 1 : 0;
}
