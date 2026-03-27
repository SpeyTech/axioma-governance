/**
 * @file test_trace.c
 * @brief Mathematical Trace Tests
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 * @license GPL-3.0-or-later
 *
 * @traceability SRS-007-SHALL-020: Mathematical trace structure
 * @traceability SRS-007-SHALL-021: Trace required fields
 * @traceability SRS-007-SHALL-022: Trace canonicality
 * @traceability SRS-007-SHALL-040: Test traceability
 * @traceability SRS-007-SHALL-043: Buffer overflow prevention
 * @traceability SRS-007-SHALL-049: Trace array ordering
 * @traceability SRS-007-SHALL-050: trace_hash OMITTED during computation
 */

#include "ax_governance.h"
#include "ax_trace.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_trace_init(void) {
    ax_math_trace_t trace;
    ax_gov_fault_flags_t faults;
    uint8_t obs_hash[32] = {1,2,3};
    uint8_t weight_hash[32] = {4,5,6};
    TEST("Trace init");
    ax_gov_clear_faults(&faults);
    if (ax_trace_init(&trace, obs_hash, 100, weight_hash, &faults) != 0) { FAIL("init failed"); return; }
    if (ax_gov_has_fault(&faults)) { FAIL("unexpected fault"); return; }
    if (memcmp(trace.obs_hash, obs_hash, 32) != 0) { FAIL("obs_hash mismatch"); return; }
    if (trace.obs_ledger_seq != 100) { FAIL("obs_ledger_seq mismatch"); return; }
    if (memcmp(trace.weight_hash, weight_hash, 32) != 0) { FAIL("weight_hash mismatch"); return; }
    if (trace.policy_results_count != 0) { FAIL("policy count != 0"); return; }
    PASS();
}

static void test_policy_addition(void) {
    ax_math_trace_t trace;
    ax_gov_fault_flags_t faults;
    uint8_t obs_hash[32] = {1};
    uint8_t weight_hash[32] = {2};
    TEST("Policy addition");
    ax_gov_clear_faults(&faults);
    ax_trace_init(&trace, obs_hash, 100, weight_hash, &faults);
    /* Valid: policy after observation */
    if (ax_trace_add_policy(&trace, 101, AX_POLICY_RESULT_PERMITTED, &faults) != 0) { FAIL("add policy failed"); return; }
    /* Valid: second policy after first */
    if (ax_trace_add_policy(&trace, 102, AX_POLICY_RESULT_BREACH, &faults) != 0) { FAIL("add policy 2 failed"); return; }
    if (trace.policy_results_count != 2) { FAIL("count != 2"); return; }
    if (trace.policy_seqs_count != 2) { FAIL("seqs count != 2"); return; }
    PASS();
}

static void test_policy_ordering(void) {
    ax_math_trace_t trace;
    ax_gov_fault_flags_t faults;
    uint8_t obs_hash[32] = {1};
    uint8_t weight_hash[32] = {2};
    TEST("Policy ordering constraints");
    /* Invalid: policy before observation */
    ax_gov_clear_faults(&faults);
    ax_trace_init(&trace, obs_hash, 100, weight_hash, &faults);
    if (ax_trace_add_policy(&trace, 50, AX_POLICY_RESULT_PERMITTED, &faults) == 0) { FAIL("before obs should fail"); return; }
    if (!faults.ordering_fault) { FAIL("ordering_fault not set"); return; }
    /* Invalid: non-monotonic */
    ax_gov_clear_faults(&faults);
    ax_trace_init(&trace, obs_hash, 100, weight_hash, &faults);
    ax_trace_add_policy(&trace, 110, AX_POLICY_RESULT_PERMITTED, &faults);
    if (ax_trace_add_policy(&trace, 105, AX_POLICY_RESULT_PERMITTED, &faults) == 0) { FAIL("non-monotonic should fail"); return; }
    if (!faults.ordering_fault) { FAIL("ordering_fault not set 2"); return; }
    PASS();
}

static void test_trace_hash(void) {
    ax_math_trace_t trace;
    ax_gov_fault_flags_t faults;
    uint8_t obs_hash[32] = {1};
    uint8_t weight_hash[32] = {2};
    uint8_t chain_head[32] = {3};
    TEST("Trace hash computation");
    ax_gov_clear_faults(&faults);
    ax_trace_init(&trace, obs_hash, 100, weight_hash, &faults);
    ax_trace_add_policy(&trace, 101, AX_POLICY_RESULT_PERMITTED, &faults);
    ax_trace_set_transition(&trace, 102, AX_AGENT_STATE_HEALTHY, &faults);
    ax_trace_set_chain_head(&trace, chain_head, &faults);
    ax_trace_set_proof_seq(&trace, 103, &faults);
    if (ax_trace_compute_hash(&trace, &faults) != 0) { FAIL("hash failed"); return; }
    if (!trace.trace_hash_computed) { FAIL("flag not set"); return; }
    bool all_zero = true;
    for (int i = 0; i < 32; i++) if (trace.trace_hash[i] != 0) { all_zero = false; break; }
    if (all_zero) { FAIL("hash all zeros"); return; }
    PASS();
}

static void test_trace_finalise(void) {
    ax_math_trace_t trace;
    ax_gov_fault_flags_t faults;
    uint8_t obs_hash[32] = {1};
    uint8_t weight_hash[32] = {2};
    uint8_t chain_head[32] = {3};
    TEST("Trace finalise");
    ax_gov_clear_faults(&faults);
    ax_trace_init(&trace, obs_hash, 100, weight_hash, &faults);
    ax_trace_add_policy(&trace, 101, AX_POLICY_RESULT_PERMITTED, &faults);
    ax_trace_set_transition(&trace, 102, AX_AGENT_STATE_HEALTHY, &faults);
    ax_trace_set_chain_head(&trace, chain_head, &faults);
    ax_trace_set_proof_seq(&trace, 103, &faults);
    if (ax_trace_finalise(&trace, &faults) != 0) { FAIL("finalise failed"); return; }
    if (!trace.trace_hash_computed) { FAIL("hash not computed"); return; }
    PASS();
}

static void test_determinism(void) {
    ax_math_trace_t t1, t2;
    ax_gov_fault_flags_t faults;
    uint8_t obs_hash[32] = {0xAA, 0xBB};
    uint8_t weight_hash[32] = {0xCC, 0xDD};
    uint8_t chain_head[32] = {0xEE, 0xFF};
    TEST("Trace determinism");
    ax_gov_clear_faults(&faults);
    ax_trace_init(&t1, obs_hash, 100, weight_hash, &faults);
    ax_trace_add_policy(&t1, 101, AX_POLICY_RESULT_PERMITTED, &faults);
    ax_trace_add_policy(&t1, 102, AX_POLICY_RESULT_BREACH, &faults);
    ax_trace_set_transition(&t1, 103, AX_AGENT_STATE_HEALTHY, &faults);
    ax_trace_set_chain_head(&t1, chain_head, &faults);
    ax_trace_set_proof_seq(&t1, 104, &faults);
    ax_trace_finalise(&t1, &faults);
    ax_gov_clear_faults(&faults);
    ax_trace_init(&t2, obs_hash, 100, weight_hash, &faults);
    ax_trace_add_policy(&t2, 101, AX_POLICY_RESULT_PERMITTED, &faults);
    ax_trace_add_policy(&t2, 102, AX_POLICY_RESULT_BREACH, &faults);
    ax_trace_set_transition(&t2, 103, AX_AGENT_STATE_HEALTHY, &faults);
    ax_trace_set_chain_head(&t2, chain_head, &faults);
    ax_trace_set_proof_seq(&t2, 104, &faults);
    ax_trace_finalise(&t2, &faults);
    if (memcmp(t1.trace_hash, t2.trace_hash, 32) != 0) { FAIL("hashes differ"); return; }
    PASS();
}

int main(void) {
    printf("\n================================================================================\n");
    printf("  axioma-governance: Mathematical Trace Tests\n");
    printf("================================================================================\n\n");
    test_trace_init();
    test_policy_addition();
    test_policy_ordering();
    test_trace_hash();
    test_trace_finalise();
    test_determinism();
    printf("\n================================================================================\n");
    printf("  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("================================================================================\n\n");
    return tests_failed > 0 ? 1 : 0;
}
