/**
 * @file test_verify.c
 * @brief Cross-Layer Verification Protocol Tests
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 * @license GPL-3.0-or-later
 *
 * @traceability SRS-007-SHALL-011: Verification chain
 * @traceability SRS-007-SHALL-012: L1 substrate certification
 * @traceability SRS-007-SHALL-048: Weight hash specification
 * @traceability SRS-007-SHALL-013: L2 weight binding
 * @traceability SRS-007-SHALL-014: L3 observation integrity
 * @traceability SRS-007-SHALL-008: Policy soundness requirement
 * @traceability SRS-007-SHALL-009: Policy violation
 * @traceability SRS-007-SHALL-010: Policies as programs
 * @traceability SRS-007-SHALL-015: L4 policy soundness
 * @traceability SRS-007-SHALL-016: L3→L4 obs-policy binding
 * @traceability SRS-007-SHALL-017: L4→L5 breach enforcement
 * @traceability SRS-007-SHALL-018: L5→L6 pre-commit ordering
 * @traceability SRS-007-SHALL-019: Full chain replay
 * @traceability SRS-007-SHALL-035: Integrity fault definition
 * @traceability SRS-007-SHALL-047: Proof-before-execution invariant
 * @traceability SRS-007-SHALL-058: Atomicity model (Option A)
 */

#include "ax_governance.h"
#include "ax_verify.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  TEST: %-60s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

/* ============================================================================
 * Fixtures
 * ============================================================================ */

static void make_gov(ax_gov_ctx_t *gov) {
    ax_gov_fault_flags_t faults;
    uint8_t config_hash[32]   = {0xC0, 0xC0};
    uint8_t policy_hash[32];
    uint8_t genesis[32]       = {0xA0};
    memset(policy_hash, 0xAB, 32);
    ax_gov_clear_faults(&faults);
    ax_gov_init(gov, config_hash, policy_hash, genesis, &faults);
}

/** Populate a fully valid verification context */
static void make_valid_ctx(ax_verify_ctx_t *ctx, const ax_gov_ctx_t *gov) {
    memset(ctx, 0, sizeof(ax_verify_ctx_t));
    memcpy(ctx->chain_head, gov->chain_head, 32);
    ctx->chain_ledger_seq = gov->next_proof_seq;

    /* L1 substrate */
    memset(ctx->substrate_cert_hash, 0x11, 32);
    ctx->substrate_cert_present = true;

    /* L2 weight binding — hashes must match */
    memset(ctx->weight_hash, 0x22, 32);
    memset(ctx->model_id_hash, 0x22, 32);
    ctx->weight_binding_present = true;

    /* L3 observation */
    memset(ctx->obs_record_hash, 0x33, 32);
    memset(ctx->obs_hash_field, 0x44, 32);
    ctx->obs_ledger_seq = 10;
    ctx->obs_present = true;

    /* L4 policy */
    memset(ctx->policy_record_hash, 0x55, 32);
    ctx->policy_obs_ledger_seq = 10;   /* matches obs */
    ctx->policy_ledger_seq = 11;
    ctx->policy_result = 0;            /* PERMITTED */
    ctx->policy_present = true;

    /* L5 transition */
    memset(ctx->trans_record_hash, 0x66, 32);
    ctx->trans_ledger_seq = 12;
    ctx->trans_next_state = AX_AGENT_STATE_HEALTHY;
    ctx->trans_present = true;

    /* Replay */
    memcpy(ctx->genesis_state_hash, gov->chain_head, 32);
    memcpy(ctx->expected_replay_hash, gov->chain_head, 32);
    ctx->replay_present = true;
}

/* ============================================================================
 * Governance Init
 * ============================================================================ */

static void test_gov_init(void) {
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t config_hash[32] = {0xC0};
    uint8_t policy_hash[32] = {0xAB};
    uint8_t genesis[32]     = {0xA0};

    TEST("Governance context initialisation");
    ax_gov_clear_faults(&faults);

    if (ax_gov_init(&gov, config_hash, policy_hash, genesis, &faults) != 0) {
        FAIL("init returned error"); return;
    }
    if (ax_gov_has_fault(&faults)) { FAIL("unexpected fault"); return; }
    if (!gov.config.initialised) { FAIL("not marked initialised"); return; }
    if (gov.next_proof_seq != 1) { FAIL("seq not 1"); return; }
    if (gov.agent_state != AX_AGENT_STATE_HEALTHY) { FAIL("not healthy"); return; }
    if (gov.in_fault_mode) { FAIL("in fault mode unexpectedly"); return; }
    PASS();
}

static void test_gov_null_params(void) {
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t h[32] = {0};

    TEST("Governance init rejects NULL params");
    ax_gov_clear_faults(&faults);

    if (ax_gov_init(NULL, h, h, h, &faults) != -1) { FAIL("NULL ctx accepted"); return; }
    if (ax_gov_init(&gov, NULL, h, h, &faults) != -1) { FAIL("NULL config accepted"); return; }
    if (ax_gov_init(&gov, h, NULL, h, &faults) != -1) { FAIL("NULL policy accepted"); return; }
    if (ax_gov_init(&gov, h, h, NULL, &faults) != -1) { FAIL("NULL genesis accepted"); return; }
    PASS();
}

/* ============================================================================
 * Step 1 — Substrate Certification
 * ============================================================================ */

static void test_step1_pass(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 1: substrate cert PASS");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ax_gov_clear_faults(&faults);

    if (ax_verify_substrate_cert(&ctx, &result, &gov, &faults) != 0) {
        FAIL("verify returned error"); return;
    }
    if (!result.passed) { FAIL("result.passed is false"); return; }
    if (result.proof.result != AX_PROOF_RESULT_VALID) { FAIL("proof not VALID"); return; }
    if (result.proof.proof_type != AX_PROOF_TYPE_SUBSTRATE_CERT) { FAIL("wrong type"); return; }
    if (!result.proof.proof_hash_computed) { FAIL("hash not computed"); return; }
    PASS();
}

static void test_step1_missing_evidence(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 1: substrate cert FAIL (missing evidence)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ctx.substrate_cert_present = false;
    ax_gov_clear_faults(&faults);

    if (ax_verify_substrate_cert(&ctx, &result, &gov, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (result.passed) { FAIL("result.passed should be false"); return; }
    if (result.proof.result != AX_PROOF_RESULT_INTEGRITY_FAULT) {
        FAIL("proof not INTEGRITY_FAULT"); return;
    }
    if (result.proof.violation != AX_VIOLATION_EVIDENCE_MISSING) {
        FAIL("wrong violation"); return;
    }
    PASS();
}

/* ============================================================================
 * Step 2 — Weight Binding
 * ============================================================================ */

static void test_step2_pass(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 2: weight binding PASS");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ax_gov_clear_faults(&faults);

    if (ax_verify_weight_binding(&ctx, &result, &gov, &faults) != 0) {
        FAIL("verify returned error"); return;
    }
    if (!result.passed) { FAIL("result.passed is false"); return; }
    if (result.proof.proof_type != AX_PROOF_TYPE_WEIGHT_BINDING) { FAIL("wrong type"); return; }
    PASS();
}

static void test_step2_weight_mismatch(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 2: weight binding FAIL (mismatch)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    /* Deliberately different */
    memset(ctx.weight_hash, 0x22, 32);
    memset(ctx.model_id_hash, 0x99, 32);
    ax_gov_clear_faults(&faults);

    if (ax_verify_weight_binding(&ctx, &result, &gov, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (result.proof.result != AX_PROOF_RESULT_INTEGRITY_FAULT) {
        FAIL("proof not INTEGRITY_FAULT"); return;
    }
    if (result.proof.violation != AX_VIOLATION_WEIGHT_MISMATCH) {
        FAIL("wrong violation"); return;
    }
    if (!faults.weight_mismatch) { FAIL("weight_mismatch fault not set"); return; }
    PASS();
}

/* ============================================================================
 * Step 3 — Observation Integrity
 * ============================================================================ */

static void test_step3_pass(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 3: observation integrity PASS");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ax_gov_clear_faults(&faults);

    if (ax_verify_obs_integrity(&ctx, &result, &gov, &faults) != 0) {
        FAIL("verify returned error"); return;
    }
    if (!result.passed) { FAIL("result.passed is false"); return; }
    PASS();
}

static void test_step3_zero_record_hash(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 3: observation integrity FAIL (zero record hash)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    memset(ctx.obs_record_hash, 0x00, 32);
    ax_gov_clear_faults(&faults);

    if (ax_verify_obs_integrity(&ctx, &result, &gov, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (result.proof.violation != AX_VIOLATION_HASH_MISMATCH) {
        FAIL("wrong violation"); return;
    }
    PASS();
}

/* ============================================================================
 * Step 4 — Policy Soundness
 * ============================================================================ */

static void test_step4_pass(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 4: policy soundness PASS");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ax_gov_clear_faults(&faults);

    if (ax_verify_policy_soundness(&ctx, &result, &gov, &faults) != 0) {
        FAIL("verify returned error"); return;
    }
    if (!result.passed) { FAIL("result.passed is false"); return; }
    if (result.proof.proof_type != AX_PROOF_TYPE_POLICY_SOUNDNESS) { FAIL("wrong type"); return; }
    PASS();
}

static void test_step4_fault_mode(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 4: policy soundness FAIL (governance in fault mode)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    gov.in_fault_mode = true;
    ax_gov_clear_faults(&faults);

    if (ax_verify_policy_soundness(&ctx, &result, &gov, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (result.proof.result != AX_PROOF_RESULT_INTEGRITY_FAULT) {
        FAIL("proof not INTEGRITY_FAULT"); return;
    }
    PASS();
}

/* ============================================================================
 * Step 5 — Obs-Policy Binding
 * ============================================================================ */

static void test_step5_pass(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 5: obs-policy binding PASS");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ax_gov_clear_faults(&faults);

    if (ax_verify_obs_policy_binding(&ctx, &result, &gov, &faults) != 0) {
        FAIL("verify returned error"); return;
    }
    if (!result.passed) { FAIL("result.passed is false"); return; }
    PASS();
}

static void test_step5_binding_broken(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 5: obs-policy binding FAIL (seq mismatch)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ctx.policy_obs_ledger_seq = 999;   /* does not match obs_ledger_seq=10 */
    ax_gov_clear_faults(&faults);

    if (ax_verify_obs_policy_binding(&ctx, &result, &gov, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (result.proof.result != AX_PROOF_RESULT_INTEGRITY_FAULT) {
        FAIL("proof not INTEGRITY_FAULT"); return;
    }
    if (result.proof.violation != AX_VIOLATION_HASH_MISMATCH) {
        FAIL("wrong violation"); return;
    }
    PASS();
}

/* ============================================================================
 * Step 6 — Breach Enforcement
 * ============================================================================ */

static void test_step6_permitted_healthy(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 6: breach enforcement PASS (PERMITTED, HEALTHY)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ctx.policy_result = 0;                        /* PERMITTED */
    ctx.trans_next_state = AX_AGENT_STATE_HEALTHY;
    ax_gov_clear_faults(&faults);

    if (ax_verify_breach_enforcement(&ctx, &result, &gov, &faults) != 0) {
        FAIL("verify returned error"); return;
    }
    if (!result.passed) { FAIL("result.passed is false"); return; }
    PASS();
}

static void test_step6_breach_to_alarm(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 6: breach enforcement PASS (BREACH, ALARM)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ctx.policy_result = 1;                      /* BREACH */
    ctx.trans_next_state = AX_AGENT_STATE_ALARM;
    ax_gov_clear_faults(&faults);

    if (ax_verify_breach_enforcement(&ctx, &result, &gov, &faults) != 0) {
        FAIL("verify returned error"); return;
    }
    if (!result.passed) { FAIL("result.passed is false"); return; }
    PASS();
}

static void test_step6_breach_not_enforced(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 6: breach enforcement FAIL (BREACH, HEALTHY)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ctx.policy_result = 1;                         /* BREACH */
    ctx.trans_next_state = AX_AGENT_STATE_HEALTHY;  /* NOT a safety state */
    ax_gov_clear_faults(&faults);

    if (ax_verify_breach_enforcement(&ctx, &result, &gov, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (result.proof.violation != AX_VIOLATION_TRANSITION_FAULT) {
        FAIL("wrong violation"); return;
    }
    PASS();
}

/* ============================================================================
 * Step 7 — Pre-Commit Ordering
 * ============================================================================ */

static void test_step7_pass(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 7: pre-commit ordering PASS");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);   /* obs=10, policy=11, trans=12 */
    ax_gov_clear_faults(&faults);

    if (ax_verify_precommit_ordering(&ctx, &result, &gov, &faults) != 0) {
        FAIL("verify returned error"); return;
    }
    if (!result.passed) { FAIL("result.passed is false"); return; }
    PASS();
}

static void test_step7_ordering_violated(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 7: pre-commit ordering FAIL (policy before obs)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ctx.policy_ledger_seq = 5;  /* 5 < obs_ledger_seq=10 — violation */
    ax_gov_clear_faults(&faults);

    if (ax_verify_precommit_ordering(&ctx, &result, &gov, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (result.proof.violation != AX_VIOLATION_ORDERING) {
        FAIL("wrong violation"); return;
    }
    if (!faults.ordering_fault) { FAIL("ordering_fault not set"); return; }
    PASS();
}

static void test_step7_trans_before_policy(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 7: pre-commit ordering FAIL (trans before policy)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ctx.trans_ledger_seq = 10;  /* same as obs, before policy=11 */
    ax_gov_clear_faults(&faults);

    if (ax_verify_precommit_ordering(&ctx, &result, &gov, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (result.proof.violation != AX_VIOLATION_ORDERING) {
        FAIL("wrong violation"); return;
    }
    PASS();
}

/* ============================================================================
 * Step 8 — Replay Verification
 * ============================================================================ */

static void test_step8_pass(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 8: replay PASS (expected hash matches chain head)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    /* expected_replay_hash set to gov->chain_head in make_valid_ctx */
    ax_gov_clear_faults(&faults);

    if (ax_verify_replay(&ctx, &result, &gov, &faults) != 0) {
        FAIL("verify returned error"); return;
    }
    if (!result.passed) { FAIL("result.passed is false"); return; }
    if (result.proof.proof_type != AX_PROOF_TYPE_REPLAY_EQUIVALENCE) { FAIL("wrong type"); return; }
    PASS();
}

static void test_step8_replay_mismatch(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;

    TEST("Step 8: replay FAIL (hash mismatch)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    memset(ctx.expected_replay_hash, 0xFF, 32);  /* does not match chain_head */
    ax_gov_clear_faults(&faults);

    if (ax_verify_replay(&ctx, &result, &gov, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (result.proof.violation != AX_VIOLATION_REPLAY_MISMATCH) {
        FAIL("wrong violation"); return;
    }
    PASS();
}

/* ============================================================================
 * Full Chain — ax_verify_all
 * ============================================================================ */

static void test_verify_all_pass(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t results[8];
    ax_gov_fault_flags_t faults;
    int steps_completed = 0;

    TEST("ax_verify_all: all 8 steps PASS");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ax_gov_clear_faults(&faults);

    if (ax_verify_all(&ctx, results, &gov, &steps_completed, &faults) != 0) {
        FAIL("verify_all returned error"); return;
    }
    if (steps_completed != 8) {
        printf("FAIL: steps_completed=%d (expected 8)\n", steps_completed);
        tests_failed++;
        return;
    }
    /* All proofs must be VALID */
    {
        int i;
        for (i = 0; i < 8; i++) {
            if (results[i].proof.result != AX_PROOF_RESULT_VALID) {
                printf("FAIL: step %d proof not VALID\n", i + 1);
                tests_failed++;
                return;
            }
        }
    }
    /* Governance sequence advanced by 8 */
    if (gov.next_proof_seq != 9) {
        printf("FAIL: next_proof_seq=%llu (expected 9)\n",
               (unsigned long long)gov.next_proof_seq);
        tests_failed++;
        return;
    }
    PASS();
}

static void test_verify_all_stops_at_fault(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t results[8];
    ax_gov_fault_flags_t faults;
    int steps_completed = 0;

    TEST("ax_verify_all: stops at step 2 (weight mismatch)");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    memset(ctx.model_id_hash, 0xFF, 32);  /* mismatch at step 2 */
    ax_gov_clear_faults(&faults);

    if (ax_verify_all(&ctx, results, &gov, &steps_completed, &faults) != -1) {
        FAIL("should have failed"); return;
    }
    if (steps_completed != 2) {
        printf("FAIL: steps_completed=%d (expected 2)\n", steps_completed);
        tests_failed++;
        return;
    }
    /* Step 1 passed, step 2 has integrity fault */
    if (results[0].proof.result != AX_PROOF_RESULT_VALID) {
        FAIL("step 1 should be VALID"); return;
    }
    if (results[1].proof.result != AX_PROOF_RESULT_INTEGRITY_FAULT) {
        FAIL("step 2 should be INTEGRITY_FAULT"); return;
    }
    PASS();
}

/* ============================================================================
 * Proof-Before-Execution Invariant
 * ============================================================================ */

static void test_proof_seq_advances(void) {
    ax_gov_ctx_t gov;
    ax_verify_ctx_t ctx;
    ax_verify_result_t result;
    ax_gov_fault_flags_t faults;
    uint64_t seq_before;

    TEST("Proof-before-execution: seq advances after each step");
    make_gov(&gov);
    make_valid_ctx(&ctx, &gov);
    ax_gov_clear_faults(&faults);

    seq_before = gov.next_proof_seq;

    ax_verify_substrate_cert(&ctx, &result, &gov, &faults);

    /* ledger_seq in proof must equal seq_before */
    if (result.proof.ledger_seq != seq_before) {
        printf("FAIL: proof.ledger_seq=%llu (expected %llu)\n",
               (unsigned long long)result.proof.ledger_seq,
               (unsigned long long)seq_before);
        tests_failed++;
        return;
    }
    /* governance seq must have advanced */
    if (gov.next_proof_seq != seq_before + 1) {
        FAIL("next_proof_seq did not advance"); return;
    }
    PASS();
}

/* ============================================================================
 * Governance Context Operations
 * ============================================================================ */

static void test_fault_mode_entry(void) {
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;

    TEST("ax_gov_enter_fault_mode: transitions to STOPPED");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);

    ax_gov_enter_fault_mode(&gov, AX_VIOLATION_WEIGHT_MISMATCH, &faults);

    if (!gov.in_fault_mode) { FAIL("not in fault mode"); return; }
    if (gov.agent_state != AX_AGENT_STATE_STOPPED) { FAIL("not STOPPED"); return; }
    if (!faults.weight_mismatch) { FAIL("weight_mismatch flag not set"); return; }
    PASS();
}

static void test_chain_head_update(void) {
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t new_head[32];

    TEST("ax_gov_update_chain_head: chain head updated");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);
    memset(new_head, 0xBB, 32);

    ax_gov_update_chain_head(&gov, new_head, &faults);

    if (memcmp(gov.chain_head, new_head, 32) != 0) {
        FAIL("chain head not updated"); return;
    }
    PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("\n=== axioma-governance: Cross-Layer Verification Tests ===\n\n");

    printf("Governance Context:\n");
    test_gov_init();
    test_gov_null_params();

    printf("\nStep 1 — Substrate Certification:\n");
    test_step1_pass();
    test_step1_missing_evidence();

    printf("\nStep 2 — Weight Binding:\n");
    test_step2_pass();
    test_step2_weight_mismatch();

    printf("\nStep 3 — Observation Integrity:\n");
    test_step3_pass();
    test_step3_zero_record_hash();

    printf("\nStep 4 — Policy Soundness:\n");
    test_step4_pass();
    test_step4_fault_mode();

    printf("\nStep 5 — Obs-Policy Binding:\n");
    test_step5_pass();
    test_step5_binding_broken();

    printf("\nStep 6 — Breach Enforcement:\n");
    test_step6_permitted_healthy();
    test_step6_breach_to_alarm();
    test_step6_breach_not_enforced();

    printf("\nStep 7 — Pre-Commit Ordering:\n");
    test_step7_pass();
    test_step7_ordering_violated();
    test_step7_trans_before_policy();

    printf("\nStep 8 — Replay Verification:\n");
    test_step8_pass();
    test_step8_replay_mismatch();

    printf("\nFull Chain:\n");
    test_verify_all_pass();
    test_verify_all_stops_at_fault();

    printf("\nInvariants:\n");
    test_proof_seq_advances();
    test_fault_mode_entry();
    test_chain_head_update();

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
