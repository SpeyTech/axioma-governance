/**
 * @file test_anchor.c
 * @brief External Anchor Publication Tests
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 * @license GPL-3.0-or-later
 *
 * @traceability SRS-007-SHALL-029: Anchor requirement
 * @traceability SRS-007-SHALL-030: Anchor computation
 * @traceability SRS-007-SHALL-032: Anchor commitment
 * @traceability SRS-007-SHALL-033: Anchor interval declaration
 * @traceability SRS-007-SHALL-034: Anchor verification
 * @traceability SRS-007-SHALL-052: Anchor time as oracle
 * @traceability SRS-007-SHALL-031: Anchor signing (GPG determinism boundary verified by SHALL-060)
 * @traceability SRS-007-SHALL-023: Track A evidence package
 * @traceability SRS-007-SHALL-024: Track B evidence package
 * @traceability SRS-007-SHALL-025: Report trigger conditions
 * @traceability SRS-007-SHALL-026: Report canonical format
 * @traceability SRS-007-SHALL-027: Report independence
 * @traceability SRS-007-SHALL-028: Golden reference inclusion
 * @traceability SRS-007-SHALL-060: GPG determinism boundary
 */

#include "ax_governance.h"
#include "ax_anchor.h"
#include "ax_compliance.h"
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
    uint8_t config_hash[32];
    uint8_t policy_hash[32];
    uint8_t genesis[32];
    memset(config_hash, 0xC0, 32);
    memset(policy_hash, 0xAB, 32);
    memset(genesis, 0xA0, 32);
    ax_gov_clear_faults(&faults);
    ax_gov_init(gov, config_hash, policy_hash, genesis, &faults);
}

/* ============================================================================
 * Anchor Config
 * ============================================================================ */

static void test_anchor_config_init(void) {
    ax_anchor_config_t cfg;
    ax_gov_fault_flags_t faults;

    TEST("Anchor config init");
    ax_gov_clear_faults(&faults);

    if (ax_anchor_config_init(&cfg, 100, 0, &faults) != 0) {
        FAIL("init failed"); return;
    }
    if (!cfg.initialised) { FAIL("not initialised"); return; }
    if (cfg.interval_seq_count != 100) { FAIL("interval wrong"); return; }
    if (cfg.next_anchor_seq != 100) { FAIL("next_anchor_seq wrong"); return; }
    PASS();
}

static void test_anchor_config_zero_interval(void) {
    ax_anchor_config_t cfg;
    ax_gov_fault_flags_t faults;

    TEST("Anchor config rejects zero interval");
    ax_gov_clear_faults(&faults);

    if (ax_anchor_config_init(&cfg, 0, 0, &faults) != -1) {
        FAIL("should reject zero interval"); return;
    }
    if (!faults.integrity_fault) { FAIL("integrity_fault not set"); return; }
    PASS();
}

static void test_anchor_is_due(void) {
    ax_anchor_config_t cfg;
    ax_gov_fault_flags_t faults;

    TEST("Anchor due detection");
    ax_gov_clear_faults(&faults);
    ax_anchor_config_init(&cfg, 100, 0, &faults);

    if (ax_anchor_is_due(&cfg, 50)) { FAIL("should not be due at 50"); return; }
    if (!ax_anchor_is_due(&cfg, 100)) { FAIL("should be due at 100"); return; }
    if (!ax_anchor_is_due(&cfg, 200)) { FAIL("should be due at 200"); return; }
    PASS();
}

/* ============================================================================
 * Anchor Hash Computation
 * ============================================================================ */

static void test_anchor_hash_deterministic(void) {
    uint8_t chain_head[32];
    uint8_t hash1[32];
    uint8_t hash2[32];
    ax_gov_fault_flags_t faults;

    TEST("Anchor hash is deterministic");
    memset(chain_head, 0xAA, 32);
    ax_gov_clear_faults(&faults);

    ax_anchor_compute_hash(chain_head, 12345ULL, hash1, &faults);
    ax_anchor_compute_hash(chain_head, 12345ULL, hash2, &faults);

    if (memcmp(hash1, hash2, 32) != 0) { FAIL("hashes differ"); return; }
    if (ax_gov_has_fault(&faults)) { FAIL("unexpected fault"); return; }
    PASS();
}

static void test_anchor_hash_varies_with_time_seq(void) {
    uint8_t chain_head[32];
    uint8_t hash1[32];
    uint8_t hash2[32];
    ax_gov_fault_flags_t faults;

    TEST("Anchor hash differs for different time_seq");
    memset(chain_head, 0xAA, 32);
    ax_gov_clear_faults(&faults);

    ax_anchor_compute_hash(chain_head, 100ULL, hash1, &faults);
    ax_anchor_compute_hash(chain_head, 101ULL, hash2, &faults);

    if (memcmp(hash1, hash2, 32) == 0) { FAIL("hashes identical — should differ"); return; }
    PASS();
}

static void test_anchor_hash_varies_with_chain_head(void) {
    uint8_t chain_head1[32];
    uint8_t chain_head2[32];
    uint8_t hash1[32];
    uint8_t hash2[32];
    ax_gov_fault_flags_t faults;

    TEST("Anchor hash differs for different chain heads");
    memset(chain_head1, 0xAA, 32);
    memset(chain_head2, 0xBB, 32);
    ax_gov_clear_faults(&faults);

    ax_anchor_compute_hash(chain_head1, 100ULL, hash1, &faults);
    ax_anchor_compute_hash(chain_head2, 100ULL, hash2, &faults);

    if (memcmp(hash1, hash2, 32) == 0) { FAIL("hashes identical — should differ"); return; }
    PASS();
}

/* ============================================================================
 * Anchor Build and Verify
 * ============================================================================ */

static void test_anchor_build_and_verify(void) {
    ax_anchor_record_t record;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32];
    uint8_t time_obs_hash[32];

    TEST("Anchor build and verify round-trip");
    make_gov(&gov);
    memset(chain_head, 0xCC, 32);
    memset(time_obs_hash, 0xDD, 32);
    ax_gov_clear_faults(&faults);

    if (ax_anchor_build(&record, chain_head, 500ULL, time_obs_hash,
                        &gov, &faults) != 0) {
        FAIL("build failed"); return;
    }
    if (!record.proof_built) { FAIL("proof not built"); return; }
    if (record.proof.proof_type != AX_PROOF_TYPE_ANCHOR_PUBLICATION) {
        FAIL("wrong proof type"); return;
    }
    if (record.anchor_time_seq != 500ULL) { FAIL("time_seq wrong"); return; }

    /* Verify */
    ax_gov_clear_faults(&faults);
    if (ax_anchor_verify(&record, &faults) != 0) {
        FAIL("verify failed"); return;
    }
    PASS();
}

static void test_anchor_verify_tampered(void) {
    ax_anchor_record_t record;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32];
    uint8_t time_obs_hash[32];

    TEST("Anchor verify detects tampered hash");
    make_gov(&gov);
    memset(chain_head, 0xCC, 32);
    memset(time_obs_hash, 0xDD, 32);
    ax_gov_clear_faults(&faults);

    ax_anchor_build(&record, chain_head, 500ULL, time_obs_hash, &gov, &faults);

    /* Tamper with the anchor hash */
    record.anchor_hash[0] ^= 0xFF;

    ax_gov_clear_faults(&faults);
    if (ax_anchor_verify(&record, &faults) != -1) {
        FAIL("should detect tampering"); return;
    }
    if (!faults.hash_mismatch) { FAIL("hash_mismatch not set"); return; }
    PASS();
}

static void test_anchor_advance(void) {
    ax_anchor_config_t cfg;
    ax_gov_fault_flags_t faults;

    TEST("Anchor interval advances correctly");
    ax_gov_clear_faults(&faults);
    ax_anchor_config_init(&cfg, 100, 0, &faults);

    ax_anchor_advance(&cfg, 100, &faults);
    if (cfg.next_anchor_seq != 200) {
        printf("FAIL: next_anchor_seq=%llu (expected 200)\n",
               (unsigned long long)cfg.next_anchor_seq);
        tests_failed++;
        return;
    }
    PASS();
}

/* ============================================================================
 * Compliance Reports
 * ============================================================================ */

static void test_compliance_init(void) {
    ax_compliance_report_t report;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32];

    TEST("Compliance report init");
    memset(chain_head, 0xEE, 32);
    ax_gov_clear_faults(&faults);

    if (ax_compliance_report_init(&report, AX_COMPLIANCE_TRACK_B,
                                  AX_REPORT_TRIGGER_ON_DEMAND,
                                  chain_head, 42, &faults) != 0) {
        FAIL("init failed"); return;
    }
    if (report.track != AX_COMPLIANCE_TRACK_B) { FAIL("track wrong"); return; }
    if (report.trigger != AX_REPORT_TRIGGER_ON_DEMAND) { FAIL("trigger wrong"); return; }
    if (report.evidence_count != 0) { FAIL("evidence_count not 0"); return; }
    PASS();
}

static void test_compliance_add_evidence(void) {
    ax_compliance_report_t report;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32] = {0};
    uint8_t ev[32];

    TEST("Compliance add evidence");
    ax_gov_clear_faults(&faults);
    ax_compliance_report_init(&report, AX_COMPLIANCE_TRACK_B,
                              AX_REPORT_TRIGGER_ON_DEMAND, chain_head, 1, &faults);

    memset(ev, 0x11, 32);
    if (ax_compliance_add_evidence(&report, ev, &faults) != 0) {
        FAIL("add failed"); return;
    }
    if (report.evidence_count != 1) { FAIL("count != 1"); return; }
    PASS();
}

static void test_compliance_track_a_wrong_track(void) {
    ax_compliance_report_t report;
    ax_track_a_evidence_t evidence;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32] = {0};

    TEST("Track A evidence rejects Track B report");
    ax_gov_clear_faults(&faults);
    ax_compliance_report_init(&report, AX_COMPLIANCE_TRACK_B,
                              AX_REPORT_TRIGGER_ON_DEMAND, chain_head, 1, &faults);
    memset(&evidence, 0, sizeof(evidence));

    if (ax_compliance_add_track_a_evidence(&report, &evidence, &faults) != -1) {
        FAIL("should reject wrong track"); return;
    }
    if (!faults.integrity_fault) { FAIL("integrity_fault not set"); return; }
    PASS();
}

static void test_compliance_track_a_golden_reference(void) {
    ax_compliance_report_t report;
    ax_track_a_evidence_t evidence;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32] = {0};

    TEST("Track A: golden reference present in evidence");
    ax_gov_clear_faults(&faults);
    ax_compliance_report_init(&report, AX_COMPLIANCE_TRACK_A,
                              AX_REPORT_TRIGGER_ON_DEMAND, chain_head, 1, &faults);
    memset(&evidence, 0, sizeof(evidence));
    memset(evidence.golden_reference_hash, 0x36, 32);
    evidence.golden_reference_present = true;

    if (ax_compliance_add_track_a_evidence(&report, &evidence, &faults) != 0) {
        FAIL("add failed"); return;
    }
    if (report.evidence_count != 1) { FAIL("golden not added"); return; }
    PASS();
}

static void test_compliance_evidence_closure_empty(void) {
    ax_compliance_report_t report;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32] = {0};
    uint8_t zero[32] = {0};

    TEST("Compliance closure: empty report has zero root");
    ax_gov_clear_faults(&faults);
    ax_compliance_report_init(&report, AX_COMPLIANCE_TRACK_B,
                              AX_REPORT_TRIGGER_ON_DEMAND, chain_head, 1, &faults);

    if (ax_compliance_compute_closure(&report, &faults) != 0) {
        FAIL("compute failed"); return;
    }
    if (!report.closure_computed) { FAIL("closure not computed"); return; }
    if (memcmp(report.evidence_closure_root, zero, 32) != 0) {
        FAIL("empty root not zero"); return;
    }
    PASS();
}

static void test_compliance_finalise_track_b(void) {
    ax_compliance_report_t report;
    ax_track_b_evidence_t evidence;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32];

    TEST("Compliance Track B finalise");
    make_gov(&gov);
    memset(chain_head, 0xEE, 32);
    ax_gov_clear_faults(&faults);

    ax_compliance_report_init(&report, AX_COMPLIANCE_TRACK_B,
                              AX_REPORT_TRIGGER_ANCHOR_INTERVAL,
                              chain_head, 50, &faults);

    memset(&evidence, 0, sizeof(evidence));
    memset(evidence.audit_ledger_hash, 0x11, 32);
    evidence.audit_ledger_present = true;
    memset(evidence.oracle_records_hash, 0x22, 32);
    evidence.oracle_records_present = true;
    memset(evidence.math_traces_hash, 0x33, 32);
    evidence.math_traces_present = true;

    ax_compliance_add_track_b_evidence(&report, &evidence, &faults);

    if (ax_compliance_finalise(&report, &gov, &faults) != 0) {
        FAIL("finalise failed"); return;
    }
    if (!report.proof_built) { FAIL("proof not built"); return; }
    if (report.proof.proof_type != AX_PROOF_TYPE_COMPLIANCE_SUMMARY) {
        FAIL("wrong proof type"); return;
    }
    if (!report.proof.proof_hash_computed) { FAIL("proof hash not computed"); return; }
    PASS();
}

static void test_compliance_verify_closure_roundtrip(void) {
    ax_compliance_report_t report;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32] = {0};
    uint8_t ev1[32];
    uint8_t ev2[32];

    TEST("Compliance closure verify round-trip");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);

    ax_compliance_report_init(&report, AX_COMPLIANCE_TRACK_B,
                              AX_REPORT_TRIGGER_ON_DEMAND, chain_head, 1, &faults);

    memset(ev1, 0x11, 32);
    memset(ev2, 0x22, 32);
    ax_compliance_add_evidence(&report, ev1, &faults);
    ax_compliance_add_evidence(&report, ev2, &faults);

    ax_compliance_finalise(&report, &gov, &faults);

    ax_gov_clear_faults(&faults);
    if (ax_compliance_verify_closure(&report, &faults) != 0) {
        FAIL("closure verify failed"); return;
    }
    PASS();
}

static void test_compliance_verify_closure_tampered(void) {
    ax_compliance_report_t report;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t chain_head[32] = {0};
    uint8_t ev[32];

    TEST("Compliance closure detects tampered evidence");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);

    ax_compliance_report_init(&report, AX_COMPLIANCE_TRACK_B,
                              AX_REPORT_TRIGGER_ON_DEMAND, chain_head, 1, &faults);
    memset(ev, 0x55, 32);
    ax_compliance_add_evidence(&report, ev, &faults);
    ax_compliance_finalise(&report, &gov, &faults);

    /* Tamper with evidence after finalisation */
    report.evidence[0][0] ^= 0xFF;

    ax_gov_clear_faults(&faults);
    if (ax_compliance_verify_closure(&report, &faults) != -1) {
        FAIL("should detect tampering"); return;
    }
    if (!faults.hash_mismatch) { FAIL("hash_mismatch not set"); return; }
    PASS();
}

static void test_compliance_string_tables(void) {
    TEST("Compliance string tables");
    if (ax_compliance_track_to_string(AX_COMPLIANCE_TRACK_A) == NULL) { FAIL("TRACK_A NULL"); return; }
    if (ax_compliance_track_to_string(AX_COMPLIANCE_TRACK_B) == NULL) { FAIL("TRACK_B NULL"); return; }
    if (ax_compliance_trigger_to_string(AX_REPORT_TRIGGER_AGENT_STOPPED) == NULL) { FAIL("trigger NULL"); return; }
    if (ax_compliance_trigger_to_string(AX_REPORT_TRIGGER_RECOVERY) == NULL) { FAIL("RECOVERY NULL"); return; }
    PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("\n=== axioma-governance: Anchor & Compliance Tests ===\n\n");

    printf("Anchor Configuration:\n");
    test_anchor_config_init();
    test_anchor_config_zero_interval();
    test_anchor_is_due();

    printf("\nAnchor Hash:\n");
    test_anchor_hash_deterministic();
    test_anchor_hash_varies_with_time_seq();
    test_anchor_hash_varies_with_chain_head();

    printf("\nAnchor Build and Verify:\n");
    test_anchor_build_and_verify();
    test_anchor_verify_tampered();
    test_anchor_advance();

    printf("\nCompliance Reports:\n");
    test_compliance_init();
    test_compliance_add_evidence();
    test_compliance_track_a_wrong_track();
    test_compliance_track_a_golden_reference();
    test_compliance_evidence_closure_empty();
    test_compliance_finalise_track_b();
    test_compliance_verify_closure_roundtrip();
    test_compliance_verify_closure_tampered();
    test_compliance_string_tables();

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
