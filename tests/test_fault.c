/**
 * @file test_fault.c
 * @brief Governance Integrity Fault Handling Tests
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 * @license GPL-3.0-or-later
 *
 * @traceability SRS-007-SHALL-035: Integrity fault definition
 * @traceability SRS-007-SHALL-036: Integrity fault recording
 * @traceability SRS-007-SHALL-037: Integrity fault response
 * @traceability SRS-007-SHALL-038: No silent governance failure
 * @traceability SRS-007-SHALL-053: Ledger failure mode (Option A)
 * @traceability SRS-007-SHALL-061: Fallback log overflow (Option A.1)
 */

#include "ax_governance.h"
#include "ax_fault.h"
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
 * Fallback Log Init
 * ============================================================================ */

static void test_fallback_init(void) {
    ax_fallback_log_t log;
    ax_gov_fault_flags_t faults;

    TEST("Fallback log init");
    ax_gov_clear_faults(&faults);
    ax_fallback_log_init(&log, &faults);

    if (!log.initialised) { FAIL("not initialised"); return; }
    if (log.state != AX_FALLBACK_STATE_IDLE) { FAIL("not IDLE"); return; }
    if (log.entry_count != 0) { FAIL("entry_count not 0"); return; }
    if (log.overflow_flag) { FAIL("overflow_flag set"); return; }
    PASS();
}

/* ============================================================================
 * Fallback Log Write
 * ============================================================================ */

static void test_fallback_write_single(void) {
    ax_fallback_log_t log;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t evidence[32];

    TEST("Fallback log: single write");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);
    ax_fallback_log_init(&log, &faults);
    memset(evidence, 0x77, 32);

    if (ax_fallback_log_write(&log, AX_VIOLATION_HASH_MISMATCH, evidence,
                              "SRS-007-SHALL-014", &gov, &faults) != 0) {
        FAIL("write failed"); return;
    }
    if (log.entry_count != 1) { FAIL("entry_count != 1"); return; }
    if (log.state != AX_FALLBACK_STATE_ACTIVE) { FAIL("state not ACTIVE"); return; }
    if (ax_fallback_log_is_overflow(&log)) { FAIL("overflow set unexpectedly"); return; }
    PASS();
}

static void test_fallback_write_multiple(void) {
    ax_fallback_log_t log;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t evidence[32];
    size_t i;
    /* Write up to MAX_ENTRIES-2 to stay within capacity */
    size_t safe_count = AX_FALLBACK_LOG_MAX_ENTRIES - 2U;

    TEST("Fallback log: multiple writes within capacity");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);
    ax_fallback_log_init(&log, &faults);

    for (i = 0; i < safe_count; i++) {
        memset(evidence, (int)(i + 1), 32);
        ax_gov_clear_faults(&faults);
        if (ax_fallback_log_write(&log, AX_VIOLATION_ORDERING, evidence,
                                  "SRS-007-SHALL-018", &gov, &faults) != 0) {
            FAIL("write failed"); return;
        }
    }
    if (log.entry_count != safe_count) {
        printf("FAIL: entry_count=%zu (expected %zu)\n", log.entry_count, safe_count);
        tests_failed++;
        return;
    }
    if (ax_fallback_log_is_overflow(&log)) { FAIL("overflow set unexpectedly"); return; }
    PASS();
}

static void test_fallback_get_entry(void) {
    ax_fallback_log_t log;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t evidence[32];
    const ax_proof_record_t *entry;

    TEST("Fallback log: get entry by index");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);
    ax_fallback_log_init(&log, &faults);
    memset(evidence, 0x99, 32);

    ax_fallback_log_write(&log, AX_VIOLATION_WEIGHT_MISMATCH, evidence,
                          "SRS-007-SHALL-013", &gov, &faults);

    entry = ax_fallback_log_get_entry(&log, 0);
    if (entry == NULL) { FAIL("entry is NULL"); return; }
    if (entry->violation != AX_VIOLATION_WEIGHT_MISMATCH) {
        FAIL("wrong violation in entry"); return;
    }
    if (entry->result != AX_PROOF_RESULT_INTEGRITY_FAULT) {
        FAIL("result not INTEGRITY_FAULT"); return;
    }

    /* Out of bounds returns NULL */
    if (ax_fallback_log_get_entry(&log, 999) != NULL) {
        FAIL("out of bounds should return NULL"); return;
    }
    PASS();
}

/* ============================================================================
 * Overflow Behaviour (SRS-007-SHALL-061, Option A.1)
 * ============================================================================ */

static void test_fallback_overflow(void) {
    ax_fallback_log_t log;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t evidence[32];
    size_t i;
    int rc;

    TEST("Fallback log overflow: OVERFLOW_MARKER written, system halts");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);
    ax_fallback_log_init(&log, &faults);

    /*
     * Fill until overflow is triggered.
     *
     * Writes 0..(MAX-2) succeed — 15 normal entries.
     * Write MAX-1 (index 15) triggers the overflow path:
     *   - entry_count has reached MAX-1 (capacity check fires)
     *   - OVERFLOW_MARKER is written into the last slot
     *   - state transitions to HALTED, returns -1
     */
    for (i = 0; i < AX_FALLBACK_LOG_MAX_ENTRIES + 1U; i++) {
        memset(evidence, (int)(i + 1), 32);
        ax_gov_clear_faults(&faults);
        rc = ax_fallback_log_write(&log, AX_VIOLATION_ORDERING, evidence,
                                   "SRS-007-SHALL-018", &gov, &faults);
        if (i < AX_FALLBACK_LOG_MAX_ENTRIES - 1U) {
            /* Normal writes should succeed */
            if (rc != 0) {
                printf("FAIL: write %zu failed unexpectedly (rc=%d)\n", i, rc);
                tests_failed++;
                return;
            }
        } else {
            /* Write at index MAX-1 triggers overflow */
            if (rc != -1) {
                FAIL("overflow write should return -1"); return;
            }
            break;
        }
    }

    if (!ax_fallback_log_is_overflow(&log)) { FAIL("overflow flag not set"); return; }
    if (!ax_fallback_log_is_halted(&log)) { FAIL("not halted after overflow"); return; }

    /* Final entry should be the OVERFLOW_MARKER */
    {
        const ax_proof_record_t *last = ax_fallback_log_get_entry(
            &log, log.entry_count - 1);
        if (last == NULL) { FAIL("last entry NULL"); return; }
        if (last->result != AX_PROOF_RESULT_INTEGRITY_FAULT) {
            FAIL("overflow marker not INTEGRITY_FAULT"); return;
        }
        if (last->violation != AX_VIOLATION_FALLBACK_OVERFLOW) {
            FAIL("overflow marker wrong violation"); return;
        }
    }

    /* Further writes must be rejected */
    ax_gov_clear_faults(&faults);
    memset(evidence, 0xFF, 32);
    rc = ax_fallback_log_write(&log, AX_VIOLATION_HASH_MISMATCH, evidence,
                               "SRS-007-SHALL-014", &gov, &faults);
    if (rc != -1) { FAIL("write after overflow should fail"); return; }

    PASS();
}

/* ============================================================================
 * ax_fault_record — Ledger Available Path
 * ============================================================================ */

static void test_fault_record_ledger_available(void) {
    ax_proof_record_t proof;
    ax_fallback_log_t log;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t evidence[32];

    TEST("ax_fault_record: ledger available path");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);
    ax_fallback_log_init(&log, &faults);
    memset(evidence, 0x44, 32);

    if (ax_fault_record(&proof, AX_VIOLATION_HASH_MISMATCH, evidence,
                        "SRS-007-SHALL-014", true, &log, &gov, &faults) != 0) {
        FAIL("fault_record failed"); return;
    }

    /* Proof must be INTEGRITY_FAULT */
    if (proof.result != AX_PROOF_RESULT_INTEGRITY_FAULT) {
        FAIL("proof not INTEGRITY_FAULT"); return;
    }
    if (proof.violation != AX_VIOLATION_HASH_MISMATCH) {
        FAIL("wrong violation"); return;
    }

    /* Governance must be in fault mode */
    if (!gov.in_fault_mode) { FAIL("not in fault mode"); return; }
    if (gov.agent_state != AX_AGENT_STATE_STOPPED) { FAIL("agent not STOPPED"); return; }

    /* Fallback log should NOT have been written */
    if (log.entry_count != 0) { FAIL("fallback log written unexpectedly"); return; }

    PASS();
}

/* ============================================================================
 * ax_fault_record — Ledger Unavailable Path
 * ============================================================================ */

static void test_fault_record_ledger_unavailable(void) {
    ax_fallback_log_t log;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t evidence[32];

    TEST("ax_fault_record: ledger unavailable — writes to fallback");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);
    ax_fallback_log_init(&log, &faults);
    memset(evidence, 0x55, 32);

    if (ax_fault_record(NULL, AX_VIOLATION_ORDERING, evidence,
                        "SRS-007-SHALL-018", false, &log, &gov, &faults) != 0) {
        FAIL("fault_record failed"); return;
    }

    /* Fallback log must have one entry */
    if (log.entry_count != 1) { FAIL("fallback log count != 1"); return; }

    /* Governance must be in fault mode */
    if (!gov.in_fault_mode) { FAIL("not in fault mode"); return; }
    if (gov.agent_state != AX_AGENT_STATE_STOPPED) { FAIL("agent not STOPPED"); return; }

    PASS();
}

static void test_fault_record_no_fallback_no_ledger(void) {
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t evidence[32];

    TEST("ax_fault_record: no ledger, no fallback — fault flags set");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);
    memset(evidence, 0x66, 32);

    /* ledger_available=false, fallback_log=NULL */
    ax_fault_record(NULL, AX_VIOLATION_REPLAY_MISMATCH, evidence,
                    "SRS-007-SHALL-019", false, NULL, &gov, &faults);

    /* Can't prevent the failure but governance must still enter fault mode */
    if (!gov.in_fault_mode) { FAIL("not in fault mode"); return; }
    PASS();
}

/* ============================================================================
 * No Silent Governance Failure (SRS-007-SHALL-038)
 * ============================================================================ */

static void test_no_silent_failure_all_violations(void) {
    ax_fallback_log_t log;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t faults;
    uint8_t evidence[32] = {0x01};
    /* Test every violation type can be recorded */
    ax_violation_t violations[] = {
        AX_VIOLATION_NONE,
        AX_VIOLATION_HASH_MISMATCH,
        AX_VIOLATION_ORDERING,
        AX_VIOLATION_WEIGHT_MISMATCH,
        AX_VIOLATION_POLICY_BREACH,
        AX_VIOLATION_TRANSITION_FAULT,
        AX_VIOLATION_EVIDENCE_MISSING,
        AX_VIOLATION_REPLAY_MISMATCH
    };
    size_t n = sizeof(violations) / sizeof(violations[0]);
    size_t i;

    TEST("No silent failure: all violation types can be recorded");
    make_gov(&gov);
    ax_gov_clear_faults(&faults);
    ax_fallback_log_init(&log, &faults);

    for (i = 0; i < n && i < AX_FALLBACK_LOG_MAX_ENTRIES - 2U; i++) {
        ax_gov_clear_faults(&faults);
        evidence[0] = (uint8_t)(i + 1);
        if (ax_fallback_log_write(&log, violations[i], evidence,
                                  "SRS-007-SHALL-038", &gov, &faults) != 0) {
            printf("FAIL: could not record violation type %zu\n", i);
            tests_failed++;
            return;
        }
    }
    if (log.entry_count != n) {
        printf("FAIL: entry_count=%zu (expected %zu)\n", log.entry_count, n);
        tests_failed++;
        return;
    }
    PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("\n=== axioma-governance: Fault Handling Tests ===\n\n");

    printf("Fallback Log Init:\n");
    test_fallback_init();

    printf("\nFallback Log Writes:\n");
    test_fallback_write_single();
    test_fallback_write_multiple();
    test_fallback_get_entry();

    printf("\nOverflow Behaviour (SRS-007-SHALL-061, Option A.1):\n");
    test_fallback_overflow();

    printf("\nFault Recording:\n");
    test_fault_record_ledger_available();
    test_fault_record_ledger_unavailable();
    test_fault_record_no_fallback_no_ledger();

    printf("\nNo Silent Failure (SRS-007-SHALL-038):\n");
    test_no_silent_failure_all_violations();

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
