/**
 * @file test_proof_capacity.c
 * @brief PCR-007 (D-11): AX:PROOF:v1 producer capacity, P1 and P2
 *
 * Owner decision 2026-10-12: Option A (192 producer evidence references)
 * with P1 (metadata strings terminated within their arrays) and P2 (enum
 * range validation, latched, signatures unchanged). Valid v1 records with
 * 193 to 237 references produced before the limit must still verify.
 *
 * Legacy fixture values were produced by axioma-governance 93d75a6
 * (pristine main) with ax_proof_finalise.
 *
 * @traceability SRS-007-SHALL-043 (as amended by SRS-007-AMD-002)
 */

#include "ax_governance.h"
#include "ax_proof.h"
#include "ax_jcs.h"
#include <axilog/sha256.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { printf("  [TEST] %s... ", name); tests_run++; } while (0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

static ax_proof_record_t r;
static uint8_t big[1 << 17];

static void make_ref(uint8_t ref[32], size_t i)
{
    memset(ref, 0, 32);
    ref[0] = (uint8_t)(i >> 8);
    ref[1] = (uint8_t)i;
    ref[31] = 0xAB;
}

static size_t canon_len(int with_hash, uint8_t digest[32])
{
    size_t n = 0;
    ax_gov_fault_flags_t f;
    ax_gov_clear_faults(&f);
    if (jcs_proof_to_canonical(&r, big, sizeof big, &n, with_hash, &f) != 0) {
        return 0;
    }
    if (digest != NULL) {
        axilog_sha256(digest, big, n);
    }
    return n;
}

/* worst = 1: every string at maximum length of 0x01 bytes (6-byte escapes),
 * DECLARED metadata, INTEGRITY_FAULT / FALLBACK_OVERFLOW, ledger_seq max. */
static int build(int worst, size_t k, ax_gov_fault_flags_t *f)
{
    char claim[AX_MAX_CLAIM_SIZE];
    char rule[AX_MAX_RULE_ID_SIZE];
    uint8_t head[32] = {0};
    uint8_t ref[32];
    ax_ordering_metadata_t m;
    size_t i;

    ax_gov_clear_faults(f);
    memset(claim, worst ? 1 : 'c', sizeof claim);
    claim[worst ? sizeof claim - 1 : 1] = '\0';
    memset(rule, worst ? 1 : 'R', sizeof rule);
    rule[worst ? sizeof rule - 1 : 1] = '\0';
    if (ax_proof_init(&r, claim,
                      worst ? AX_PROOF_TYPE_ANCHOR_PUBLICATION : AX_PROOF_TYPE_SUBSTRATE_CERT,
                      rule, head, worst ? UINT64_MAX : 0, f) != 0) {
        return -1;
    }
    if (worst) {
        memset(&m, 1, sizeof m);
        m.description[sizeof m.description - 1] = '\0';
        m.key_field[sizeof m.key_field - 1] = '\0';
        m.direction[sizeof m.direction - 1] = '\0';
        m.is_set = true;
        if (ax_proof_set_ordering(&r, AX_EVIDENCE_ORDER_DECLARED, &m, f) != 0) {
            return -2;
        }
        ax_proof_set_result(&r, AX_PROOF_RESULT_INTEGRITY_FAULT,
                            AX_VIOLATION_FALLBACK_OVERFLOW, f);
    }
    for (i = 0; i < k; i++) {
        make_ref(ref, i);
        if (ax_proof_add_evidence(&r, ref, f) != 0) {
            return -3;
        }
    }
    return 0;
}

/* 1. The worst-case record at the bound finalises and has the derived size. */
static void test_worst_case_at_bound(void)
{
    ax_gov_fault_flags_t f;
    TEST("worst case, 192 references: finalises, canonical size 16,356 = 3,493 + 67*192 - 1");
    if (build(1, AX_PROOF_MAX_EVIDENCE_REFS, &f) != 0) { FAIL("build"); return; }
    if (ax_proof_finalise(&r, &f) != 0) { FAIL("finalise failed"); return; }
    if (canon_len(1, NULL) != 16356) { FAIL("size differs from derivation"); return; }
    PASS();
}

/* 2. Reference 193 is rejected at add time, not at finalisation. */
static void test_193rd_rejected_at_add(void)
{
    ax_gov_fault_flags_t f;
    uint8_t ref[32];
    TEST("reference 193 rejected by ax_proof_add_evidence with overflow; record unchanged");
    if (build(0, AX_PROOF_MAX_EVIDENCE_REFS, &f) != 0) { FAIL("build"); return; }
    make_ref(ref, 999);
    if (ax_proof_add_evidence(&r, ref, &f) != -1 || !f.overflow) { FAIL("193rd accepted"); return; }
    if (r.evidence_refs_count != AX_PROOF_MAX_EVIDENCE_REFS) { FAIL("count changed"); return; }
    PASS();
}

/* 3. Ordinary records are unaffected. */
static void test_minimal_at_bound(void)
{
    ax_gov_fault_flags_t f;
    TEST("minimal record, 192 references: finalises");
    if (build(0, AX_PROOF_MAX_EVIDENCE_REFS, &f) != 0) { FAIL("build"); return; }
    if (ax_proof_finalise(&r, &f) != 0) { FAIL("finalise failed"); return; }
    PASS();
}

/* 4. P1: each metadata string must be terminated within its array. */
static void test_p1_unterminated_metadata(void)
{
    ax_gov_fault_flags_t f;
    ax_ordering_metadata_t m;
    int which, ok = 1;
    TEST("P1: unterminated description, key_field or direction rejected; ordering unchanged");
    for (which = 0; which < 3; which++) {
        if (build(0, 1, &f) != 0) { FAIL("build"); return; }
        memset(&m, 0, sizeof m);
        strcpy(m.description, "d");
        strcpy(m.key_field, "ledger_seq");
        strcpy(m.direction, "ascending");
        m.is_set = true;
        if (which == 0) memset(m.description, 'x', sizeof m.description);
        if (which == 1) memset(m.key_field, 'x', sizeof m.key_field);
        if (which == 2) memset(m.direction, 'x', sizeof m.direction);
        if (ax_proof_set_ordering(&r, AX_EVIDENCE_ORDER_DECLARED, &m, &f) != -1 || !f.overflow) ok = 0;
        if (r.evidence_ordering != AX_EVIDENCE_ORDER_LEX || r.ordering_metadata.is_set) ok = 0;
    }
    if (!ok) { FAIL("unterminated metadata accepted"); return; }
    PASS();
}

/* 5. P2: out-of-range result or violation is latched and finalisation fails. */
static void test_p2_enum_latched(void)
{
    ax_gov_fault_flags_t f, f2;
    TEST("P2: out-of-range violation or result latched; finalise fails with integrity_fault");
    if (build(0, 1, &f) != 0) { FAIL("build"); return; }
    ax_proof_set_result(&r, AX_PROOF_RESULT_INVALID, (ax_violation_t)9, &f);
    if (!f.integrity_fault) { FAIL("violation 9 not faulted"); return; }
    /* latched in the record: a fresh fault context still cannot finalise */
    ax_gov_clear_faults(&f2);
    if (ax_proof_finalise(&r, &f2) != -1 || !f2.integrity_fault) { FAIL("finalised with violation 9"); return; }
    if (build(0, 1, &f) != 0) { FAIL("build"); return; }
    ax_proof_set_result(&r, (ax_proof_result_t)3, AX_VIOLATION_NONE, &f);
    if (!f.integrity_fault) { FAIL("result 3 not faulted"); return; }
    ax_gov_clear_faults(&f2);
    if (ax_proof_finalise(&r, &f2) != -1 || !f2.integrity_fault) { FAIL("finalised with result 3"); return; }
    PASS();
}

/* 6. Encoder guards for records filled by direct struct writes. */
static void test_encoder_guards(void)
{
    ax_gov_fault_flags_t f;
    size_t n;
    int ok = 1;
    TEST("encoder refuses out-of-range enums, count > 1024 and unterminated strings (no OOB read)");
    build(0, 1, &f);
    r.proof_type = (ax_proof_type_t)AX_PROOF_TYPE_COUNT;
    ax_gov_clear_faults(&f);
    if (jcs_proof_to_canonical(&r, big, sizeof big, &n, false, &f) != -1 || !f.integrity_fault) ok = 0;
    build(0, 1, &f);
    r.evidence_ordering = (ax_evidence_ordering_t)3;
    ax_gov_clear_faults(&f);
    if (jcs_proof_to_canonical(&r, big, sizeof big, &n, false, &f) != -1 || !f.integrity_fault) ok = 0;
    build(0, 1, &f);
    r.evidence_refs_count = AX_MAX_EVIDENCE_REFS + 1;
    ax_gov_clear_faults(&f);
    if (jcs_proof_to_canonical(&r, big, sizeof big, &n, false, &f) != -1 || !f.overflow) ok = 0;
    build(0, 1, &f);
    memset(r.claim, 'x', sizeof r.claim);
    ax_gov_clear_faults(&f);
    if (jcs_proof_to_canonical(&r, big, sizeof big, &n, false, &f) != -1 || !f.overflow) ok = 0;
    if (!ok) { FAIL("guard missing"); return; }
    PASS();
}

/* 7. Producer paths refuse more than 192 references set by direct writes. */
static void test_direct_write_count_rejected(void)
{
    ax_gov_fault_flags_t f;
    uint8_t ref[32];
    size_t i;
    TEST("finalise and compute_hash refuse 193 references written directly into the struct");
    build(0, AX_PROOF_MAX_EVIDENCE_REFS, &f);
    for (i = AX_PROOF_MAX_EVIDENCE_REFS; i < 193; i++) {
        make_ref(ref, i);
        memcpy(r.evidence_refs[i], ref, 32);
    }
    r.evidence_refs_count = 193;
    ax_gov_clear_faults(&f);
    if (ax_proof_finalise(&r, &f) != -1 || !f.overflow) { FAIL("finalise accepted 193"); return; }
    ax_gov_clear_faults(&f);
    if (ax_proof_compute_hash(&r, &f) != -1 || !f.overflow) { FAIL("compute_hash accepted 193"); return; }
    PASS();
}

/* 8. Valid v1 records produced before the limit still verify. */
static void hex_to_bytes(const char *hex, uint8_t out[32])
{
    size_t i;
    unsigned v;
    for (i = 0; i < 32; i++) {
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/*
 * Legacy records are rebuilt exactly as 93d75a6 stored them, commitment
 * included. Two properties are checked against 93d75a6:
 *  (a) the canonical bytes with proof_hash are byte-identical, so the
 *      encoder still accepts and reproduces 193 to 237 references;
 *  (b) ax_proof_verify_hash gives the same outcome as on 93d75a6. On that
 *      commit the outcome is hash_mismatch for EVERY finalised record (finding
 *      D-23: proof_hash is computed while the commitment field is still zero,
 *      and the stored record carries the real commitment). PCR-007 does not
 *      change that behaviour; with the commitment field zeroed, as at hashing
 *      time, the recomputed proof_hash matches.
 */
static void test_legacy_records_verify(void)
{
    static const struct { size_t k; size_t len; const char *proof_hash; const char *canonical; const char *commitment; } L[] = {
        { 193, 13382,
          "0a616ae5e97ba2149487865470c99138ff2763c9ca81df4e53d85a9b57693f50",
          "3f0e7d324a184888e99231a18aa1fd6020a8e41fa71e20cbd4561ae4a3338f0d",
          "9b687f7fe40619dadc868095dd75d714a14c8552a1836c4524550b1bdd9a98af" },
        { 237, 16330,
          "c533edb9c5e3049878698425bcccaa98b4a41599a850f3c919b2cb4bac9a0682",
          "d77c1f1c3b10eca722bea2831eed4951e30aeb77538fe69e23e023ef6e3559e9",
          "269fb3f7766c2dcbc16473a22f5f38681edfbb97ec71eb1649e3198035f9bc4b" },
    };
    ax_gov_fault_flags_t f;
    uint8_t ref[32], want[32], got[32];
    size_t t, i;
    TEST("legacy v1 records with 193 and 237 references (made by 93d75a6): same bytes, same verification outcome");
    for (t = 0; t < 2; t++) {
        build(0, AX_PROOF_MAX_EVIDENCE_REFS, &f);
        for (i = AX_PROOF_MAX_EVIDENCE_REFS; i < L[t].k; i++) {
            make_ref(ref, i);
            memcpy(r.evidence_refs[i], ref, 32);
        }
        r.evidence_refs_count = L[t].k;
        hex_to_bytes(L[t].proof_hash, r.proof_hash);
        hex_to_bytes(L[t].commitment, r.commitment);
        r.proof_hash_computed = true;
        hex_to_bytes(L[t].canonical, want);
        if (canon_len(1, got) != L[t].len || memcmp(got, want, 32) != 0) {
            FAIL("canonical bytes differ from 93d75a6"); return;
        }
        ax_gov_clear_faults(&f);
        if (ax_proof_validate(&r, &f) != 0) { FAIL("validate rejected legacy record"); return; }
        ax_gov_clear_faults(&f);
        if (ax_proof_verify_hash(&r, &f) != -1 || !f.hash_mismatch) {
            FAIL("verify_hash outcome differs from 93d75a6 (D-23 behaviour)"); return;
        }
        memset(r.commitment, 0, 32);
        ax_gov_clear_faults(&f);
        if (ax_proof_verify_hash(&r, &f) != 0) { FAIL("proof_hash no longer reproduces"); return; }
    }
    PASS();
}

int main(void)
{
    printf("\n=== PCR-007 (D-11) AX:PROOF:v1 capacity, P1, P2 ===\n");
    test_worst_case_at_bound();
    test_193rd_rejected_at_add();
    test_minimal_at_bound();
    test_p1_unterminated_metadata();
    test_p2_enum_latched();
    test_encoder_guards();
    test_direct_write_count_rejected();
    test_legacy_records_verify();
    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
