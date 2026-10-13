/**
 * @file test_proof_v1_legacy.c
 * @brief D-23: AX:PROOF:v1 legacy verification profile
 *
 * Owner decision 2026-10-12: approve an explicit legacy-v1 verification
 * profile using the zeroed-commitment calculation of the existing producer,
 * keep v1 producer bytes, and separate structural/hash consistency from
 * authenticated provenance. Tests are committed before the implementation.
 *
 * Fixtures marked "93d75a6" were produced by pristine main with
 * ax_proof_finalise and are stored exactly as that producer left them
 * (commitment populated).
 *
 * @traceability SRS-007-AMD-004
 */

#include "ax_governance.h"
#include "ax_proof.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { printf("  [TEST] %s... ", name); tests_run++; } while (0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

static ax_proof_record_t r;

static void make_ref(uint8_t ref[32], size_t i)
{
    memset(ref, 0, 32);
    ref[0] = (uint8_t)(i >> 8);
    ref[1] = (uint8_t)i;
    ref[31] = 0xAB;
}

static void hex_to_bytes(const char *hex, uint8_t out[32])
{
    size_t i;
    unsigned v;
    for (i = 0; i < 32; i++) {
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* Short record as built by the fixture generator: claim "c", rule "R". */
static void build_short(size_t k)
{
    ax_gov_fault_flags_t f;
    uint8_t head[32] = {0}, ref[32];
    size_t i;
    ax_gov_clear_faults(&f);
    ax_proof_init(&r, "c", AX_PROOF_TYPE_SUBSTRATE_CERT, "R", head, 0, &f);
    for (i = 0; i < k && i < AX_PROOF_MAX_EVIDENCE_REFS; i++) {
        make_ref(ref, i);
        ax_proof_add_evidence(&r, ref, &f);
    }
    for (; i < k; i++) {            /* legacy counts above the producer bound */
        make_ref(ref, i);
        memcpy(r.evidence_refs[i], ref, 32);
    }
    r.evidence_refs_count = k;
}

static int verdict_of(ax_proof_v1_legacy_verdict_t *v)
{
    ax_gov_fault_flags_t f;
    ax_gov_clear_faults(&f);
    return ax_proof_verify_v1_legacy(&r, v, &f);
}

/* 1. Records stored by the v1 producer on 93d75a6 are consistent. */
static void test_main_fixtures_consistent(void)
{
    static const struct { size_t k; const char *ph; const char *cm; } L[] = {
        { 1,   "2629899304c50c2d381ea76c09acd808aa18d6d6270b7c78ae6ca76a555fc806",
               "1810c4a59c5909dae6ef67a285c4b622c717a007b3ba7236119829837da83e08" },
        { 193, "0a616ae5e97ba2149487865470c99138ff2763c9ca81df4e53d85a9b57693f50",
               "9b687f7fe40619dadc868095dd75d714a14c8552a1836c4524550b1bdd9a98af" },
        { 237, "c533edb9c5e3049878698425bcccaa98b4a41599a850f3c919b2cb4bac9a0682",
               "269fb3f7766c2dcbc16473a22f5f38681edfbb97ec71eb1649e3198035f9bc4b" },
    };
    ax_proof_v1_legacy_verdict_t v;
    size_t t;
    TEST("records stored by 93d75a6 (1, 193, 237 refs) are CONSISTENT under the legacy profile");
    for (t = 0; t < 3; t++) {
        build_short(L[t].k);
        hex_to_bytes(L[t].ph, r.proof_hash);
        hex_to_bytes(L[t].cm, r.commitment);
        r.proof_hash_computed = true;
        if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_CONSISTENT) {
            printf("(k=%zu) ", L[t].k); FAIL("not CONSISTENT"); return;
        }
    }
    PASS();
}

/* 2. Records finalised by the current producer are consistent, and the
 *    unchanged ax_proof_verify_hash still reports the D-23 mismatch. */
static void test_current_producer_consistent(void)
{
    ax_gov_fault_flags_t f;
    ax_proof_v1_legacy_verdict_t v;
    TEST("record finalised by this producer: legacy profile CONSISTENT; ax_proof_verify_hash unchanged (D-23)");
    build_short(AX_PROOF_MAX_EVIDENCE_REFS);
    ax_gov_clear_faults(&f);
    if (ax_proof_finalise(&r, &f) != 0) { FAIL("finalise"); return; }
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_CONSISTENT) { FAIL("not CONSISTENT"); return; }
    ax_gov_clear_faults(&f);
    if (ax_proof_verify_hash(&r, &f) != -1 || !f.hash_mismatch) { FAIL("verify_hash behaviour changed"); return; }
    PASS();
}

/* 3. Tampering is detected and attributed to the right hash. */
static void test_tampering(void)
{
    ax_gov_fault_flags_t f;
    ax_proof_v1_legacy_verdict_t v;
    int ok = 1;
    TEST("tampered claim, evidence ref or proof_hash -> HASH_MISMATCH; tampered commitment -> COMMITMENT_MISMATCH");
    build_short(3);
    ax_gov_clear_faults(&f);
    ax_proof_finalise(&r, &f);
    r.claim[0] = 'd';
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_HASH_MISMATCH) ok = 0;
    r.claim[0] = 'c';
    r.evidence_refs[1][5] ^= 1;
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_HASH_MISMATCH) ok = 0;
    r.evidence_refs[1][5] ^= 1;
    r.proof_hash[0] ^= 1;
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_HASH_MISMATCH) ok = 0;
    r.proof_hash[0] ^= 1;
    r.commitment[31] ^= 1;
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_COMMITMENT_MISMATCH) ok = 0;
    r.commitment[31] ^= 1;
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_CONSISTENT) ok = 0;
    if (!ok) { FAIL("wrong verdict"); return; }
    PASS();
}

/* 4. Structural failures give STRUCTURE_INVALID, never a hash verdict. */
static void test_structure(void)
{
    ax_gov_fault_flags_t f;
    ax_proof_v1_legacy_verdict_t v;
    int ok = 1;
    TEST("no evidence, proof_hash not computed, empty claim, out-of-range enum -> STRUCTURE_INVALID");
    build_short(2); ax_gov_clear_faults(&f); ax_proof_finalise(&r, &f);
    r.evidence_refs_count = 0;
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_STRUCTURE_INVALID) ok = 0;
    build_short(2); ax_gov_clear_faults(&f); ax_proof_finalise(&r, &f);
    r.proof_hash_computed = false;
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_STRUCTURE_INVALID) ok = 0;
    build_short(2); ax_gov_clear_faults(&f); ax_proof_finalise(&r, &f);
    r.claim[0] = '\0';
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_STRUCTURE_INVALID) ok = 0;
    build_short(2); ax_gov_clear_faults(&f); ax_proof_finalise(&r, &f);
    r.violation = (ax_violation_t)9;
    if (verdict_of(&v) != 0 || v != AX_PROOF_V1_LEGACY_STRUCTURE_INVALID) ok = 0;
    if (!ok) { FAIL("wrong verdict"); return; }
    PASS();
}

/* 5. The profile does not modify the record and rejects NULL arguments. */
static void test_contract(void)
{
    ax_gov_fault_flags_t f;
    ax_proof_v1_legacy_verdict_t v;
    static ax_proof_record_t copy;
    TEST("record unchanged by verification; NULL arguments return -1");
    build_short(4); ax_gov_clear_faults(&f); ax_proof_finalise(&r, &f);
    memcpy(&copy, &r, sizeof r);
    if (verdict_of(&v) != 0 || memcmp(&copy, &r, sizeof r) != 0) { FAIL("record modified"); return; }
    ax_gov_clear_faults(&f);
    if (ax_proof_verify_v1_legacy(NULL, &v, &f) != -1 ||
        ax_proof_verify_v1_legacy(&r, NULL, &f) != -1 ||
        ax_proof_verify_v1_legacy(&r, &v, NULL) != -1) { FAIL("NULL accepted"); return; }
    PASS();
}

int main(void)
{
    printf("\n=== D-23 AX:PROOF:v1 legacy verification profile ===\n");
    test_main_fixtures_consistent();
    test_current_producer_consistent();
    test_tampering();
    test_structure();
    test_contract();
    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
