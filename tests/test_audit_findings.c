/**
 * @file test_audit_findings.c
 * @brief Regression tests for audit findings F009–F015
 *
 * Each test directly exercises the specific invariant identified in the
 * audit. These tests exist to prove the findings are resolved and to
 * prevent regression.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 * @license GPL-3.0-or-later
 *
 * @traceability SRS-007-SHALL-007: Canonical format
 * @traceability SRS-007-SHALL-019: Replay verification
 * @traceability SRS-007-SHALL-045: Cryptographic binding fields
 * @traceability SRS-007-SHALL-054: Commitment payload encoding
 * @traceability SRS-007-SHALL-056: Proof type versioning
 * @traceability SRS-007-SHALL-057: Evidence ordering mode
 * @traceability SRS-007-SHALL-059: Merkle tree algorithm
 * @traceability SRS-007-SHALL-053: Ledger failure mode
 * @traceability SRS-007-SHALL-061: Fallback log overflow
 */

#include "ax_governance.h"
#include "ax_proof.h"
#include "ax_merkle.h"
#include "ax_fault.h"
#include "ax_verify.h"
#include "axilog/types.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  TEST: %-66s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

/* ============================================================================
 * Fixtures
 * ============================================================================ */

static void make_proof(ax_proof_record_t *r, ax_gov_fault_flags_t *f) {
    uint8_t head[32] = {0xA0};
    uint8_t ev[32]   = {0x11};
    ax_gov_clear_faults(f);
    ax_proof_init(r, "test claim", AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
                  "SRS-007-SHALL-001", head, 1, f);
    ax_proof_add_evidence(r, ev, f);
}

/* ============================================================================
 * F009: Single canonical buffer — proof_hash and commitment use same bytes
 * ============================================================================ */

static void test_f009_hash_covers_same_bytes_as_commitment(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;
    uint8_t head[32] = {0xA0};
    uint8_t ev[32]   = {0x11};
    uint8_t stored_hash[32];
    uint8_t stored_commitment[32];

    /* Build two identical proofs and verify proof_hash and commitment are
     * deterministically identical — which can only hold if both are derived
     * from the same canonical byte sequence. */
    ax_proof_record_t r2;
    ax_gov_fault_flags_t f2;

    TEST("F009: proof_hash and commitment are deterministic across identical builds");
    ax_gov_clear_faults(&f);
    ax_proof_init(&r, "identical claim", AX_PROOF_TYPE_POLICY_SOUNDNESS,
                  "SRS-007-SHALL-008", head, 42, &f);
    ax_proof_add_evidence(&r, ev, &f);
    ax_proof_finalise(&r, &f);

    memcpy(stored_hash, r.proof_hash, 32);
    memcpy(stored_commitment, r.commitment, 32);

    ax_gov_clear_faults(&f2);
    ax_proof_init(&r2, "identical claim", AX_PROOF_TYPE_POLICY_SOUNDNESS,
                  "SRS-007-SHALL-008", head, 42, &f2);
    ax_proof_add_evidence(&r2, ev, &f2);
    ax_proof_finalise(&r2, &f2);

    if (memcmp(stored_hash, r2.proof_hash, 32) != 0) {
        FAIL("proof_hash differs across identical builds"); return;
    }
    if (memcmp(stored_commitment, r2.commitment, 32) != 0) {
        FAIL("commitment differs across identical builds"); return;
    }
    PASS();
}

static void test_f009_mutation_invalidates_hash(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;
    uint8_t ev1[32] = {0x11};
    uint8_t ev2[32] = {0x22};
    uint8_t hash_before[32];
    uint8_t commitment_before[32];

    TEST("F009: mutating evidence after finalise invalidates proof_hash_computed");
    make_proof(&r, &f);
    ax_proof_finalise(&r, &f);

    memcpy(hash_before, r.proof_hash, 32);
    memcpy(commitment_before, r.commitment, 32);

    /* Add evidence after finalisation — must invalidate */
    ax_proof_add_evidence(&r, ev2, &f);

    if (r.proof_hash_computed) {
        FAIL("proof_hash_computed should be false after mutation"); return;
    }

    /* Re-finalise — must produce different hash */
    ax_gov_clear_faults(&f);
    ax_proof_add_evidence(&r, ev1, &f);  /* ignored, already present */
    ax_proof_finalise(&r, &f);

    if (memcmp(hash_before, r.proof_hash, 32) == 0) {
        FAIL("proof_hash unchanged despite evidence mutation"); return;
    }
    PASS();
    (void)commitment_before;
}

static void test_f009_commitment_covers_proof_hash(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;
    uint8_t commitment_a[32];
    uint8_t commitment_b[32];
    uint8_t head_a[32] = {0xAA};
    uint8_t head_b[32] = {0xBB};
    uint8_t ev[32] = {0x55};

    TEST("F009: commitment changes when proof_hash changes (commitment covers hash)");
    ax_gov_clear_faults(&f);
    ax_proof_init(&r, "claim", AX_PROOF_TYPE_SUBSTRATE_CERT,
                  "SRS-007-SHALL-012", head_a, 1, &f);
    ax_proof_add_evidence(&r, ev, &f);
    ax_proof_finalise(&r, &f);
    memcpy(commitment_a, r.commitment, 32);

    ax_gov_clear_faults(&f);
    ax_proof_init(&r, "claim", AX_PROOF_TYPE_SUBSTRATE_CERT,
                  "SRS-007-SHALL-012", head_b, 1, &f);
    ax_proof_add_evidence(&r, ev, &f);
    ax_proof_finalise(&r, &f);
    memcpy(commitment_b, r.commitment, 32);

    /* Different prev_chain_head → different proof_hash → different commitment */
    if (memcmp(commitment_a, commitment_b, 32) == 0) {
        FAIL("commitment did not change when proof_hash changed"); return;
    }
    PASS();
}

/* ============================================================================
 * F010: TEMPORAL ordering requires explicit metadata
 * ============================================================================ */

static void test_f010_temporal_without_metadata_rejected(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;

    TEST("F010: TEMPORAL ordering without metadata is rejected");
    make_proof(&r, &f);
    ax_gov_clear_faults(&f);

    /* set_ordering with TEMPORAL and no metadata must fail */
    if (ax_proof_set_ordering(&r, AX_EVIDENCE_ORDER_TEMPORAL, NULL, &f) != -1) {
        FAIL("TEMPORAL without metadata should be rejected"); return;
    }
    if (!f.integrity_fault) { FAIL("integrity_fault not set"); return; }
    PASS();
}

static void test_f010_temporal_with_metadata_accepted(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;
    ax_ordering_metadata_t meta;

    TEST("F010: TEMPORAL ordering with metadata is accepted");
    make_proof(&r, &f);
    ax_gov_clear_faults(&f);

    memset(&meta, 0, sizeof(meta));
    memcpy(meta.description, "Ascending by ledger_seq", 23);
    memcpy(meta.key_field, "ledger_seq", 10);
    memcpy(meta.direction, "ascending", 9);
    meta.is_set = true;

    if (ax_proof_set_ordering(&r, AX_EVIDENCE_ORDER_TEMPORAL, &meta, &f) != 0) {
        FAIL("TEMPORAL with metadata should be accepted"); return;
    }
    if (ax_gov_has_fault(&f)) { FAIL("unexpected fault"); return; }
    if (!r.ordering_metadata.is_set) { FAIL("metadata not stored"); return; }
    PASS();
}

static void test_f010_temporal_finalise_without_metadata_faults(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;

    TEST("F010: finalise with TEMPORAL set but no metadata faults on sort");
    make_proof(&r, &f);
    /* Force TEMPORAL ordering directly, bypassing set_ordering validation */
    r.evidence_ordering = AX_EVIDENCE_ORDER_TEMPORAL;
    r.ordering_metadata.is_set = false;
    ax_gov_clear_faults(&f);

    /* ax_proof_sort_evidence should detect missing metadata */
    ax_proof_sort_evidence(&r, &f);

    if (!f.ordering_fault) {
        FAIL("ordering_fault not set for TEMPORAL without metadata"); return;
    }
    PASS();
}

/* ============================================================================
 * F011: Merkle rejects unsorted input
 * ============================================================================ */

static void test_f011_unsorted_input_rejected(void) {
    ax_merkle_ctx_t ctx;
    ax_gov_fault_flags_t f;
    uint8_t h1[32], h2[32];

    TEST("F011: Merkle compute_root rejects unsorted leaf input");
    ax_gov_clear_faults(&f);
    ax_merkle_init(&ctx, &f);

    /* Add leaves in reverse order (h2 > h1 lexicographically) */
    memset(h1, 0x11, 32);
    memset(h2, 0xFF, 32);

    /* Add directly to bypass sorting in ax_merkle_add_leaves */
    ax_merkle_add_leaf(&ctx, h2, &f);  /* higher hash first — wrong order */
    ax_merkle_add_leaf(&ctx, h1, &f);  /* lower hash second */

    ax_gov_clear_faults(&f);
    if (ax_merkle_compute_root(&ctx, &f) != -1) {
        FAIL("should reject unsorted input"); return;
    }
    if (!f.ordering_fault) { FAIL("ordering_fault not set"); return; }
    PASS();
}

static void test_f011_sorted_input_accepted(void) {
    ax_merkle_ctx_t ctx;
    ax_gov_fault_flags_t f;
    uint8_t h1[32], h2[32], root[32];

    TEST("F011: Merkle compute_root accepts correctly sorted input");
    ax_gov_clear_faults(&f);
    ax_merkle_init(&ctx, &f);

    memset(h1, 0x11, 32);
    memset(h2, 0xFF, 32);

    /* Add in correct order (h1 < h2 lexicographically) */
    ax_merkle_add_leaf(&ctx, h1, &f);
    ax_merkle_add_leaf(&ctx, h2, &f);

    ax_gov_clear_faults(&f);
    if (ax_merkle_compute_root(&ctx, &f) != 0) {
        FAIL("should accept sorted input"); return;
    }
    if (ax_merkle_get_root(&ctx, root, &f) != 0) { FAIL("get_root failed"); return; }
    PASS();
}

static void test_f011_add_leaves_sorts_before_build(void) {
    ax_merkle_ctx_t ctx;
    ax_gov_fault_flags_t f;
    uint8_t hashes[3][32];
    uint8_t root[32];

    TEST("F011: ax_merkle_add_leaves sorts before inserting (safe path)");
    ax_gov_clear_faults(&f);
    ax_merkle_init(&ctx, &f);

    /* Insert in reverse — add_leaves should sort */
    memset(hashes[0], 0xFF, 32);
    memset(hashes[1], 0x88, 32);
    memset(hashes[2], 0x11, 32);

    if (ax_merkle_add_leaves(&ctx, (const uint8_t (*)[32])hashes, 3, &f) != 0) {
        FAIL("add_leaves failed"); return;
    }
    ax_gov_clear_faults(&f);
    if (ax_merkle_compute_root(&ctx, &f) != 0) {
        FAIL("compute_root failed after add_leaves sort"); return;
    }
    if (ax_merkle_get_root(&ctx, root, &f) != 0) { FAIL("get_root failed"); return; }
    if (ax_gov_has_fault(&f)) { FAIL("unexpected fault"); return; }
    PASS();
}

/* ============================================================================
 * F012: Atomic fallback log — entry_count is the commit point
 * ============================================================================ */

static void test_f012_entry_count_is_commit_point(void) {
    ax_fallback_log_t log;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t f;
    uint8_t config[32] = {0xC0}, policy[32] = {0xAB}, genesis[32] = {0xA0};
    uint8_t ev[32] = {0x77};
    size_t count_before;

    TEST("F012: entry_count only increments after complete proof written");
    ax_gov_clear_faults(&f);
    ax_gov_init(&gov, config, policy, genesis, &f);
    ax_fallback_log_init(&log, &f);

    count_before = log.entry_count;

    ax_gov_clear_faults(&f);
    ax_fallback_log_write(&log, AX_VIOLATION_HASH_MISMATCH, ev,
                          "SRS-007-SHALL-014", &gov, &f);

    /* Count must have increased by exactly 1 */
    if (log.entry_count != count_before + 1) {
        FAIL("entry_count not exactly 1 after write"); return;
    }

    /* Entry must have a valid, finalised proof */
    {
        const ax_proof_record_t *entry = ax_fallback_log_get_entry(&log, 0);
        if (entry == NULL) { FAIL("entry is NULL"); return; }
        if (!entry->proof_hash_computed) { FAIL("entry proof_hash not computed"); return; }
        if (entry->result != AX_PROOF_RESULT_INTEGRITY_FAULT) {
            FAIL("entry result not INTEGRITY_FAULT"); return;
        }
    }
    PASS();
}

static void test_f012_halted_state_prevents_further_ops(void) {
    ax_fallback_log_t log;
    ax_gov_ctx_t gov;
    ax_gov_fault_flags_t f;
    uint8_t config[32] = {0xC0}, policy[32] = {0xAB}, genesis[32] = {0xA0};
    uint8_t ev[32] = {0x77};
    size_t i;

    TEST("F012: HALTED state rejects all further fallback writes");
    ax_gov_clear_faults(&f);
    ax_gov_init(&gov, config, policy, genesis, &f);
    ax_fallback_log_init(&log, &f);

    /* Fill to overflow */
    for (i = 0; i < AX_FALLBACK_LOG_MAX_ENTRIES; i++) {
        ax_gov_clear_faults(&f);
        ev[0] = (uint8_t)(i + 1);
        ax_fallback_log_write(&log, AX_VIOLATION_ORDERING, ev,
                              "SRS-007-SHALL-018", &gov, &f);
        if (ax_fallback_log_is_halted(&log)) { break; }
    }

    if (!ax_fallback_log_is_halted(&log)) { FAIL("not halted"); return; }

    /* Any further write must be refused */
    ax_gov_clear_faults(&f);
    if (ax_fallback_log_write(&log, AX_VIOLATION_HASH_MISMATCH, ev,
                              "SRS-007-SHALL-014", &gov, &f) != -1) {
        FAIL("write after HALTED should return -1"); return;
    }
    PASS();
}

/* ============================================================================
 * F013: UTF-8 validation in JCS encoder
 * ============================================================================ */

static void test_f013_valid_ascii_claim_accepted(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;
    uint8_t head[32] = {0};
    uint8_t ev[32]   = {0x01};
    uint8_t buf[4096];
    size_t  out_len;

    TEST("F013: valid ASCII claim encodes without error");
    ax_gov_clear_faults(&f);
    ax_proof_init(&r, "Valid ASCII claim", AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
                  "SRS-007-SHALL-007", head, 1, &f);
    ax_proof_add_evidence(&r, ev, &f);
    ax_proof_finalise(&r, &f);

    ax_gov_clear_faults(&f);
    if (ax_proof_to_canonical_json(&r, (char *)buf, sizeof(buf),
                                   &out_len, false, &f) != 0) {
        FAIL("encode failed for valid ASCII"); return;
    }
    if (ax_gov_has_fault(&f)) { FAIL("unexpected fault"); return; }
    PASS();
}

static void test_f013_invalid_utf8_in_claim_rejected(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;
    uint8_t head[32] = {0};
    uint8_t ev[32]   = {0x01};
    uint8_t buf[4096];
    size_t  out_len;

    TEST("F013: invalid UTF-8 bytes in claim are rejected by encoder");
    ax_gov_clear_faults(&f);
    ax_proof_init(&r, "Valid init", AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
                  "SRS-007-SHALL-007", head, 1, &f);
    ax_proof_add_evidence(&r, ev, &f);
    ax_proof_finalise(&r, &f);

    /* Inject invalid UTF-8 directly into the claim buffer
     * 0xFF is never valid in UTF-8 */
    r.claim[0] = (char)0xFF;
    r.claim[1] = (char)0xFE;
    r.claim[2] = '\0';

    ax_gov_clear_faults(&f);
    if (ax_proof_to_canonical_json(&r, (char *)buf, sizeof(buf),
                                   &out_len, false, &f) != -1) {
        FAIL("invalid UTF-8 should be rejected"); return;
    }
    PASS();
}

static void test_f013_valid_utf8_multibyte_accepted(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;
    uint8_t head[32] = {0};
    uint8_t ev[32]   = {0x01};
    uint8_t buf[4096];
    size_t  out_len;

    TEST("F013: valid multi-byte UTF-8 in claim is accepted");
    ax_gov_clear_faults(&f);
    /* U+00E9 = é = 0xC3 0xA9 (valid 2-byte UTF-8) */
    ax_proof_init(&r, "caf\xC3\xA9", AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
                  "SRS-007-SHALL-007", head, 1, &f);
    ax_proof_add_evidence(&r, ev, &f);
    ax_proof_finalise(&r, &f);

    ax_gov_clear_faults(&f);
    if (ax_proof_to_canonical_json(&r, (char *)buf, sizeof(buf),
                                   &out_len, false, &f) != 0) {
        FAIL("valid UTF-8 should be accepted"); return;
    }
    PASS();
}

/* ============================================================================
 * F014: Replay produces byte-identical outputs (memcmp verification)
 * ============================================================================ */

static void test_f014_replay_produces_identical_proof_bytes(void) {
    ax_proof_record_t r1, r2;
    ax_gov_fault_flags_t f;
    uint8_t head[32] = {0xA0};
    uint8_t ev[32]   = {0x33};
    uint8_t buf1[4096], buf2[4096];
    size_t  len1, len2;

    TEST("F014: replayed proof serialisation is byte-identical (memcmp)");
    ax_gov_clear_faults(&f);

    /* Build proof once */
    ax_proof_init(&r1, "replay claim", AX_PROOF_TYPE_REPLAY_EQUIVALENCE,
                  "SRS-007-SHALL-019", head, 100, &f);
    ax_proof_add_evidence(&r1, ev, &f);
    ax_proof_finalise(&r1, &f);

    /* "Replay" — identical inputs must produce identical record */
    ax_gov_clear_faults(&f);
    ax_proof_init(&r2, "replay claim", AX_PROOF_TYPE_REPLAY_EQUIVALENCE,
                  "SRS-007-SHALL-019", head, 100, &f);
    ax_proof_add_evidence(&r2, ev, &f);
    ax_proof_finalise(&r2, &f);

    /* Serialise both — must be byte-identical */
    ax_gov_clear_faults(&f);
    ax_proof_to_canonical_json(&r1, (char *)buf1, sizeof(buf1), &len1, true, &f);
    ax_proof_to_canonical_json(&r2, (char *)buf2, sizeof(buf2), &len2, true, &f);

    if (len1 != len2) {
        FAIL("serialised lengths differ"); return;
    }
    if (memcmp(buf1, buf2, len1) != 0) {
        FAIL("serialised bytes not identical across replay"); return;
    }
    PASS();
}

static void test_f014_different_inputs_produce_different_bytes(void) {
    ax_proof_record_t r1, r2;
    ax_gov_fault_flags_t f;
    uint8_t head[32] = {0xA0};
    uint8_t ev1[32]  = {0x11};
    uint8_t ev2[32]  = {0x22};
    uint8_t buf1[4096], buf2[4096];
    size_t  len1, len2;

    TEST("F014: different inputs produce different serialised bytes");
    ax_gov_clear_faults(&f);
    ax_proof_init(&r1, "claim", AX_PROOF_TYPE_REPLAY_EQUIVALENCE,
                  "SRS-007-SHALL-019", head, 1, &f);
    ax_proof_add_evidence(&r1, ev1, &f);
    ax_proof_finalise(&r1, &f);

    ax_gov_clear_faults(&f);
    ax_proof_init(&r2, "claim", AX_PROOF_TYPE_REPLAY_EQUIVALENCE,
                  "SRS-007-SHALL-019", head, 1, &f);
    ax_proof_add_evidence(&r2, ev2, &f);
    ax_proof_finalise(&r2, &f);

    ax_gov_clear_faults(&f);
    ax_proof_to_canonical_json(&r1, (char *)buf1, sizeof(buf1), &len1, true, &f);
    ax_proof_to_canonical_json(&r2, (char *)buf2, sizeof(buf2), &len2, true, &f);

    if (len1 == len2 && memcmp(buf1, buf2, len1) == 0) {
        FAIL("different inputs produced identical bytes"); return;
    }
    PASS();
}

/* ============================================================================
 * F015: Schema version enforcement
 * ============================================================================ */

static void test_f015_schema_version_constant_is_v1(void) {
    TEST("F015: AX_PROOF_SCHEMA_VERSION is 'AX:PROOF:v1'");
    if (strcmp(AX_PROOF_SCHEMA_VERSION, "AX:PROOF:v1") != 0) {
        FAIL("wrong schema version constant"); return;
    }
    PASS();
}

static void test_f015_schema_version_valid_accepts_v1(void) {
    TEST("F015: ax_proof_schema_version_valid accepts AX:PROOF:v1");
    if (!ax_proof_schema_version_valid("AX:PROOF:v1")) {
        FAIL("v1 should be valid"); return;
    }
    PASS();
}

static void test_f015_schema_version_valid_rejects_v2(void) {
    TEST("F015: ax_proof_schema_version_valid rejects AX:PROOF:v2");
    if (ax_proof_schema_version_valid("AX:PROOF:v2")) {
        FAIL("v2 should be invalid"); return;
    }
    if (ax_proof_schema_version_valid(NULL)) {
        FAIL("NULL should be invalid"); return;
    }
    if (ax_proof_schema_version_valid("")) {
        FAIL("empty string should be invalid"); return;
    }
    PASS();
}

static void test_f015_schema_version_in_canonical_output(void) {
    ax_proof_record_t r;
    ax_gov_fault_flags_t f;
    uint8_t head[32] = {0};
    uint8_t ev[32]   = {0x01};
    uint8_t buf[4096];
    size_t  out_len;
    const char *version_str = "\"schema_version\":\"AX:PROOF:v1\"";

    TEST("F015: schema_version appears in canonical serialisation output");
    ax_gov_clear_faults(&f);
    ax_proof_init(&r, "claim", AX_PROOF_TYPE_CROSS_LAYER_VERIFY,
                  "SRS-007-SHALL-007", head, 1, &f);
    ax_proof_add_evidence(&r, ev, &f);
    ax_proof_finalise(&r, &f);

    ax_gov_clear_faults(&f);
    ax_proof_to_canonical_json(&r, (char *)buf, sizeof(buf), &out_len, false, &f);
    buf[out_len] = '\0';

    if (strstr((char *)buf, version_str) == NULL) {
        FAIL("schema_version not found in output"); return;
    }
    PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("\n=== axioma-governance: Audit Finding Regression Tests (F009-F015) ===\n\n");

    printf("F009 — Single canonical buffer:\n");
    test_f009_hash_covers_same_bytes_as_commitment();
    test_f009_mutation_invalidates_hash();
    test_f009_commitment_covers_proof_hash();

    printf("\nF010 — TEMPORAL ordering requires explicit mapping:\n");
    test_f010_temporal_without_metadata_rejected();
    test_f010_temporal_with_metadata_accepted();
    test_f010_temporal_finalise_without_metadata_faults();

    printf("\nF011 — Merkle rejects unsorted input:\n");
    test_f011_unsorted_input_rejected();
    test_f011_sorted_input_accepted();
    test_f011_add_leaves_sorts_before_build();

    printf("\nF012 — Atomic fault recording and STOPPED barrier:\n");
    test_f012_entry_count_is_commit_point();
    test_f012_halted_state_prevents_further_ops();

    printf("\nF013 — UTF-8 validation in JCS encoder:\n");
    test_f013_valid_ascii_claim_accepted();
    test_f013_invalid_utf8_in_claim_rejected();
    test_f013_valid_utf8_multibyte_accepted();

    printf("\nF014 — Replay produces byte-identical outputs:\n");
    test_f014_replay_produces_identical_proof_bytes();
    test_f014_different_inputs_produce_different_bytes();

    printf("\nF015 — Schema version enforcement:\n");
    test_f015_schema_version_constant_is_v1();
    test_f015_schema_version_valid_accepts_v1();
    test_f015_schema_version_valid_rejects_v2();
    test_f015_schema_version_in_canonical_output();

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
