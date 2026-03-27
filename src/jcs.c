/**
 * @file jcs.c
 * @brief RFC 8785 JSON Canonicalization Scheme (JCS) Encoder
 *
 * DVEC: v1.3
 * DETERMINISM: D1 — Strict Deterministic
 * MEMORY: Zero Dynamic Allocation
 * LAYER: L7 — Governance
 * SRS: SRS-007 v0.3 Audit-Frozen FINAL
 *
 * Implements strict RFC 8785 canonical JSON encoding with:
 * - Deterministic key ordering (lexicographic by UTF-8 bytes)
 * - Canonical number formatting (no insignificant digits)
 * - Canonical string escaping (only required escapes)
 * - No whitespace
 * - UTF-8 byte-level operations
 *
 * This module operates on byte buffers (uint8_t*), never C strings,
 * to guarantee byte-exact encoding.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-007-SHALL-007: Canonical format (RFC 8785)
 * @traceability SRS-007-SHALL-022: Trace canonicality
 * @traceability SRS-007-SHALL-039: Source code traceability
 * @traceability SRS-007-SHALL-040: Test traceability
 * @traceability SRS-007-SHALL-045: Proof hash computation
 */

#include "ax_jcs.h"
#include "ax_proof.h"
#include "ax_trace.h"
#include <string.h>

/*
 * ============================================================================
 * JCS Writer Context
 * ============================================================================
 */

/**
 * @brief JCS writer context for building canonical JSON
 *
 * All operations are byte-exact. The writer tracks:
 * - Output buffer and capacity
 * - Current write position
 * - Overflow flag (hard failure, no partial output)
 */
typedef struct {
    uint8_t *buf;           /**< Output buffer (byte array, not C string) */
    size_t   cap;           /**< Buffer capacity in bytes */
    size_t   pos;           /**< Current write position */
    bool     overflow;      /**< True if any write would exceed capacity */
} jcs_writer_t;

/*
 * ============================================================================
 * Internal Writer Operations
 * ============================================================================
 */

/**
 * @brief Initialise JCS writer
 */
static void jcs_init(jcs_writer_t *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->pos = 0;
    w->overflow = false;
}

/**
 * @brief Write a single byte
 *
 * Sets overflow flag if capacity exceeded. Never writes partial output.
 */
static void jcs_write_byte(jcs_writer_t *w, uint8_t b) {
    if (w->overflow) return;
    if (w->pos >= w->cap) {
        w->overflow = true;
        return;
    }
    w->buf[w->pos++] = b;
}

/**
 * @brief Write multiple bytes
 */
static void jcs_write_bytes(jcs_writer_t *w, const uint8_t *data, size_t len) {
    size_t i;
    if (w->overflow) return;
    if (w->pos + len > w->cap) {
        w->overflow = true;
        return;
    }
    for (i = 0; i < len; i++) {
        w->buf[w->pos++] = data[i];
    }
}

/**
 * @brief Write ASCII string (compile-time literals only)
 */
static void jcs_write_ascii(jcs_writer_t *w, const char *s) {
    while (*s) {
        jcs_write_byte(w, (uint8_t)*s++);
    }
}

/*
 * ============================================================================
 * RFC 8785 String Escaping
 * ============================================================================
 *
 * Per RFC 8785 Section 3.2.2.2:
 * - Backspace       -> \b
 * - Horizontal tab  -> \t
 * - Newline         -> \n
 * - Form feed       -> \f
 * - Carriage return -> \r
 * - Quotation mark  -> \"
 * - Reverse solidus -> \\
 * - Control chars (U+0000-U+001F except above) -> \uXXXX
 *
 * All other characters (including non-ASCII UTF-8) pass through unchanged.
 */

/**
 * @brief Write a JSON-escaped string per RFC 8785
 *
 * @param w Writer context
 * @param data UTF-8 byte sequence
 * @param len Length in bytes
 *
 * @traceability SRS-007-SHALL-007: Canonical string escaping
 */
static void jcs_write_string(jcs_writer_t *w, const uint8_t *data, size_t len) {
    static const char HEX[] = "0123456789abcdef";
    size_t i;

    jcs_write_byte(w, '"');

    for (i = 0; i < len; i++) {
        uint8_t c = data[i];

        if (c == '"') {
            jcs_write_byte(w, '\\');
            jcs_write_byte(w, '"');
        } else if (c == '\\') {
            jcs_write_byte(w, '\\');
            jcs_write_byte(w, '\\');
        } else if (c == '\b') {
            jcs_write_byte(w, '\\');
            jcs_write_byte(w, 'b');
        } else if (c == '\t') {
            jcs_write_byte(w, '\\');
            jcs_write_byte(w, 't');
        } else if (c == '\n') {
            jcs_write_byte(w, '\\');
            jcs_write_byte(w, 'n');
        } else if (c == '\f') {
            jcs_write_byte(w, '\\');
            jcs_write_byte(w, 'f');
        } else if (c == '\r') {
            jcs_write_byte(w, '\\');
            jcs_write_byte(w, 'r');
        } else if (c < 0x20) {
            /* Control character: \uXXXX */
            jcs_write_byte(w, '\\');
            jcs_write_byte(w, 'u');
            jcs_write_byte(w, '0');
            jcs_write_byte(w, '0');
            jcs_write_byte(w, (uint8_t)HEX[(c >> 4) & 0x0F]);
            jcs_write_byte(w, (uint8_t)HEX[c & 0x0F]);
        } else {
            /* Regular character or UTF-8 continuation byte */
            jcs_write_byte(w, c);
        }
    }

    jcs_write_byte(w, '"');
}

/**
 * @brief Write a C string as JSON string (null-terminated input)
 */
static void jcs_write_cstring(jcs_writer_t *w, const char *s) {
    jcs_write_string(w, (const uint8_t *)s, strlen(s));
}

/*
 * ============================================================================
 * RFC 8785 Number Formatting
 * ============================================================================
 *
 * Per RFC 8785 Section 3.2.2.3:
 * - No leading zeros (except "0" itself)
 * - No trailing zeros in fractional part
 * - No unnecessary decimal point
 * - No + sign for positive numbers
 * - Exponential notation only when required
 *
 * For our use case (uint64_t ledger sequences), we only need unsigned integers.
 */

/**
 * @brief Write uint64_t as canonical JSON number
 *
 * @traceability SRS-007-SHALL-007: Canonical number formatting
 */
static void jcs_write_uint64(jcs_writer_t *w, uint64_t value) {
    char digits[21];  /* Max uint64 is 20 digits + null */
    int i = 0;
    int j;

    if (value == 0) {
        jcs_write_byte(w, '0');
        return;
    }

    /* Extract digits in reverse order */
    while (value > 0) {
        digits[i++] = (char)('0' + (value % 10));
        value /= 10;
    }

    /* Write in correct order */
    for (j = i - 1; j >= 0; j--) {
        jcs_write_byte(w, (uint8_t)digits[j]);
    }
}

/*
 * ============================================================================
 * Hex Encoding (for hash values)
 * ============================================================================
 */

/**
 * @brief Write 32-byte hash as lowercase hex string
 *
 * @traceability SRS-007-SHALL-046: Evidence reference encoding
 */
static void jcs_write_hash_hex(jcs_writer_t *w, const uint8_t hash[32]) {
    static const char HEX[] = "0123456789abcdef";
    int i;

    jcs_write_byte(w, '"');
    for (i = 0; i < 32; i++) {
        jcs_write_byte(w, (uint8_t)HEX[(hash[i] >> 4) & 0x0F]);
        jcs_write_byte(w, (uint8_t)HEX[hash[i] & 0x0F]);
    }
    jcs_write_byte(w, '"');
}

/*
 * ============================================================================
 * JCS Object/Array Helpers
 * ============================================================================
 */

static void jcs_object_start(jcs_writer_t *w) {
    jcs_write_byte(w, '{');
}

static void jcs_object_end(jcs_writer_t *w) {
    jcs_write_byte(w, '}');
}

static void jcs_array_start(jcs_writer_t *w) {
    jcs_write_byte(w, '[');
}

static void jcs_array_end(jcs_writer_t *w) {
    jcs_write_byte(w, ']');
}

static void jcs_comma(jcs_writer_t *w) {
    jcs_write_byte(w, ',');
}

static void jcs_colon(jcs_writer_t *w) {
    jcs_write_byte(w, ':');
}

static void jcs_null(jcs_writer_t *w) {
    jcs_write_ascii(w, "null");
}

/**
 * @brief Write a key (for object members)
 */
static void jcs_key(jcs_writer_t *w, const char *key) {
    jcs_write_cstring(w, key);
    jcs_colon(w);
}

/*
 * ============================================================================
 * Implementation — Proof Serialisation
 * ============================================================================
 */

/* String tables for enum serialisation */
static const char *JCS_PROOF_TYPE_STRINGS[] = {
    "ANCHOR_PUBLICATION",
    "COMPLIANCE_SUMMARY",
    "CROSS_LAYER_VERIFY",
    "POLICY_SOUNDNESS",
    "REPLAY_EQUIVALENCE",
    "SUBSTRATE_CERT",
    "WEIGHT_BINDING"
};

static const char *JCS_ORDERING_STRINGS[] = {
    "LEX",
    "TEMPORAL",
    "DECLARED"
};

static const char *JCS_RESULT_STRINGS[] = {
    "VALID",
    "INVALID",
    "INTEGRITY_FAULT"
};

static const char *JCS_VIOLATION_STRINGS[] = {
    "NONE",
    "HASH_MISMATCH",
    "ORDERING",
    "WEIGHT_MISMATCH",
    "POLICY_BREACH",
    "TRANSITION_FAULT",
    "EVIDENCE_MISSING",
    "REPLAY_MISMATCH",
    "FALLBACK_OVERFLOW"
};

static const char *JCS_POLICY_RESULT_STRINGS[] = {
    "PERMITTED",
    "BREACH"
};

static const char *JCS_AGENT_STATE_STRINGS[] = {
    "HEALTHY",
    "ALARM",
    "STOPPED",
    "FAILED"
};

int jcs_proof_to_canonical(
    const ax_proof_record_t *record,
    uint8_t                 *buffer,
    size_t                   buffer_size,
    size_t                  *out_size,
    bool                     include_proof_hash,
    ax_gov_fault_flags_t    *faults
) {
    jcs_writer_t w;
    size_t i;

    if (record == NULL || buffer == NULL || out_size == NULL || faults == NULL) {
        return -1;
    }

    jcs_init(&w, buffer, buffer_size);

    /* Object start */
    jcs_object_start(&w);

    /* claim */
    jcs_key(&w, "claim");
    jcs_write_cstring(&w, record->claim);
    jcs_comma(&w);

    /* commitment */
    jcs_key(&w, "commitment");
    jcs_write_hash_hex(&w, record->commitment);
    jcs_comma(&w);

    /* evidence_ordering */
    jcs_key(&w, "evidence_ordering");
    jcs_write_cstring(&w, JCS_ORDERING_STRINGS[record->evidence_ordering]);
    jcs_comma(&w);

    /* evidence_refs */
    jcs_key(&w, "evidence_refs");
    jcs_array_start(&w);
    for (i = 0; i < record->evidence_refs_count; i++) {
        if (i > 0) jcs_comma(&w);
        jcs_write_hash_hex(&w, record->evidence_refs[i]);
    }
    jcs_array_end(&w);
    jcs_comma(&w);

    /* ledger_seq */
    jcs_key(&w, "ledger_seq");
    jcs_write_uint64(&w, record->ledger_seq);
    jcs_comma(&w);

    /* ordering_metadata */
    jcs_key(&w, "ordering_metadata");
    if (record->ordering_metadata.is_set) {
        /* Nested object with lexicographic key order: description, direction, key_field */
        jcs_object_start(&w);
        jcs_key(&w, "description");
        jcs_write_cstring(&w, record->ordering_metadata.description);
        jcs_comma(&w);
        jcs_key(&w, "direction");
        jcs_write_cstring(&w, record->ordering_metadata.direction);
        jcs_comma(&w);
        jcs_key(&w, "key_field");
        jcs_write_cstring(&w, record->ordering_metadata.key_field);
        jcs_object_end(&w);
    } else {
        jcs_null(&w);
    }
    jcs_comma(&w);

    /* prev_chain_head */
    jcs_key(&w, "prev_chain_head");
    jcs_write_hash_hex(&w, record->prev_chain_head);

    /* proof_hash — OMIT entirely when not including (SRS-007-SHALL-045) */
    if (include_proof_hash && record->proof_hash_computed) {
        jcs_comma(&w);
        jcs_key(&w, "proof_hash");
        jcs_write_hash_hex(&w, record->proof_hash);
    }
    /* Note: No comma/field if proof_hash not included */

    jcs_comma(&w);

    /* proof_type */
    jcs_key(&w, "proof_type");
    jcs_write_cstring(&w, JCS_PROOF_TYPE_STRINGS[record->proof_type]);
    jcs_comma(&w);

    /* result */
    jcs_key(&w, "result");
    jcs_write_cstring(&w, JCS_RESULT_STRINGS[record->result]);
    jcs_comma(&w);

    /* rule_id */
    jcs_key(&w, "rule_id");
    jcs_write_cstring(&w, record->rule_id);
    jcs_comma(&w);

    /* schema_version */
    jcs_key(&w, "schema_version");
    jcs_write_cstring(&w, "AX:PROOF:v1");
    jcs_comma(&w);

    /* violation */
    jcs_key(&w, "violation");
    if (record->violation == AX_VIOLATION_NONE) {
        jcs_null(&w);
    } else {
        jcs_write_cstring(&w, JCS_VIOLATION_STRINGS[record->violation]);
    }

    /* Object end */
    jcs_object_end(&w);

    /* Check for overflow */
    if (w.overflow) {
        faults->overflow = 1;
        return -1;
    }

    *out_size = w.pos;
    return 0;
}

/*
 * ============================================================================
 * Implementation — Trace Serialisation
 * ============================================================================
 */

int jcs_trace_to_canonical(
    const ax_math_trace_t   *trace,
    uint8_t                 *buffer,
    size_t                   buffer_size,
    size_t                  *out_size,
    bool                     include_trace_hash,
    ax_gov_fault_flags_t    *faults
) {
    jcs_writer_t w;
    size_t i;

    if (trace == NULL || buffer == NULL || out_size == NULL || faults == NULL) {
        return -1;
    }

    jcs_init(&w, buffer, buffer_size);

    /* Object start */
    jcs_object_start(&w);

    /* chain_head */
    jcs_key(&w, "chain_head");
    jcs_write_hash_hex(&w, trace->chain_head);
    jcs_comma(&w);

    /* obs_hash */
    jcs_key(&w, "obs_hash");
    jcs_write_hash_hex(&w, trace->obs_hash);
    jcs_comma(&w);

    /* obs_ledger_seq */
    jcs_key(&w, "obs_ledger_seq");
    jcs_write_uint64(&w, trace->obs_ledger_seq);
    jcs_comma(&w);

    /* policy_results */
    jcs_key(&w, "policy_results");
    jcs_array_start(&w);
    for (i = 0; i < trace->policy_results_count; i++) {
        if (i > 0) jcs_comma(&w);
        jcs_write_cstring(&w, JCS_POLICY_RESULT_STRINGS[trace->policy_results[i]]);
    }
    jcs_array_end(&w);
    jcs_comma(&w);

    /* policy_seqs */
    jcs_key(&w, "policy_seqs");
    jcs_array_start(&w);
    for (i = 0; i < trace->policy_seqs_count; i++) {
        if (i > 0) jcs_comma(&w);
        jcs_write_uint64(&w, trace->policy_seqs[i]);
    }
    jcs_array_end(&w);
    jcs_comma(&w);

    /* proof_ledger_seq */
    jcs_key(&w, "proof_ledger_seq");
    jcs_write_uint64(&w, trace->proof_ledger_seq);

    /* trace_hash — OMIT entirely when not including (SRS-007-SHALL-050) */
    if (include_trace_hash && trace->trace_hash_computed) {
        jcs_comma(&w);
        jcs_key(&w, "trace_hash");
        jcs_write_hash_hex(&w, trace->trace_hash);
    }

    jcs_comma(&w);

    /* trans_ledger_seq */
    jcs_key(&w, "trans_ledger_seq");
    jcs_write_uint64(&w, trace->trans_ledger_seq);
    jcs_comma(&w);

    /* trans_next_state */
    jcs_key(&w, "trans_next_state");
    jcs_write_cstring(&w, JCS_AGENT_STATE_STRINGS[trace->trans_next_state]);
    jcs_comma(&w);

    /* weight_hash */
    jcs_key(&w, "weight_hash");
    jcs_write_hash_hex(&w, trace->weight_hash);

    /* Object end */
    jcs_object_end(&w);

    /* Check for overflow */
    if (w.overflow) {
        faults->overflow = 1;
        return -1;
    }

    *out_size = w.pos;
    return 0;
}
