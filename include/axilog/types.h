/**
 * @file axilog/types.h
 * @brief Axilog Core Types — Delegated from libaxilog (L1)
 *
 * DVEC: v1.3
 * DETERMINISM: D1 — Strict Deterministic
 * MEMORY: Zero Dynamic Allocation
 * LAYER: L1 — Substrate
 * SRS: SRS-005 v1.1 (libaxilog)
 *
 * This header provides core types from the libaxilog substrate layer.
 * It is delegated here for L7 governance to use without requiring full
 * libaxilog linkage during development.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-005-SHALL-001: Q16.16 fixed-point type
 */

#ifndef AXILOG_TYPES_H
#define AXILOG_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * ============================================================================
 * Fixed-Point Types (Q16.16)
 * ============================================================================
 */

/**
 * @brief Q16.16 fixed-point type
 *
 * 32-bit signed integer with 16 fractional bits.
 * Range: [-32768.0, +32767.99998474121]
 *
 * @traceability SRS-005-SHALL-001
 */
typedef int32_t fixed_t;

/**
 * @brief Fixed-point constants
 *
 * @traceability SRS-005-SHALL-001
 */
#define FIXED_SHIFT   16
#define FIXED_ONE     (1 << FIXED_SHIFT)        /* 65536 = 0x00010000 */
#define FIXED_HALF    (1 << (FIXED_SHIFT - 1))  /* 32768 = 0x00008000 */
#define FIXED_MAX     INT32_MAX                 /* 0x7FFFFFFF */
#define FIXED_MIN     INT32_MIN                 /* 0x80000000 */
#define FIXED_EPS     1                         /* 0x00000001 */

/*
 * ============================================================================
 * Fault Flags
 * ============================================================================
 */

/**
 * @brief Certifiable fault flags (ct_ prefix for certifiable-* ecosystem)
 *
 * @traceability SRS-005-SHALL-002: Fault propagation
 */
typedef struct {
    uint32_t overflow    : 1;  /**< Saturated high */
    uint32_t underflow   : 1;  /**< Saturated low */
    uint32_t div_zero    : 1;  /**< Division by zero */
    uint32_t domain      : 1;  /**< Invalid input domain */
    uint32_t precision   : 1;  /**< Precision loss detected */
    uint32_t _reserved   : 27;
} ct_fault_flags_t;

/**
 * @brief Check if any fault flag is set
 *
 * @param f Pointer to fault flags
 * @return true if any fault is set
 *
 * @traceability SRS-005-SHALL-002
 */
static inline bool ct_has_fault(const ct_fault_flags_t *f) {
    return f->overflow || f->underflow || f->div_zero ||
           f->domain || f->precision;
}

/**
 * @brief Clear all fault flags
 *
 * @param f Pointer to fault flags
 *
 * @traceability SRS-005-SHALL-002
 */
static inline void ct_clear_faults(ct_fault_flags_t *f) {
    f->overflow = 0;
    f->underflow = 0;
    f->div_zero = 0;
    f->domain = 0;
    f->precision = 0;
}

/*
 * ============================================================================
 * SHA-256 Types
 * ============================================================================
 */

/**
 * @brief SHA-256 context
 *
 * @traceability SRS-005-SHALL-070: SHA-256 implementation
 */
typedef struct {
    uint32_t state[8];      /**< Hash state */
    uint64_t count;         /**< Total bytes processed */
    uint8_t  buffer[64];    /**< Message block buffer */
} ax_sha256_ctx_t;

/**
 * @brief Initialise SHA-256 context
 *
 * @param ctx Context to initialise
 *
 * @traceability SRS-005-SHALL-070: SHA-256 implementation
 */
void ax_sha256_init(ax_sha256_ctx_t *ctx);

/**
 * @brief Update SHA-256 with data
 *
 * @param ctx Context
 * @param data Input data
 * @param len Data length in bytes
 *
 * @traceability SRS-005-SHALL-070: SHA-256 implementation
 */
void ax_sha256_update(ax_sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalise SHA-256 and produce digest
 *
 * @param ctx Context
 * @param digest Output buffer (32 bytes)
 *
 * @traceability SRS-005-SHALL-070: SHA-256 implementation
 */
void ax_sha256_final(ax_sha256_ctx_t *ctx, uint8_t digest[32]);

/**
 * @brief Compute SHA-256 in one call
 *
 * @param data Input data
 * @param len Data length in bytes
 * @param digest Output buffer (32 bytes)
 *
 * @traceability SRS-005-SHALL-070: SHA-256 implementation
 */
void ax_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

/*
 * ============================================================================
 * Evidence Types
 * ============================================================================
 */

/**
 * @brief Domain separation tags (DVEC-001 §4.4)
 *
 * Evidence type tags — typed evidence records committed to the ledger
 *
 * @traceability DVEC-001 §4.4: Domain Separation Registry
 */
#define AX_TAG_STATE   "AX:STATE:v1"    /**< State commitment */
#define AX_TAG_TRANS   "AX:TRANS:v1"    /**< Transition commitment */
#define AX_TAG_OBS     "AX:OBS:v1"      /**< Observation record */
#define AX_TAG_POLICY  "AX:POLICY:v1"   /**< Policy assertion */
#define AX_TAG_PROOF   "AX:PROOF:v1"    /**< Verification proof */

/**
 * @brief Chain tags — ledger protocol prefixes
 *
 * @traceability DVEC-001 §4.4: Domain Separation Registry
 */
#define AX_TAG_LEDGER  "AX:LEDGER:v1"   /**< Axioma hash chain */

/**
 * @brief Anchor tag for external anchoring
 *
 * @traceability SRS-007-SHALL-030: Anchor computation
 */
#define AX_TAG_ANCHOR  "AX:ANCHOR:v1"   /**< External anchor */

#ifdef __cplusplus
}
#endif

#endif /* AXILOG_TYPES_H */
