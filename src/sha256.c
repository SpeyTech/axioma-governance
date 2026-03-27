/**
 * @file sha256.c
 * @brief SHA-256 Implementation — DVM Substrate Primitive
 *
 * DVEC: v1.3
 * DETERMINISM: D1 — Strict Deterministic
 * MEMORY: Zero Dynamic Allocation
 * LAYER: L1 — Substrate (delegated to L7)
 * SRS: SRS-005 v1.1
 *
 * Pure C99 SHA-256 implementation with no dynamic allocation.
 * Bit-identical across all platforms.
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 *            All rights reserved.
 * @license GPL-3.0-or-later
 * @patent UK GB2521625.0
 *
 * @traceability SRS-005-SHALL-070: SHA-256 implementation
 */

#include "axilog/types.h"
#include <string.h>

/*
 * ============================================================================
 * SHA-256 Constants
 * ============================================================================
 */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/*
 * ============================================================================
 * Helper Functions
 * ============================================================================
 */

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32U - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sigma0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline uint32_t sigma1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline uint32_t gamma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline uint32_t gamma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

/**
 * @brief Process a single 512-bit block
 *
 * @traceability SRS-005-SHALL-070
 */
static void sha256_transform(ax_sha256_ctx_t *ctx, const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    size_t i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8)  |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
    }

    /* Initialise working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Compression function */
    for (i = 0; i < 64; i++) {
        t1 = h + sigma1(e) + ch(e, f, g) + K[i] + W[i];
        t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Update state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

/*
 * ============================================================================
 * Public API
 * ============================================================================
 */

/**
 * @brief Initialise SHA-256 context
 *
 * @param ctx Context to initialise
 *
 * @traceability SRS-005-SHALL-070
 */
void ax_sha256_init(ax_sha256_ctx_t *ctx) {
    memcpy(ctx->state, H0, sizeof(H0));
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

/**
 * @brief Update SHA-256 with data
 *
 * @param ctx Context
 * @param data Input data
 * @param len Data length in bytes
 *
 * @traceability SRS-005-SHALL-070
 */
void ax_sha256_update(ax_sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t buf_pos = (size_t)(ctx->count & 63);
    size_t remaining = len;
    size_t to_copy;

    ctx->count += len;

    /* Fill buffer and process if full */
    while (remaining > 0) {
        to_copy = 64 - buf_pos;
        if (to_copy > remaining) {
            to_copy = remaining;
        }

        memcpy(ctx->buffer + buf_pos, data, to_copy);
        buf_pos += to_copy;
        data += to_copy;
        remaining -= to_copy;

        if (buf_pos == 64) {
            sha256_transform(ctx, ctx->buffer);
            buf_pos = 0;
        }
    }
}

/**
 * @brief Finalise SHA-256 and produce digest
 *
 * @param ctx Context
 * @param digest Output buffer (32 bytes)
 *
 * @traceability SRS-005-SHALL-070
 */
void ax_sha256_final(ax_sha256_ctx_t *ctx, uint8_t digest[32]) {
    size_t buf_pos = (size_t)(ctx->count & 63);
    uint64_t bit_count = ctx->count * 8;
    size_t i;

    /* Pad with 0x80 */
    ctx->buffer[buf_pos++] = 0x80;

    /* Need new block if not enough space for length */
    if (buf_pos > 56) {
        memset(ctx->buffer + buf_pos, 0, 64 - buf_pos);
        sha256_transform(ctx, ctx->buffer);
        buf_pos = 0;
    }

    /* Pad with zeros */
    memset(ctx->buffer + buf_pos, 0, 56 - buf_pos);

    /* Append length in big-endian */
    ctx->buffer[56] = (uint8_t)(bit_count >> 56);
    ctx->buffer[57] = (uint8_t)(bit_count >> 48);
    ctx->buffer[58] = (uint8_t)(bit_count >> 40);
    ctx->buffer[59] = (uint8_t)(bit_count >> 32);
    ctx->buffer[60] = (uint8_t)(bit_count >> 24);
    ctx->buffer[61] = (uint8_t)(bit_count >> 16);
    ctx->buffer[62] = (uint8_t)(bit_count >> 8);
    ctx->buffer[63] = (uint8_t)(bit_count);

    sha256_transform(ctx, ctx->buffer);

    /* Output digest in big-endian */
    for (i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/**
 * @brief Compute SHA-256 in one call
 *
 * @param data Input data
 * @param len Data length in bytes
 * @param digest Output buffer (32 bytes)
 *
 * @traceability SRS-005-SHALL-070
 */
void ax_sha256(const uint8_t *data, size_t len, uint8_t digest[32]) {
    ax_sha256_ctx_t ctx;
    ax_sha256_init(&ctx);
    ax_sha256_update(&ctx, data, len);
    ax_sha256_final(&ctx, digest);
}
