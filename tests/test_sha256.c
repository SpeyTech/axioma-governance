/**
 * @file test_sha256.c
 * @brief SHA-256 Implementation Tests
 *
 * @copyright Copyright (C) 2026 The Murray Family Innovation Trust.
 * @license GPL-3.0-or-later
 *
 * @traceability SRS-005-SHALL-070: SHA-256 implementation
 * @traceability SRS-007-SHALL-001: Cross-platform bit-identical execution
 * @traceability SRS-007-SHALL-002: Deterministic algorithm selection
 * @traceability SRS-007-SHALL-040: Test traceability
 */

#include "axilog/types.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  TEST: %s ... ", name)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    static const char HEX[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i*2] = HEX[(bytes[i] >> 4) & 0x0F];
        hex[i*2+1] = HEX[bytes[i] & 0x0F];
    }
    hex[len*2] = '\0';
}

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(hex + i*2, "%2x", &b) != 1) return -1;
        bytes[i] = (uint8_t)b;
    }
    return 0;
}

/* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
static void test_empty(void) {
    uint8_t digest[32], expected[32];
    char hex[65];
    TEST("SHA-256 empty string");
    ax_sha256((const uint8_t*)"", 0, digest);
    hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", expected, 32);
    if (memcmp(digest, expected, 32) != 0) {
        bytes_to_hex(digest, 32, hex);
        printf("FAIL: got %s\n", hex);
        tests_failed++;
    } else PASS();
}

/* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
static void test_abc(void) {
    uint8_t digest[32], expected[32];
    TEST("SHA-256 'abc'");
    ax_sha256((const uint8_t*)"abc", 3, digest);
    hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expected, 32);
    if (memcmp(digest, expected, 32) != 0) FAIL("hash mismatch"); else PASS();
}

/* Test incremental hashing */
static void test_incremental(void) {
    ax_sha256_ctx_t ctx;
    uint8_t d1[32], d2[32];
    const char *msg = "The quick brown fox jumps over the lazy dog";
    TEST("SHA-256 incremental");
    ax_sha256((const uint8_t*)msg, strlen(msg), d1);
    ax_sha256_init(&ctx);
    ax_sha256_update(&ctx, (const uint8_t*)msg, 10);
    ax_sha256_update(&ctx, (const uint8_t*)(msg+10), strlen(msg)-10);
    ax_sha256_final(&ctx, d2);
    if (memcmp(d1, d2, 32) != 0) FAIL("incremental differs"); else PASS();
}

/* Determinism test */
static void test_determinism(void) {
    uint8_t d1[32], d2[32];
    const uint8_t data[100] = {0xAA, 0xBB, 0xCC};
    TEST("SHA-256 determinism");
    ax_sha256(data, sizeof(data), d1);
    ax_sha256(data, sizeof(data), d2);
    if (memcmp(d1, d2, 32) != 0) FAIL("not deterministic"); else PASS();
}

int main(void) {
    printf("\n================================================================================\n");
    printf("  axioma-governance: SHA-256 Tests\n");
    printf("================================================================================\n\n");
    test_empty();
    test_abc();
    test_incremental();
    test_determinism();
    printf("\n================================================================================\n");
    printf("  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("================================================================================\n\n");
    return tests_failed > 0 ? 1 : 0;
}
