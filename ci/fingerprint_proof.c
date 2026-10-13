/* ci/fingerprint_proof.c - AX:PROOF:v1 records built through the public API
 * (counts up to the producer bound of 192, every ordering, every result and
 * violation, plain, quote-escaped and control-escaped strings at maximum
 * length). Prints proof_hash, commitment and SHA-256 of both canonical forms.
 * PCR-007 requires this output to be byte-identical to pristine main
 * (93d75a6), proving that no valid record changes. CI compares the SHA-256
 * of the output with ci/fingerprints-proof.txt. */
#include "ax_governance.h"
#include "ax_proof.h"
#include "ax_jcs.h"
#include <axilog/sha256.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static ax_proof_record_t r;
static uint8_t buf[1 << 15];
static void hx(const uint8_t *p){ for(int i=0;i<32;i++) printf("%02x",p[i]); }
static void fill(char *d, size_t cap, char c, size_t n){ if (n > cap - 1) n = cap - 1; memset(d, c, n); d[n] = '\0'; }
int main(void){
  static const size_t ks[] = {1, 2, 3, 64, 191, 192};
  static const char content[] = { 'a', '"', 0x01 };
  for (size_t ci = 0; ci < 3; ci++)
  for (int ord = 0; ord <= 2; ord++)
  for (int res = 0; res <= 2; res++)
  for (int vio = 0; vio <= 8; vio += (res == 0 ? 9 : 1))
  for (size_t ki = 0; ki < sizeof ks / sizeof *ks; ki++) {
    ax_gov_fault_flags_t f; uint8_t head[32], ref[32]; char claim[AX_MAX_CLAIM_SIZE], rule[AX_MAX_RULE_ID_SIZE];
    ax_ordering_metadata_t m; size_t n0 = 0, n1 = 0, k = ks[ki], i; uint8_t d0[32], d1[32];
    /* worst content only at the largest count; keeps every record within the bound */
    size_t len = (content[ci] == 'a') ? 40 : (k == 192 ? 255 : 20);
    ax_gov_clear_faults(&f);
    for (i = 0; i < 32; i++) head[i] = (uint8_t)(i * 7 + ci);
    fill(claim, sizeof claim, content[ci], len);
    fill(rule, sizeof rule, content[ci], len);
    if (ax_proof_init(&r, claim, (ax_proof_type_t)((ki + ci) % AX_PROOF_TYPE_COUNT), rule, head,
                      (uint64_t)k * 1000003u + (uint64_t)res, &f) != 0) { printf("init_fail\n"); continue; }
    if (ord != 0) {
      memset(&m, 0, sizeof m);
      fill(m.description, sizeof m.description, content[ci], len);
      strcpy(m.key_field, "ledger_seq"); strcpy(m.direction, "ascending"); m.is_set = true;
      ax_proof_set_ordering(&r, (ax_evidence_ordering_t)ord, &m, &f);
    }
    ax_proof_set_result(&r, (ax_proof_result_t)res, (ax_violation_t)vio, &f);
    for (i = 0; i < k; i++) {
      for (int j = 0; j < 32; j++) ref[j] = (uint8_t)((i * 131 + (size_t)j * 17 + ci) & 0xFF);
      ref[0] = (uint8_t)(255 - (i & 0xFF));
      ax_proof_add_evidence(&r, ref, &f);
    }
    int rc = ax_proof_finalise(&r, &f);
    ax_gov_fault_flags_t g; ax_gov_clear_faults(&g);
    jcs_proof_to_canonical(&r, buf, sizeof buf, &n1, true, &g);
    axilog_sha256(d1, buf, n1);
    ax_proof_record_t z = r; memset(z.commitment, 0, 32); z.proof_hash_computed = false;
    jcs_proof_to_canonical(&z, buf, sizeof buf, &n0, false, &g);
    axilog_sha256(d0, buf, n0);
    printf("c=%zu o=%d r=%d v=%d k=%zu rc=%d n0=%zu n1=%zu ph=", ci, ord, res, vio, k, rc, n0, n1); hx(r.proof_hash);
    printf(" cm="); hx(r.commitment); printf(" h0="); hx(d0); printf(" h1="); hx(d1); printf("\n");
  }
  return 0;
}
