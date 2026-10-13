/* ci/fingerprint.c - v1 Merkle roots, proofs and verdicts for 22 tree sizes,
 * for cross-architecture byte-identity checks. CI hashes this output and
 * compares it with ci/fingerprints.txt. */
#include "ax_governance.h"
#include "ax_merkle.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static uint64_t s = 0x9E3779B97F4A7C15ULL;
static uint8_t rb(void){ s ^= s << 13; s ^= s >> 7; s ^= s << 17; return (uint8_t)(s >> 24); }
static void hx(const uint8_t *p){ for(int i=0;i<32;i++) printf("%02x",p[i]); }
int main(void){
  static ax_merkle_ctx_t c; static uint8_t L[1024][32];
  size_t sizes[] = {1,2,3,4,5,6,7,8,9,15,16,17,31,32,33,100,255,256,257,513,1023,1024};
  for (size_t si=0; si<sizeof sizes/sizeof *sizes; si++){
    size_t n = sizes[si]; ax_gov_fault_flags_t f; uint8_t root[32];
    for (size_t i=0;i<n;i++) for(int j=0;j<32;j++) L[i][j]=rb();
    ax_gov_clear_faults(&f); ax_merkle_init(&c,&f);
    int rc = ax_merkle_add_leaves(&c,(const uint8_t(*)[32])L,n,&f);
    rc |= ax_merkle_compute_root(&c,&f); rc |= ax_merkle_get_root(&c,root,&f);
    printf("n=%zu rc=%d root=",n,rc); hx(root); printf("\n");
    for (size_t m=0;m<n;m+= (n>40? n/7+1 : 1)){
      static ax_merkle_proof_t p; ax_gov_clear_faults(&f);
      int g = ax_merkle_generate_proof(&c,m,&p,&f);
      int v = ax_merkle_verify_proof(&p,&f);
      printf(" m=%zu gen=%d depth=%zu ver=%d sib0=",m,g,p.proof_depth,v); if(p.proof_depth) hx(p.siblings[0]); printf("\n");
    }
  }
  return 0;
}
