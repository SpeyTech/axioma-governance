# RTM — Requirements Traceability Matrix

| Field | Value |
|-------|-------|
| Document | RTM |
| Generated | 2026-03-27 |
| SRS | SRS-007 v0.3 Audit-Frozen FINAL |
| Repository | axioma-governance |
| Layer | L7 — Governance |
| Patent | UK GB2521625.0 |

---

## Summary

| Metric | Value |
|--------|-------|
| Total SHALL requirements | 61 |
| Requirements with source traceability | 61 |
| Requirements with test coverage | 61 |
| Fully satisfied | 61 |
| Missing source trace | 0 |
| Missing test coverage | 0 |
| **Verdict** | **PASS** |

---

## Traceability Table

| Requirement | Description | Source Files | Test Files | Status |
|-------------|-------------|--------------|------------|--------|
| `SRS-007-SHALL-001` | Determinism definition (D2 — Constrained Deterministic) | verify.c<br>ax_governance.h | test_golden.c<br>test_sha256.c<br>*(+3 more)* | ✅ PASS |
| `SRS-007-SHALL-002` | Evidence closure — governance operates on committed evidence only | verify.c<br>ax_verify.h<br>*(+1 more)* | test_golden.c<br>test_sha256.c | ✅ PASS |
| `SRS-007-SHALL-003` | Proof commitment — every proof committed to L6 before use | verify.c<br>proof.c<br>*(+2 more)* | test_proof.c | ✅ PASS |
| `SRS-007-SHALL-004` | AX:PROOF:v1 required fields | verify.c<br>proof.c<br>*(+2 more)* | test_proof.c | ✅ PASS |
| `SRS-007-SHALL-005` | Proof type closed set | proof.c<br>ax_proof.h<br>*(+1 more)* | test_proof.c | ✅ PASS |
| `SRS-007-SHALL-006` | Evidence reference requirement — at least one evidence ref | proof.c<br>ax_proof.h | test_proof.c | ✅ PASS |
| `SRS-007-SHALL-007` | Canonical format — RFC 8785 (JCS) | jcs.c<br>proof.c<br>*(+2 more)* | test_golden.c<br>test_audit_findings.c<br>*(+1 more)* | ✅ PASS |
| `SRS-007-SHALL-008` | Policy soundness requirement — deterministic, evidence-closed, independently verifiable | verify.c<br>ax_verify.h | test_verify.c<br>test_audit_findings.c | ✅ PASS |
| `SRS-007-SHALL-009` | Policy violation — non-conformant policies rejected at init | verify.c | test_verify.c | ✅ PASS |
| `SRS-007-SHALL-010` | Policies as programs — deterministic programs over committed evidence | verify.c | test_verify.c | ✅ PASS |
| `SRS-007-SHALL-011` | Verification chain — 8-step cross-layer verification protocol | verify.c<br>ax_verify.h | test_verify.c | ✅ PASS |
| `SRS-007-SHALL-012` | L1 substrate certification — no forbidden arithmetic patterns | verify.c<br>ax_verify.h | test_verify.c<br>test_audit_findings.c | ✅ PASS |
| `SRS-007-SHALL-013` | L2 weight-to-evidence binding — WeightHash(L2) = ModelID(AX:OBS:v1) | verify.c<br>ax_verify.h | test_fault.c<br>test_verify.c | ✅ PASS |
| `SRS-007-SHALL-014` | L3 observation integrity — obs_hash verified | verify.c<br>ax_verify.h | test_fault.c<br>test_verify.c<br>*(+1 more)* | ✅ PASS |
| `SRS-007-SHALL-015` | L4 policy soundness verification | verify.c<br>ax_verify.h | test_verify.c | ✅ PASS |
| `SRS-007-SHALL-016` | L3→L4 observation-to-policy binding | verify.c<br>ax_verify.h | test_verify.c | ✅ PASS |
| `SRS-007-SHALL-017` | L4→L5 breach-to-transition enforcement | verify.c<br>ax_verify.h<br>*(+1 more)* | test_verify.c | ✅ PASS |
| `SRS-007-SHALL-018` | L5→L6 pre-commit ordering invariant | verify.c<br>ax_verify.h | test_fault.c<br>test_verify.c<br>*(+1 more)* | ✅ PASS |
| `SRS-007-SHALL-019` | Full chain replay verification | verify.c<br>ax_verify.h<br>*(+1 more)* | test_golden.c<br>test_fault.c<br>*(+2 more)* | ✅ PASS |
| `SRS-007-SHALL-020` | Mathematical trace requirement | trace.c<br>ax_trace.h | test_trace.c | ✅ PASS |
| `SRS-007-SHALL-021` | Trace required fields | trace.c<br>ax_trace.h<br>*(+1 more)* | test_trace.c | ✅ PASS |
| `SRS-007-SHALL-022` | Trace canonicality — RFC 8785, bit-identical | trace.c<br>jcs.c<br>*(+2 more)* | test_trace.c | ✅ PASS |
| `SRS-007-SHALL-023` | Track A evidence package — DO-178C, IEC 62304, ISO 26262 | compliance.c<br>ax_compliance.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-024` | Track B evidence package — EU AI Act Art 9, ISO/IEC 42001, FCA PS22/3 | compliance.c<br>ax_compliance.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-025` | Report trigger conditions — event-driven, not sequence-count | compliance.c<br>ax_compliance.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-026` | Report canonical format — JCS, committed as COMPLIANCE_SUMMARY | compliance.c<br>ax_compliance.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-027` | Report independence — verifiable by third party | compliance.c<br>ax_compliance.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-028` | Golden reference inclusion in Track A | compliance.c<br>ax_compliance.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-029` | Anchor requirement — periodic publication to transparency log | anchor.c<br>ax_anchor.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-030` | Anchor computation — SHA-256(AX:ANCHOR:v1 \|\| LE64(time_seq) \|\| chain_head) | anchor.c<br>ax_anchor.h<br>*(+1 more)* | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-031` | Anchor signing — GPG-signed, appended to latest-anchor.txt | ax_anchor.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-032` | Anchor commitment — committed as ANCHOR_PUBLICATION proof | anchor.c<br>ax_anchor.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-033` | Anchor interval declaration — declared at init, committed to manifest | anchor.c<br>ax_anchor.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-034` | Anchor verification — third party verifiable from public key + log | anchor.c<br>ax_anchor.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-035` | Integrity fault definition | fault.c<br>verify.c<br>*(+2 more)* | test_fault.c<br>test_verify.c | ✅ PASS |
| `SRS-007-SHALL-036` | Integrity fault recording — committed as AX:PROOF:v1 | fault.c<br>ax_fault.h<br>*(+1 more)* | test_fault.c | ✅ PASS |
| `SRS-007-SHALL-037` | Integrity fault response — agent to STOPPED | fault.c<br>verify.c<br>*(+2 more)* | test_fault.c | ✅ PASS |
| `SRS-007-SHALL-038` | No silent governance failure | fault.c<br>ax_fault.h<br>*(+1 more)* | test_fault.c | ✅ PASS |
| `SRS-007-SHALL-039` | Evidence citation requirement — every claim cites committed evidence | jcs.c<br>ax_governance.h | test_golden.c | ✅ PASS |
| `SRS-007-SHALL-040` | Claim-to-evidence mapping | jcs.c | test_golden.c<br>test_sha256.c<br>*(+3 more)* | ✅ PASS |
| `SRS-007-SHALL-041` | SRS traceability — every public function has SRS anchors | jcs.c | test_golden.c | ✅ PASS |
| `SRS-007-SHALL-042` | Bounded execution — O(N) or better per operation | ax_governance.h | test_golden.c<br>test_merkle.c | ✅ PASS |
| `SRS-007-SHALL-043` | Bounded allocation model — Option B caller-provided buffers | ax_merkle.h<br>ax_fault.h<br>*(+2 more)* | test_golden.c<br>test_trace.c<br>*(+2 more)* | ✅ PASS |
| `SRS-007-SHALL-044` | Configuration canonicality — policy set and config JCS-hashed at init | verify.c<br>ax_governance.h | test_golden.c | ✅ PASS |
| `SRS-007-SHALL-045` | Cryptographic binding fields — proof_hash field OMITTED during hash computation | jcs.c<br>proof.c<br>*(+2 more)* | test_golden.c<br>test_audit_findings.c<br>*(+1 more)* | ✅ PASS |
| `SRS-007-SHALL-046` | Evidence reference encoding — SHA-256 lowercase hex | jcs.c<br>proof.c<br>*(+1 more)* | test_golden.c | ✅ PASS |
| `SRS-007-SHALL-047` | Proof-before-execution invariant | verify.c<br>ax_verify.h | test_verify.c | ✅ PASS |
| `SRS-007-SHALL-048` | Weight hash specification — Q16.16 row-major LE canonical form | verify.c<br>ax_verify.h | test_verify.c | ✅ PASS |
| `SRS-007-SHALL-049` | Trace array ordering — policy_seqs ascending | trace.c<br>ax_trace.h | test_trace.c | ✅ PASS |
| `SRS-007-SHALL-050` | Trace hash computation — trace_hash field OMITTED during computation | trace.c<br>ax_trace.h<br>*(+1 more)* | test_golden.c<br>test_trace.c | ✅ PASS |
| `SRS-007-SHALL-051` | Evidence closure proof — Merkle root over all cited evidence | merkle.c<br>compliance.c<br>*(+2 more)* | test_merkle.c | ✅ PASS |
| `SRS-007-SHALL-052` | Anchor time as oracle — time_seq is ledger_seq of Time Oracle AX:OBS:v1 | anchor.c<br>ax_anchor.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-053` | Ledger failure mode — Option A deterministic fallback log | fault.c<br>ax_fault.h | test_fault.c<br>test_audit_findings.c | ✅ PASS |
| `SRS-007-SHALL-054` | Commitment payload encoding — AX:PROOF:v1 \|\| LE64(len) \|\| UTF-8 | proof.c<br>ax_proof.h | test_golden.c<br>test_audit_findings.c | ✅ PASS |
| `SRS-007-SHALL-055` | Chain head reference — prev_chain_head in every proof | verify.c<br>ax_governance.h | test_golden.c<br>test_proof.c | ✅ PASS |
| `SRS-007-SHALL-056` | Proof type versioning mechanism | ax_proof.h<br>ax_governance.h | test_golden.c<br>test_audit_findings.c<br>*(+1 more)* | ✅ PASS |
| `SRS-007-SHALL-057` | Evidence ordering mode — LEX / TEMPORAL / DECLARED | proof.c<br>ax_proof.h<br>*(+1 more)* | test_golden.c<br>test_audit_findings.c<br>*(+1 more)* | ✅ PASS |
| `SRS-007-SHALL-058` | Atomicity model — Option A single-threaded sequencing | verify.c<br>ax_verify.h | test_verify.c | ✅ PASS |
| `SRS-007-SHALL-059` | Merkle tree construction algorithm — left-balanced, SHA-256 internal nodes | merkle.c<br>compliance.c<br>*(+2 more)* | test_golden.c<br>test_audit_findings.c<br>*(+1 more)* | ✅ PASS |
| `SRS-007-SHALL-060` | GPG signature determinism boundary — signature excluded from proof payload | anchor.c<br>ax_anchor.h | test_anchor_compliance.c | ✅ PASS |
| `SRS-007-SHALL-061` | Fallback log overflow — Option A.1 truncation with OVERFLOW_MARKER | fault.c<br>ax_fault.h | test_fault.c<br>test_audit_findings.c | ✅ PASS |

---

## Missing Coverage

### Missing Source Traceability

_None._

### Missing Test Coverage

_None._

---

## Verification Method

This RTM is generated by `scripts/ax-rtm-verify.py`.

**Source traceability** is detected via `@traceability SRS-007-SHALL-NNN` tags
in `.c` and `.h` files under `src/` and `include/`.

**Test coverage** is detected via any mention of `SRS-007-SHALL-NNN` in test
files under `tests/`.

To regenerate:
```bash
python3 scripts/ax-rtm-verify.py --md
```

---

*Copyright (C) 2026 The Murray Family Innovation Trust.*  
*Patent UK GB2521625.0*
