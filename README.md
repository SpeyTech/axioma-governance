# axioma-governance

**L7 Proof-Carrying Governance Layer for the Axioma Framework**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](LICENSE)
[![DVEC: v1.3](https://img.shields.io/badge/DVEC-v1.3-green.svg)](docs/DVEC-001-v1.3-Final.md)
[![SRS: SRS-007 v0.3](https://img.shields.io/badge/SRS-007%20v0.3-orange.svg)](docs/requirements/SRS-007-v0.3.md)

## Overview

axioma-governance implements the proof-carrying governance layer for the Axioma verifiable AI execution framework. Every governance claim becomes a cryptographically evidenced argument over committed evidence records.

**Governing Principle:** *"A regulator does not receive an assertion. They receive a cryptographic proof."*

## Axioma Layer Stack

```
L7 axioma-governance  ← THIS REPOSITORY
L6 axioma-audit       — Cryptographic audit ledger
L5 axioma-agent       — Behavioural FSM, totality contract  
L4 axioma-policy      — Policy evaluation, operational envelope
L3 axioma-oracle      — Oracle Boundary Gateway
L2 certifiable-*      — Deterministic ML inference
L1 libaxilog          — DVM substrate (Q16.16, SHA-256)
```

## Features

- **AX:PROOF:v1 Records**: Cryptographically bound proof records with canonical JSON serialisation (RFC 8785)
- **Mathematical Trace**: Full evidence chain from observation → policy → transition → proof
- **Evidence Closure Merkle Tree**: Compact membership proofs for evidence sets
- **Determinism Class D2**: Constrained Deterministic (identical outputs for identical inputs)
- **Zero Dynamic Allocation**: Bounded allocation model with compile-time constants

## Building

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
ctest --output-on-failure
```

### Requirements

- C99 compiler (GCC 11+, Clang 14+)
- CMake 3.14+

### DVEC Compiler Flags

The build enforces determinism-critical flags per DVEC-001 v1.3:

```
-fno-strict-aliasing -fwrapv -fno-tree-vectorize -fno-fast-math -fno-builtin
```

## Usage

```c
#include "ax_governance.h"
#include "ax_proof.h"

ax_proof_record_t proof;
ax_gov_fault_flags_t faults;
uint8_t prev_chain_head[32] = {0};
uint8_t evidence_hash[32] = { /* ... */ };

ax_gov_clear_faults(&faults);

// Initialise proof record
ax_proof_init(&proof, 
    "Policy permits action under constraint C1",
    AX_PROOF_TYPE_POLICY_SOUNDNESS,
    "SRS-007-SHALL-008",
    prev_chain_head,
    ledger_seq,
    &faults);

// Add evidence references
ax_proof_add_evidence(&proof, evidence_hash, &faults);

// Finalise (sort, hash, commit)
ax_proof_finalise(&proof, &faults);

// proof.proof_hash and proof.commitment are now set
```

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `ax_proof_record_t` | AX:PROOF:v1 record structure |
| `ax_math_trace_t` | Mathematical trace linking evidence chain |
| `ax_merkle_ctx_t` | Merkle tree context for evidence closure |
| `ax_gov_fault_flags_t` | Fault flags for governance operations |

### Proof Types (Closed Set)

| Enum | Description |
|------|-------------|
| `AX_PROOF_TYPE_ANCHOR_PUBLICATION` | External anchor commitment |
| `AX_PROOF_TYPE_COMPLIANCE_SUMMARY` | Compliance report proof |
| `AX_PROOF_TYPE_CROSS_LAYER_VERIFY` | Cross-layer chain verification |
| `AX_PROOF_TYPE_POLICY_SOUNDNESS` | Policy evaluation over evidence |
| `AX_PROOF_TYPE_REPLAY_EQUIVALENCE` | Replay produces identical results |
| `AX_PROOF_TYPE_SUBSTRATE_CERT` | L1 substrate certification |
| `AX_PROOF_TYPE_WEIGHT_BINDING` | L2 model identity verification |

## Specification Compliance

This implementation traces to **SRS-007 v0.3 Audit-Frozen FINAL** with 61 SHALL requirements:

- §3 Determinism: SHALL-001, SHALL-002, SHALL-044
- §4 AX:PROOF:v1: SHALL-003 through SHALL-007, SHALL-045, SHALL-046, SHALL-054 through SHALL-057
- §5 Policy Soundness: SHALL-008 through SHALL-010
- §6 Cross-Layer Verification: SHALL-011 through SHALL-019, SHALL-047, SHALL-048, SHALL-058
- §7 Mathematical Trace: SHALL-020 through SHALL-022, SHALL-049, SHALL-050
- §8 Compliance Reports: SHALL-023 through SHALL-028, SHALL-051, SHALL-059
- §9 External Anchoring: SHALL-029 through SHALL-034, SHALL-052, SHALL-060
- §10 Integrity Faults: SHALL-035 through SHALL-038, SHALL-053, SHALL-061
- §11 Traceability: SHALL-039 through SHALL-041
- §12 Boundedness: SHALL-042, SHALL-043

## License

GPL-3.0-or-later

## Patent

UK Patent GB2521625.0 — Murray Deterministic Computing Platform (MDCP)

## Copyright

Copyright (C) 2026 The Murray Family Innovation Trust. All rights reserved.

## Author

William Murray <william@speytech.com>
