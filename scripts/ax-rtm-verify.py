#!/usr/bin/env python3
"""
ax-rtm-verify.py — Requirements Traceability Matrix Verifier

DVEC: v1.3
SRS: SRS-007 v0.3 Audit-Frozen FINAL

Verifies that all 61 SHALL requirements from SRS-007 are:
  1. Traced to at least one source file via @traceability tags
  2. Covered by at least one test file
  3. Optionally: produces RTM.md for human review

Usage:
    python3 scripts/ax-rtm-verify.py [--verbose] [--md] [--root DIR]

Exit codes:
    0 — All 61 requirements satisfied
    1 — One or more requirements missing traceability or test coverage
    2 — Script error (missing directory etc.)

@copyright Copyright (C) 2026 The Murray Family Innovation Trust.
@license GPL-3.0-or-later
@patent UK GB2521625.0

@traceability SRS-007-SHALL-039: Source code traceability
@traceability SRS-007-SHALL-040: Test traceability
@traceability SRS-007-SHALL-041: Documentation traceability
"""

import os
import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set
from datetime import date

# =============================================================================
# SRS-007 SHALL Requirements — exact titles from SRS-007 v0.3
# =============================================================================

SRS_007_REQUIREMENTS: Dict[str, str] = {
    # §3 Determinism
    "SRS-007-SHALL-001": "Determinism definition (D2 — Constrained Deterministic)",
    "SRS-007-SHALL-002": "Evidence closure — governance operates on committed evidence only",
    "SRS-007-SHALL-044": "Configuration canonicality — policy set and config JCS-hashed at init",

    # §4 AX:PROOF:v1
    "SRS-007-SHALL-003": "Proof commitment — every proof committed to L6 before use",
    "SRS-007-SHALL-004": "AX:PROOF:v1 required fields",
    "SRS-007-SHALL-005": "Proof type closed set",
    "SRS-007-SHALL-006": "Evidence reference requirement — at least one evidence ref",
    "SRS-007-SHALL-007": "Canonical format — RFC 8785 (JCS)",
    "SRS-007-SHALL-045": "Cryptographic binding fields — proof_hash field OMITTED during hash computation",
    "SRS-007-SHALL-046": "Evidence reference encoding — SHA-256 lowercase hex",
    "SRS-007-SHALL-054": "Commitment payload encoding — AX:PROOF:v1 || LE64(len) || UTF-8",
    "SRS-007-SHALL-055": "Chain head reference — prev_chain_head in every proof",
    "SRS-007-SHALL-056": "Proof type versioning mechanism",
    "SRS-007-SHALL-057": "Evidence ordering mode — LEX / TEMPORAL / DECLARED",

    # §5 Policy Soundness
    "SRS-007-SHALL-008": "Policy soundness requirement — deterministic, evidence-closed, independently verifiable",
    "SRS-007-SHALL-009": "Policy violation — non-conformant policies rejected at init",
    "SRS-007-SHALL-010": "Policies as programs — deterministic programs over committed evidence",

    # §6 Cross-Layer Verification
    "SRS-007-SHALL-011": "Verification chain — 8-step cross-layer verification protocol",
    "SRS-007-SHALL-012": "L1 substrate certification — no forbidden arithmetic patterns",
    "SRS-007-SHALL-013": "L2 weight-to-evidence binding — WeightHash(L2) = ModelID(AX:OBS:v1)",
    "SRS-007-SHALL-014": "L3 observation integrity — obs_hash verified",
    "SRS-007-SHALL-015": "L4 policy soundness verification",
    "SRS-007-SHALL-016": "L3→L4 observation-to-policy binding",
    "SRS-007-SHALL-017": "L4→L5 breach-to-transition enforcement",
    "SRS-007-SHALL-018": "L5→L6 pre-commit ordering invariant",
    "SRS-007-SHALL-019": "Full chain replay verification",
    "SRS-007-SHALL-047": "Proof-before-execution invariant",
    "SRS-007-SHALL-048": "Weight hash specification — Q16.16 row-major LE canonical form",
    "SRS-007-SHALL-058": "Atomicity model — Option A single-threaded sequencing",

    # §7 Mathematical Trace
    "SRS-007-SHALL-020": "Mathematical trace requirement",
    "SRS-007-SHALL-021": "Trace required fields",
    "SRS-007-SHALL-022": "Trace canonicality — RFC 8785, bit-identical",
    "SRS-007-SHALL-049": "Trace array ordering — policy_seqs ascending",
    "SRS-007-SHALL-050": "Trace hash computation — trace_hash field OMITTED during computation",

    # §8 Compliance Reports
    "SRS-007-SHALL-023": "Track A evidence package — DO-178C, IEC 62304, ISO 26262",
    "SRS-007-SHALL-024": "Track B evidence package — EU AI Act Art 9, ISO/IEC 42001, FCA PS22/3",
    "SRS-007-SHALL-025": "Report trigger conditions — event-driven, not sequence-count",
    "SRS-007-SHALL-026": "Report canonical format — JCS, committed as COMPLIANCE_SUMMARY",
    "SRS-007-SHALL-027": "Report independence — verifiable by third party",
    "SRS-007-SHALL-028": "Golden reference inclusion in Track A",
    "SRS-007-SHALL-051": "Evidence closure proof — Merkle root over all cited evidence",
    "SRS-007-SHALL-059": "Merkle tree construction algorithm — left-balanced, SHA-256 internal nodes",

    # §9 External Anchoring
    "SRS-007-SHALL-029": "Anchor requirement — periodic publication to transparency log",
    "SRS-007-SHALL-030": "Anchor computation — SHA-256(AX:ANCHOR:v1 || LE64(time_seq) || chain_head)",
    "SRS-007-SHALL-031": "Anchor signing — GPG-signed, appended to latest-anchor.txt",
    "SRS-007-SHALL-032": "Anchor commitment — committed as ANCHOR_PUBLICATION proof",
    "SRS-007-SHALL-033": "Anchor interval declaration — declared at init, committed to manifest",
    "SRS-007-SHALL-034": "Anchor verification — third party verifiable from public key + log",
    "SRS-007-SHALL-052": "Anchor time as oracle — time_seq is ledger_seq of Time Oracle AX:OBS:v1",
    "SRS-007-SHALL-060": "GPG signature determinism boundary — signature excluded from proof payload",

    # §10 Integrity Faults
    "SRS-007-SHALL-035": "Integrity fault definition",
    "SRS-007-SHALL-036": "Integrity fault recording — committed as AX:PROOF:v1",
    "SRS-007-SHALL-037": "Integrity fault response — agent to STOPPED",
    "SRS-007-SHALL-038": "No silent governance failure",
    "SRS-007-SHALL-053": "Ledger failure mode — Option A deterministic fallback log",
    "SRS-007-SHALL-061": "Fallback log overflow — Option A.1 truncation with OVERFLOW_MARKER",

    # §11 Traceability
    "SRS-007-SHALL-039": "Evidence citation requirement — every claim cites committed evidence",
    "SRS-007-SHALL-040": "Claim-to-evidence mapping",
    "SRS-007-SHALL-041": "SRS traceability — every public function has SRS anchors",

    # §12 Boundedness
    "SRS-007-SHALL-042": "Bounded execution — O(N) or better per operation",
    "SRS-007-SHALL-043": "Bounded allocation model — Option B caller-provided buffers",
}

assert len(SRS_007_REQUIREMENTS) == 61, \
    f"Expected 61 requirements, got {len(SRS_007_REQUIREMENTS)}"

# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class RequirementStatus:
    req_id: str
    description: str
    source_files: List[str] = field(default_factory=list)
    test_files: List[str] = field(default_factory=list)

    @property
    def has_source_trace(self) -> bool:
        return len(self.source_files) > 0

    @property
    def has_test_coverage(self) -> bool:
        return len(self.test_files) > 0

    @property
    def is_satisfied(self) -> bool:
        return self.has_source_trace and self.has_test_coverage


@dataclass
class RTMReport:
    requirements: Dict[str, RequirementStatus] = field(default_factory=dict)
    source_files_scanned: int = 0
    test_files_scanned: int = 0

    @property
    def satisfied(self) -> List[str]:
        return [r.req_id for r in self.requirements.values() if r.is_satisfied]

    @property
    def missing_source(self) -> List[str]:
        return sorted([r.req_id for r in self.requirements.values()
                       if not r.has_source_trace])

    @property
    def missing_tests(self) -> List[str]:
        return sorted([r.req_id for r in self.requirements.values()
                       if r.has_source_trace and not r.has_test_coverage])

    @property
    def is_passing(self) -> bool:
        return len(self.missing_source) == 0 and len(self.missing_tests) == 0

# =============================================================================
# Scanner
# =============================================================================

TRACE_TAG   = re.compile(r'@traceability\s+(SRS-007-SHALL-\d{3})')
ANY_REQ_REF = re.compile(r'\b(SRS-007-SHALL-\d{3})\b')

def scan_file(filepath: Path, pattern: re.Pattern) -> Set[str]:
    found = set()
    try:
        text = filepath.read_text(encoding='utf-8')
        for m in pattern.finditer(text):
            found.add(m.group(1))
    except Exception as e:
        print(f"WARNING: cannot read {filepath}: {e}", file=sys.stderr)
    return found

# =============================================================================
# Verification
# =============================================================================

def verify(root: Path) -> RTMReport:
    report = RTMReport()
    for req_id, desc in SRS_007_REQUIREMENTS.items():
        report.requirements[req_id] = RequirementStatus(req_id=req_id, description=desc)

    # Source: .c and .h files — require @traceability tag
    src_files = list((root / "src").rglob("*.c")) + \
                list((root / "include").rglob("*.h"))
    report.source_files_scanned = len(src_files)
    for f in src_files:
        for req_id in scan_file(f, TRACE_TAG):
            if req_id in report.requirements:
                rel = str(f.relative_to(root))
                if rel not in report.requirements[req_id].source_files:
                    report.requirements[req_id].source_files.append(rel)

    # Tests: .c files — accept any mention of requirement ID
    test_files = list((root / "tests").rglob("*.c"))
    report.test_files_scanned = len(test_files)
    for f in test_files:
        for req_id in scan_file(f, ANY_REQ_REF):
            if req_id in report.requirements:
                rel = str(f.relative_to(root))
                if rel not in report.requirements[req_id].test_files:
                    report.requirements[req_id].test_files.append(rel)

    return report

# =============================================================================
# Console output
# =============================================================================

def print_console(report: RTMReport, verbose: bool) -> None:
    W = 80
    print("\n" + "=" * W)
    print("  axioma-governance — RTM Verification")
    print("  SRS-007 v0.3 Audit-Frozen FINAL")
    print("=" * W)
    print(f"\n  Source files : {report.source_files_scanned}")
    print(f"  Test files   : {report.test_files_scanned}")
    print(f"  Requirements : {len(report.requirements)} total")
    print(f"  Satisfied    : {len(report.satisfied)} / {len(report.requirements)}")

    if report.missing_source:
        print(f"\n  MISSING SOURCE TRACEABILITY ({len(report.missing_source)}):")
        for r in report.missing_source:
            print(f"    {r}: {report.requirements[r].description}")

    if report.missing_tests:
        print(f"\n  MISSING TEST COVERAGE ({len(report.missing_tests)}):")
        for r in report.missing_tests:
            print(f"    {r}: {report.requirements[r].description}")

    if verbose:
        print("\n  FULL STATUS:")
        for req_id in sorted(report.requirements):
            req = report.requirements[req_id]
            if req.is_satisfied:
                icon = "PASS "
            elif req.has_source_trace:
                icon = "NOTST"
            else:
                icon = "MISS "
            print(f"    [{icon}] {req_id}  {req.description[:55]}")
            for s in req.source_files[:2]:
                print(f"             src  : {s}")
            for t in req.test_files[:2]:
                print(f"             test : {t}")

    print("\n" + "-" * W)
    verdict = "PASS" if report.is_passing else "FAIL"
    print(f"  RTM VERIFICATION: {verdict}")
    print("-" * W + "\n")

# =============================================================================
# RTM.md generation
# =============================================================================

def write_rtm_md(report: RTMReport, root: Path) -> Path:
    lines = []
    today = date.today().isoformat()

    lines += [
        "# RTM — Requirements Traceability Matrix",
        "",
        "| Field | Value |",
        "|-------|-------|",
        "| Document | RTM |",
        f"| Generated | {today} |",
        "| SRS | SRS-007 v0.3 Audit-Frozen FINAL |",
        "| Repository | axioma-governance |",
        "| Layer | L7 — Governance |",
        "| Patent | UK GB2521625.0 |",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total SHALL requirements | {len(report.requirements)} |",
        f"| Requirements with source traceability | {sum(1 for r in report.requirements.values() if r.has_source_trace)} |",
        f"| Requirements with test coverage | {sum(1 for r in report.requirements.values() if r.has_test_coverage)} |",
        f"| Fully satisfied | {len(report.satisfied)} |",
        f"| Missing source trace | {len(report.missing_source)} |",
        f"| Missing test coverage | {len(report.missing_tests)} |",
        f"| **Verdict** | **{'PASS' if report.is_passing else 'FAIL'}** |",
        "",
        "---",
        "",
        "## Traceability Table",
        "",
        "| Requirement | Description | Source Files | Test Files | Status |",
        "|-------------|-------------|--------------|------------|--------|",
    ]

    for req_id in sorted(report.requirements):
        req = report.requirements[req_id]

        # Source files — up to 2, basename only for readability
        src_str = "<br>".join(
            Path(f).name for f in req.source_files[:2]
        ) if req.source_files else "—"
        if len(req.source_files) > 2:
            src_str += f"<br>*(+{len(req.source_files)-2} more)*"

        # Test files — up to 2
        tst_str = "<br>".join(
            Path(f).name for f in req.test_files[:2]
        ) if req.test_files else "—"
        if len(req.test_files) > 2:
            tst_str += f"<br>*(+{len(req.test_files)-2} more)*"

        if req.is_satisfied:
            status = "✅ PASS"
        elif req.has_source_trace:
            status = "🟠 NO TEST"
        else:
            status = "🔴 MISSING"

        desc = req.description.replace("|", "\\|")
        lines.append(
            f"| `{req_id}` | {desc} | {src_str} | {tst_str} | {status} |"
        )

    lines += [
        "",
        "---",
        "",
        "## Missing Coverage",
        "",
    ]

    if report.missing_source:
        lines += ["### Missing Source Traceability", ""]
        for r in report.missing_source:
            lines.append(f"- `{r}`: {report.requirements[r].description}")
        lines.append("")
    else:
        lines += ["### Missing Source Traceability", "", "_None._", ""]

    if report.missing_tests:
        lines += ["### Missing Test Coverage", ""]
        for r in report.missing_tests:
            lines.append(f"- `{r}`: {report.requirements[r].description}")
        lines.append("")
    else:
        lines += ["### Missing Test Coverage", "", "_None._", ""]

    lines += [
        "---",
        "",
        "## Verification Method",
        "",
        "This RTM is generated by `scripts/ax-rtm-verify.py`.",
        "",
        "**Source traceability** is detected via `@traceability SRS-007-SHALL-NNN` tags",
        "in `.c` and `.h` files under `src/` and `include/`.",
        "",
        "**Test coverage** is detected via any mention of `SRS-007-SHALL-NNN` in test",
        "files under `tests/`.",
        "",
        "To regenerate:",
        "```bash",
        "python3 scripts/ax-rtm-verify.py --md",
        "```",
        "",
        "---",
        "",
        "*Copyright (C) 2026 The Murray Family Innovation Trust.*  ",
        "*Patent UK GB2521625.0*",
    ]

    out_path = root / "RTM.md"
    out_path.write_text("\n".join(lines) + "\n", encoding='utf-8')
    return out_path

# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify SRS-007 Requirements Traceability Matrix"
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show full per-requirement status")
    parser.add_argument("--md", action="store_true",
                        help="Write RTM.md to project root")
    parser.add_argument("--root", type=Path, default=Path.cwd(),
                        help="Project root directory (default: cwd)")
    args = parser.parse_args()

    for subdir in ("src", "include", "tests"):
        if not (args.root / subdir).exists():
            print(f"ERROR: {args.root}/{subdir} not found", file=sys.stderr)
            return 2

    report = verify(args.root)
    print_console(report, args.verbose)

    if args.md:
        out = write_rtm_md(report, args.root)
        print(f"  RTM.md written to: {out}")

    return 0 if report.is_passing else 1

if __name__ == "__main__":
    sys.exit(main())
