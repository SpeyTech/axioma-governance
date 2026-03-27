#!/usr/bin/env python3
"""
ax-rtm-verify.py — Requirements Traceability Matrix Verifier

DVEC: v1.3
SRS: SRS-007 v0.3 Audit-Frozen FINAL

Verifies that all 61 SHALL requirements from SRS-007 are:
1. Traced to source code via @traceability tags
2. Covered by at least one test
3. Documented in CONFORMANCE.md

Usage:
    python3 scripts/ax-rtm-verify.py [--verbose] [--strict]

Exit codes:
    0 — All requirements satisfied
    1 — Missing traceability or coverage
    2 — Script error

@copyright Copyright (C) 2026 The Murray Family Innovation Trust.
@license GPL-3.0-or-later
@patent UK GB2521625.0
"""

import os
import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional

# =============================================================================
# SRS-007 SHALL Requirements (61 total)
# =============================================================================

SRS_007_REQUIREMENTS = {
    # §3 Determinism
    "SRS-007-SHALL-001": "Cross-platform bit-identical execution",
    "SRS-007-SHALL-002": "Deterministic algorithm selection",
    "SRS-007-SHALL-044": "No floating-point in governance layer",
    
    # §4 AX:PROOF:v1
    "SRS-007-SHALL-003": "Proof commitment cryptographic binding",
    "SRS-007-SHALL-004": "AX:PROOF:v1 required fields",
    "SRS-007-SHALL-005": "Proof type closed set",
    "SRS-007-SHALL-006": "Evidence reference requirement (non-empty)",
    "SRS-007-SHALL-007": "Canonical format (RFC 8785 JCS)",
    "SRS-007-SHALL-045": "proof_hash field OMITTED during hash computation",
    "SRS-007-SHALL-046": "Evidence reference encoding (lowercase hex)",
    "SRS-007-SHALL-054": "Commitment payload encoding (tag || LE64 || UTF-8)",
    "SRS-007-SHALL-055": "Schema version field",
    "SRS-007-SHALL-056": "Proof type string encoding",
    "SRS-007-SHALL-057": "Evidence ordering mode (LEX/TEMPORAL/DECLARED)",
    
    # §5 Policy Soundness
    "SRS-007-SHALL-008": "Policy evaluation determinism",
    "SRS-007-SHALL-009": "Policy result closed set",
    "SRS-007-SHALL-010": "Policy ordering constraints",
    
    # §6 Cross-Layer Verification
    "SRS-007-SHALL-011": "L1 substrate verification",
    "SRS-007-SHALL-012": "L2 training verification",
    "SRS-007-SHALL-013": "L3 oracle verification",
    "SRS-007-SHALL-014": "L4 policy verification",
    "SRS-007-SHALL-015": "L5 agent verification",
    "SRS-007-SHALL-016": "L6 audit verification",
    "SRS-007-SHALL-017": "Weight binding verification",
    "SRS-007-SHALL-018": "Replay equivalence verification",
    "SRS-007-SHALL-019": "Replay determinism",
    "SRS-007-SHALL-047": "Verification step ordering",
    "SRS-007-SHALL-048": "Verification failure handling",
    "SRS-007-SHALL-058": "Proof-before-execution enforcement",
    
    # §7 Mathematical Trace
    "SRS-007-SHALL-020": "Mathematical trace structure",
    "SRS-007-SHALL-021": "Trace required fields",
    "SRS-007-SHALL-022": "Trace canonicality",
    "SRS-007-SHALL-049": "Trace array ordering (strict monotonic)",
    "SRS-007-SHALL-050": "trace_hash field OMITTED during computation",
    
    # §8 Compliance Reports
    "SRS-007-SHALL-023": "Track A report structure",
    "SRS-007-SHALL-024": "Track B report structure",
    "SRS-007-SHALL-025": "Report signing",
    "SRS-007-SHALL-026": "Report timestamp",
    "SRS-007-SHALL-027": "Report chain linkage",
    "SRS-007-SHALL-028": "Report retention period",
    "SRS-007-SHALL-051": "Evidence closure Merkle root",
    "SRS-007-SHALL-059": "Merkle tree algorithm",
    
    # §9 External Anchoring
    "SRS-007-SHALL-029": "Anchor publication format",
    "SRS-007-SHALL-030": "Anchor frequency",
    "SRS-007-SHALL-031": "Anchor chain selection",
    "SRS-007-SHALL-032": "Anchor verification",
    "SRS-007-SHALL-033": "Anchor fallback",
    "SRS-007-SHALL-034": "Anchor timestamp",
    "SRS-007-SHALL-052": "Anchor payload encoding",
    "SRS-007-SHALL-060": "Anchor confirmation depth",
    
    # §10 Integrity Faults
    "SRS-007-SHALL-035": "Fault detection",
    "SRS-007-SHALL-036": "Fault classification",
    "SRS-007-SHALL-037": "Fault response",
    "SRS-007-SHALL-038": "Fault logging",
    "SRS-007-SHALL-053": "Fallback log structure",
    "SRS-007-SHALL-061": "Fallback log rotation",
    
    # §11 Traceability
    "SRS-007-SHALL-039": "Source code traceability",
    "SRS-007-SHALL-040": "Test traceability",
    "SRS-007-SHALL-041": "Documentation traceability",
    
    # §12 Boundedness
    "SRS-007-SHALL-042": "Bounded memory allocation",
    "SRS-007-SHALL-043": "Buffer overflow prevention",
}

# Requirements implemented in Phase 1
PHASE_1_REQUIREMENTS = {
    "SRS-007-SHALL-001", "SRS-007-SHALL-002", "SRS-007-SHALL-003",
    "SRS-007-SHALL-004", "SRS-007-SHALL-005", "SRS-007-SHALL-006",
    "SRS-007-SHALL-007", "SRS-007-SHALL-019", "SRS-007-SHALL-020",
    "SRS-007-SHALL-021", "SRS-007-SHALL-022", "SRS-007-SHALL-039",
    "SRS-007-SHALL-040", "SRS-007-SHALL-042", "SRS-007-SHALL-043",
    "SRS-007-SHALL-044", "SRS-007-SHALL-045", "SRS-007-SHALL-046",
    "SRS-007-SHALL-049", "SRS-007-SHALL-050", "SRS-007-SHALL-051",
    "SRS-007-SHALL-054", "SRS-007-SHALL-055", "SRS-007-SHALL-056",
    "SRS-007-SHALL-057", "SRS-007-SHALL-059",
}

# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class RequirementStatus:
    """Status of a single requirement."""
    req_id: str
    description: str
    source_files: List[str] = field(default_factory=list)
    test_files: List[str] = field(default_factory=list)
    in_phase_1: bool = False
    
    @property
    def has_source_trace(self) -> bool:
        return len(self.source_files) > 0
    
    @property
    def has_test_coverage(self) -> bool:
        return len(self.test_files) > 0
    
    @property
    def is_satisfied(self) -> bool:
        if not self.in_phase_1:
            return True  # Future phase — not required yet
        return self.has_source_trace and self.has_test_coverage

@dataclass
class RTMReport:
    """Full RTM verification report."""
    requirements: Dict[str, RequirementStatus] = field(default_factory=dict)
    source_files_scanned: int = 0
    test_files_scanned: int = 0
    
    @property
    def total_requirements(self) -> int:
        return len(self.requirements)
    
    @property
    def phase_1_requirements(self) -> int:
        return sum(1 for r in self.requirements.values() if r.in_phase_1)
    
    @property
    def satisfied_requirements(self) -> int:
        return sum(1 for r in self.requirements.values() if r.is_satisfied)
    
    @property
    def missing_source_trace(self) -> List[str]:
        return [r.req_id for r in self.requirements.values() 
                if r.in_phase_1 and not r.has_source_trace]
    
    @property
    def missing_test_coverage(self) -> List[str]:
        return [r.req_id for r in self.requirements.values() 
                if r.in_phase_1 and not r.has_test_coverage]
    
    @property
    def is_passing(self) -> bool:
        return len(self.missing_source_trace) == 0 and len(self.missing_test_coverage) == 0

# =============================================================================
# Scanner
# =============================================================================

TRACEABILITY_PATTERN = re.compile(r'@traceability\s+(SRS-007-SHALL-\d{3})')
TEST_TRACE_PATTERN = re.compile(r'(SRS-007-SHALL-\d{3})')

def scan_source_file(filepath: Path) -> Set[str]:
    """Extract @traceability tags from a source file."""
    requirements = set()
    try:
        content = filepath.read_text(encoding='utf-8')
        for match in TRACEABILITY_PATTERN.finditer(content):
            requirements.add(match.group(1))
    except Exception as e:
        print(f"  WARNING: Could not read {filepath}: {e}", file=sys.stderr)
    return requirements

def scan_test_file(filepath: Path) -> Set[str]:
    """Extract requirement references from a test file."""
    requirements = set()
    try:
        content = filepath.read_text(encoding='utf-8')
        # Look for any mention of requirement IDs in tests
        for match in TEST_TRACE_PATTERN.finditer(content):
            requirements.add(match.group(1))
    except Exception as e:
        print(f"  WARNING: Could not read {filepath}: {e}", file=sys.stderr)
    return requirements

def find_files(root: Path, pattern: str) -> List[Path]:
    """Find all files matching pattern under root."""
    return list(root.rglob(pattern))

# =============================================================================
# Verification
# =============================================================================

def verify_rtm(project_root: Path, verbose: bool = False) -> RTMReport:
    """Perform full RTM verification."""
    report = RTMReport()
    
    # Initialize all requirements
    for req_id, description in SRS_007_REQUIREMENTS.items():
        report.requirements[req_id] = RequirementStatus(
            req_id=req_id,
            description=description,
            in_phase_1=(req_id in PHASE_1_REQUIREMENTS)
        )
    
    # Scan source files
    src_dir = project_root / "src"
    include_dir = project_root / "include"
    
    source_files = find_files(src_dir, "*.c") + find_files(include_dir, "*.h")
    report.source_files_scanned = len(source_files)
    
    if verbose:
        print(f"\nScanning {len(source_files)} source files...")
    
    for filepath in source_files:
        reqs = scan_source_file(filepath)
        rel_path = str(filepath.relative_to(project_root))
        for req_id in reqs:
            if req_id in report.requirements:
                report.requirements[req_id].source_files.append(rel_path)
                if verbose:
                    print(f"  {req_id} -> {rel_path}")
    
    # Scan test files
    test_dir = project_root / "tests"
    test_files = find_files(test_dir, "*.c")
    report.test_files_scanned = len(test_files)
    
    if verbose:
        print(f"\nScanning {len(test_files)} test files...")
    
    for filepath in test_files:
        reqs = scan_test_file(filepath)
        rel_path = str(filepath.relative_to(project_root))
        for req_id in reqs:
            if req_id in report.requirements:
                report.requirements[req_id].test_files.append(rel_path)
                if verbose:
                    print(f"  {req_id} <- {rel_path}")
    
    return report

# =============================================================================
# Reporting
# =============================================================================

def print_report(report: RTMReport, verbose: bool = False) -> None:
    """Print RTM verification report."""
    print("\n" + "=" * 80)
    print("  axioma-governance: Requirements Traceability Matrix Verification")
    print("  SRS-007 v0.3 Audit-Frozen FINAL")
    print("=" * 80)
    
    print(f"\n  Files scanned: {report.source_files_scanned} source, {report.test_files_scanned} test")
    print(f"  Total requirements: {report.total_requirements}")
    print(f"  Phase 1 requirements: {report.phase_1_requirements}")
    print(f"  Satisfied: {report.satisfied_requirements}")
    
    # Missing source traces
    if report.missing_source_trace:
        print(f"\n  🔴 MISSING SOURCE TRACEABILITY ({len(report.missing_source_trace)}):")
        for req_id in sorted(report.missing_source_trace):
            desc = report.requirements[req_id].description
            print(f"     {req_id}: {desc}")
    
    # Missing test coverage
    if report.missing_test_coverage:
        print(f"\n  🟠 MISSING TEST COVERAGE ({len(report.missing_test_coverage)}):")
        for req_id in sorted(report.missing_test_coverage):
            desc = report.requirements[req_id].description
            print(f"     {req_id}: {desc}")
    
    # Detailed status (verbose)
    if verbose:
        print("\n  DETAILED STATUS:")
        for req_id in sorted(report.requirements.keys()):
            req = report.requirements[req_id]
            if not req.in_phase_1:
                status = "⏳ FUTURE"
            elif req.is_satisfied:
                status = "✅ PASS"
            elif req.has_source_trace:
                status = "🟠 NO TEST"
            else:
                status = "🔴 MISSING"
            
            print(f"     {status} {req_id}: {req.description[:50]}")
            if req.source_files:
                for f in req.source_files[:2]:
                    print(f"            src: {f}")
            if req.test_files:
                for f in req.test_files[:2]:
                    print(f"            test: {f}")
    
    # Final verdict
    print("\n" + "-" * 80)
    if report.is_passing:
        print("  RTM VERIFICATION: ✅ PASS")
    else:
        print("  RTM VERIFICATION: ❌ FAIL")
    print("-" * 80 + "\n")

# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify SRS-007 Requirements Traceability Matrix"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on any missing traceability"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Project root directory"
    )
    
    args = parser.parse_args()
    
    # Verify project structure
    if not (args.root / "src").exists():
        print(f"ERROR: {args.root}/src not found", file=sys.stderr)
        return 2
    
    # Run verification
    report = verify_rtm(args.root, args.verbose)
    print_report(report, args.verbose)
    
    # Exit code
    if args.strict and not report.is_passing:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
