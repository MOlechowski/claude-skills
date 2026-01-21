#!/usr/bin/env python3
"""
speckit_analyze.py - Phase 4: ANALYZE

Validates consistency across spec artifacts.

Usage:
    speckit_analyze.py [OPTIONS]

Options:
    --strict         Fail on HIGH severity issues (default: warn only)
    --json           Output in JSON format
    --help, -h       Show this help message

Examples:
    speckit_analyze.py
    speckit_analyze.py --strict --json
"""

import sys
import json
import re
import argparse
from pathlib import Path

# Add scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from common import (
    Status,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
    EXIT_MISSING_PREREQ,
    log_phase,
    validate_prerequisites
)


# Severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 4: ANALYZE - Validate consistency across artifacts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Severity Levels:
    CRITICAL  - Blocks further progress
    HIGH      - Significant issue, requires attention
    MEDIUM    - Minor inconsistency
    LOW       - Suggestion for improvement

Examples:
    %(prog)s
    %(prog)s --strict --json
"""
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on HIGH severity issues (default: warn only)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    return parser.parse_args()


def check_missing_sections(content: str, required_sections: list, file_name: str) -> list:
    """Check for missing required sections."""
    findings = []
    content_lower = content.lower()

    for section in required_sections:
        if section.lower() not in content_lower:
            findings.append({
                "severity": SEVERITY_MEDIUM,
                "category": "missing_section",
                "file": file_name,
                "message": f"Missing recommended section: {section}"
            })

    return findings


def check_empty_sections(content: str, file_name: str) -> list:
    """Check for empty sections (heading with no content)."""
    findings = []
    lines = content.split("\n")

    for i, line in enumerate(lines):
        if line.startswith("## "):
            # Check if next non-empty line is another heading or end of file
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1

            if j >= len(lines) or lines[j].startswith("#"):
                section_name = line.replace("##", "").strip()
                findings.append({
                    "severity": SEVERITY_HIGH,
                    "category": "empty_section",
                    "file": file_name,
                    "message": f"Empty section: {section_name}"
                })

    return findings


def check_unresolved_markers(content: str, file_name: str) -> list:
    """Check for unresolved placeholder markers."""
    findings = []

    markers = [
        (r"\[TODO\]", SEVERITY_HIGH, "Unresolved TODO"),
        (r"\[TBD\]", SEVERITY_HIGH, "Unresolved TBD"),
        (r"NEEDS CLARIFICATION", SEVERITY_CRITICAL, "Needs clarification marker"),
        (r"\[unclear\]", SEVERITY_HIGH, "Unclear marker"),
        (r"<placeholder>", SEVERITY_MEDIUM, "Placeholder text"),
        (r"XXX", SEVERITY_MEDIUM, "XXX marker"),
    ]

    for pattern, severity, description in markers:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            findings.append({
                "severity": severity,
                "category": "unresolved_marker",
                "file": file_name,
                "message": f"{description}: {match.group()}"
            })

    return findings


def check_spec_plan_consistency(spec_content: str, plan_content: str) -> list:
    """Check consistency between spec.md and plan.md."""
    findings = []

    # Check if plan references spec concepts
    # This is a simplified check - could be expanded

    # Extract key terms from spec (words in headings)
    spec_headings = re.findall(r"^#+\s+(.+)$", spec_content, re.MULTILINE)
    spec_terms = set()
    for heading in spec_headings:
        words = re.findall(r"\b[a-zA-Z]{4,}\b", heading.lower())
        spec_terms.update(words)

    # Check if plan mentions spec terms (basic coverage check)
    plan_lower = plan_content.lower()
    missing_terms = []
    for term in list(spec_terms)[:10]:  # Check first 10 terms
        if term not in plan_lower:
            missing_terms.append(term)

    if len(missing_terms) > 5:
        findings.append({
            "severity": SEVERITY_MEDIUM,
            "category": "consistency",
            "file": "plan.md",
            "message": f"Plan may not cover all spec topics. Missing terms: {', '.join(missing_terms[:5])}"
        })

    return findings


def execute_phase(args, paths: dict) -> dict:
    """
    Execute Phase 4: ANALYZE.

    Validates consistency across spec artifacts.
    """
    log_phase(4, "ANALYZE", "start")

    feature_dir = Path(paths.get("FEATURE_DIR", ""))
    spec_file = feature_dir / "spec.md"
    plan_file = feature_dir / "plan.md"

    findings = []

    # Check spec.md
    if spec_file.exists():
        spec_content = spec_file.read_text()
        print(f"  {Status.RUNNING} Analyzing spec.md...")

        findings.extend(check_empty_sections(spec_content, "spec.md"))
        findings.extend(check_unresolved_markers(spec_content, "spec.md"))
        findings.extend(check_missing_sections(
            spec_content,
            ["Overview", "Requirements", "User Stories"],
            "spec.md"
        ))
    else:
        findings.append({
            "severity": SEVERITY_CRITICAL,
            "category": "missing_file",
            "file": "spec.md",
            "message": "spec.md not found"
        })

    # Check plan.md
    if plan_file.exists():
        plan_content = plan_file.read_text()
        print(f"  {Status.RUNNING} Analyzing plan.md...")

        findings.extend(check_empty_sections(plan_content, "plan.md"))
        findings.extend(check_unresolved_markers(plan_content, "plan.md"))

        # Cross-artifact consistency
        if spec_file.exists():
            findings.extend(check_spec_plan_consistency(spec_content, plan_content))
    else:
        findings.append({
            "severity": SEVERITY_HIGH,
            "category": "missing_file",
            "file": "plan.md",
            "message": "plan.md not found"
        })

    # Count by severity
    severity_counts = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_HIGH: 0,
        SEVERITY_MEDIUM: 0,
        SEVERITY_LOW: 0
    }
    for finding in findings:
        severity_counts[finding["severity"]] += 1

    print(f"  {Status.INFO} Analysis complete: {len(findings)} findings")

    # Determine status based on findings
    status = "complete"
    if severity_counts[SEVERITY_CRITICAL] > 0:
        status = "blocked"
        log_phase(4, "ANALYZE", "error")
    elif args.strict and severity_counts[SEVERITY_HIGH] > 0:
        status = "warning"
        log_phase(4, "ANALYZE", "complete")
    else:
        log_phase(4, "ANALYZE", "complete")

    return {
        "status": status,
        "phase": 4,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "findings": findings
    }


def main():
    args = parse_args()

    # Validate prerequisites (basic check)
    paths = validate_prerequisites(require_tasks=False)
    if not paths.get("valid"):
        # Try to continue anyway for analysis
        from common import get_feature_paths
        paths = {"paths": get_feature_paths()}

    actual_paths = paths.get("paths", paths)
    print(f"{Status.RUNNING} Analyzing specification artifacts...")

    result = execute_phase(args, actual_paths)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{Status.SUCCESS if result['status'] == 'complete' else Status.WARNING} Phase 4 complete: ANALYZE")
        print(f"  Total findings: {result['total_findings']}")

        counts = result["severity_counts"]
        if counts[SEVERITY_CRITICAL] > 0:
            print(f"  {Status.ERROR} CRITICAL: {counts[SEVERITY_CRITICAL]}")
        if counts[SEVERITY_HIGH] > 0:
            print(f"  {Status.WARNING} HIGH: {counts[SEVERITY_HIGH]}")
        if counts[SEVERITY_MEDIUM] > 0:
            print(f"  {Status.INFO} MEDIUM: {counts[SEVERITY_MEDIUM]}")
        if counts[SEVERITY_LOW] > 0:
            print(f"  {Status.INFO} LOW: {counts[SEVERITY_LOW]}")

        if result["findings"]:
            print(f"\n{Status.INFO} Findings:")
            for f in result["findings"][:10]:  # Show first 10
                severity_icon = {
                    SEVERITY_CRITICAL: Status.ERROR,
                    SEVERITY_HIGH: Status.WARNING,
                    SEVERITY_MEDIUM: Status.INFO,
                    SEVERITY_LOW: Status.INFO
                }.get(f["severity"], Status.INFO)
                print(f"  {severity_icon} [{f['severity']}] {f['file']}: {f['message']}")

        if result["status"] == "blocked":
            print(f"\n{Status.ERROR} CRITICAL issues must be resolved before proceeding")
        elif result["status"] == "warning":
            print(f"\n{Status.WARNING} HIGH issues should be addressed")
        else:
            print(f"\n{Status.INFO} Next: Run speckit_tasks.py")

    exit_code = EXIT_SUCCESS
    if result["status"] == "blocked":
        exit_code = EXIT_VALIDATION_ERROR
    elif result["status"] == "warning" and args.strict:
        exit_code = EXIT_VALIDATION_ERROR

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
