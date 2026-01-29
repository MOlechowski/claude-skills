#!/usr/bin/env python3
"""
speckit_validate.py - Validate spec artifacts

Validates spec.md, plan.md, tasks.md, and acceptance.md quality checklists before PR creation.

Usage:
    speckit_validate.py [FEATURE_DIR] [OPTIONS]

Options:
    --strict         Fail on warnings (not just errors)
    --json           Output in JSON format
    --help, -h       Show this help message

Examples:
    speckit_validate.py
    speckit_validate.py specs/001-my-feature
    speckit_validate.py --strict --json
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
    get_feature_paths,
    get_current_branch
)


# Validation result types
RESULT_PASS = "pass"
RESULT_WARN = "warn"
RESULT_FAIL = "fail"


# Unresolved marker patterns
UNRESOLVED_MARKERS = [
    (r"\[TODO\]", "TODO marker"),
    (r"\[TBD\]", "TBD marker"),
    (r"NEEDS CLARIFICATION", "Needs clarification"),
    (r"\[unclear\]", "Unclear marker"),
    (r"\[PLACEHOLDER\]", "Placeholder"),
    (r"XXX", "XXX marker"),
]

# Required sections for each file
SPEC_REQUIRED_SECTIONS = ["overview", "requirements"]
SPEC_RECOMMENDED_SECTIONS = ["user stories", "acceptance criteria"]
PLAN_REQUIRED_SECTIONS = ["tech stack", "architecture"]
PLAN_RECOMMENDED_SECTIONS = ["dependencies", "risks"]


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate spec artifacts (spec.md, plan.md, tasks.md, acceptance.md)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s
    %(prog)s specs/001-my-feature
    %(prog)s --strict --json
"""
    )
    parser.add_argument(
        "feature_dir",
        nargs="?",
        help="Feature directory to validate (default: current feature)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on warnings (not just errors)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    return parser.parse_args()


def check_file_exists(file_path: Path) -> tuple:
    """Check if file exists."""
    if file_path.exists():
        return RESULT_PASS, "File exists"
    return RESULT_FAIL, "File not found"


def check_sections(content: str, required: list, recommended: list) -> list:
    """Check for required and recommended sections."""
    results = []
    content_lower = content.lower()

    for section in required:
        if section in content_lower or f"## {section}" in content_lower:
            results.append((RESULT_PASS, f"Has {section} section"))
        else:
            results.append((RESULT_FAIL, f"Missing required section: {section}"))

    for section in recommended:
        if section in content_lower or f"## {section}" in content_lower:
            results.append((RESULT_PASS, f"Has {section} section"))
        else:
            results.append((RESULT_WARN, f"Missing recommended section: {section}"))

    return results


def check_unresolved_markers(content: str) -> list:
    """Check for unresolved markers in content."""
    results = []
    found_markers = []

    for pattern, description in UNRESOLVED_MARKERS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            found_markers.append(f"{description} ({len(matches)})")

    if found_markers:
        results.append((RESULT_FAIL, f"Unresolved markers: {', '.join(found_markers)}"))
    else:
        results.append((RESULT_PASS, "No unresolved markers"))

    return results


def check_tasks_format(content: str) -> list:
    """Check tasks.md format."""
    results = []

    # Check for checkbox format
    checkbox_pattern = r"^\s*-\s*\[([ xX])\]"
    tasks = re.findall(checkbox_pattern, content, re.MULTILINE)

    if tasks:
        completed = sum(1 for t in tasks if t.lower() == 'x')
        total = len(tasks)
        results.append((RESULT_PASS, f"Found {total} tasks ({completed} completed)"))
    else:
        results.append((RESULT_FAIL, "No tasks found (expected checkbox format: - [ ])"))

    # Check for empty phases
    phase_pattern = r"^##\s+(.+?)$"
    phases = re.findall(phase_pattern, content, re.MULTILINE)

    if phases:
        results.append((RESULT_PASS, f"Found {len(phases)} phases"))
    else:
        results.append((RESULT_WARN, "No phase sections found"))

    return results


def check_tech_stack(content: str) -> list:
    """Check if tech stack is defined in plan.md."""
    results = []

    # Look for language/version field
    lang_pattern = r"\*\*Language/Version\*\*:\s*(.+)"
    lang_match = re.search(lang_pattern, content)

    if lang_match:
        value = lang_match.group(1).strip()
        if "NEEDS CLARIFICATION" in value or not value:
            results.append((RESULT_WARN, "Language/Version not specified"))
        else:
            results.append((RESULT_PASS, f"Language defined: {value[:50]}"))
    else:
        results.append((RESULT_WARN, "Language/Version field not found"))

    return results


def check_acceptance_checklists(feature_dir: Path) -> dict:
    """Validate quality checklists section in acceptance.md."""
    results = []
    acceptance_file = feature_dir / "acceptance.md"

    if not acceptance_file.exists():
        results.append((RESULT_FAIL, "Missing acceptance.md with Quality Checklists section"))
        return {"file": "quality checklists", "results": results}

    content = acceptance_file.read_text()
    if "## Quality Checklists" not in content:
        results.append((RESULT_FAIL, "acceptance.md missing ## Quality Checklists section"))
        return {"file": "quality checklists", "results": results}

    chk_items = re.findall(r"CHK-\d+", content)
    if chk_items:
        results.append((RESULT_PASS, f"Quality checklists in acceptance.md ({len(chk_items)} items)"))
    else:
        results.append((RESULT_FAIL, "Quality Checklists section exists but has no CHK items"))

    return {"file": "quality checklists", "results": results}


def validate_spec(feature_dir: Path) -> dict:
    """Validate spec.md."""
    spec_file = feature_dir / "spec.md"
    results = []

    # Check file exists
    exists_result = check_file_exists(spec_file)
    results.append(exists_result)

    if exists_result[0] == RESULT_FAIL:
        return {"file": "spec.md", "results": results}

    content = spec_file.read_text()

    # Check sections
    results.extend(check_sections(content, SPEC_REQUIRED_SECTIONS, SPEC_RECOMMENDED_SECTIONS))

    # Check unresolved markers
    results.extend(check_unresolved_markers(content))

    return {"file": "spec.md", "results": results}


def validate_plan(feature_dir: Path) -> dict:
    """Validate plan.md."""
    plan_file = feature_dir / "plan.md"
    results = []

    # Check file exists
    exists_result = check_file_exists(plan_file)
    results.append(exists_result)

    if exists_result[0] == RESULT_FAIL:
        return {"file": "plan.md", "results": results}

    content = plan_file.read_text()

    # Check sections
    results.extend(check_sections(content, PLAN_REQUIRED_SECTIONS, PLAN_RECOMMENDED_SECTIONS))

    # Check tech stack
    results.extend(check_tech_stack(content))

    # Check unresolved markers
    results.extend(check_unresolved_markers(content))

    return {"file": "plan.md", "results": results}


def validate_tasks(feature_dir: Path) -> dict:
    """Validate tasks.md."""
    tasks_file = feature_dir / "tasks.md"
    results = []

    # Check file exists
    exists_result = check_file_exists(tasks_file)
    results.append(exists_result)

    if exists_result[0] == RESULT_FAIL:
        return {"file": "tasks.md", "results": results}

    content = tasks_file.read_text()

    # Check tasks format
    results.extend(check_tasks_format(content))

    # Check unresolved markers
    results.extend(check_unresolved_markers(content))

    return {"file": "tasks.md", "results": results}


def validate_branch() -> dict:
    """Validate feature branch naming."""
    results = []
    branch = get_current_branch()

    if re.match(r"^\d{3}-", branch):
        results.append((RESULT_PASS, f"Valid feature branch: {branch}"))
    elif branch in ["main", "master"]:
        results.append((RESULT_WARN, f"On {branch} branch, not a feature branch"))
    else:
        results.append((RESULT_WARN, f"Branch '{branch}' doesn't follow ###-name format"))

    return {"file": "branch", "results": results}


def validate_feature(feature_dir: Path) -> dict:
    """Run all validations on a feature directory."""
    validations = []

    # Validate branch
    validations.append(validate_branch())

    # Validate each file
    validations.append(validate_spec(feature_dir))
    validations.append(validate_plan(feature_dir))
    validations.append(validate_tasks(feature_dir))

    # Validate quality checklists in acceptance.md
    validations.append(check_acceptance_checklists(feature_dir))

    # Count results
    errors = 0
    warnings = 0
    passes = 0

    for v in validations:
        for result_type, _ in v["results"]:
            if result_type == RESULT_FAIL:
                errors += 1
            elif result_type == RESULT_WARN:
                warnings += 1
            else:
                passes += 1

    return {
        "feature_dir": str(feature_dir),
        "validations": validations,
        "summary": {
            "errors": errors,
            "warnings": warnings,
            "passes": passes
        }
    }


def print_results(validation_result: dict, json_output: bool = False):
    """Print validation results."""
    if json_output:
        print(json.dumps(validation_result, indent=2))
        return

    feature_dir = validation_result["feature_dir"]
    print(f"🔍 Validating feature: {Path(feature_dir).name}\n")

    for v in validation_result["validations"]:
        file_name = v["file"]
        print(f"{file_name}")

        for result_type, message in v["results"]:
            if result_type == RESULT_PASS:
                icon = Status.SUCCESS
            elif result_type == RESULT_WARN:
                icon = Status.WARNING
            else:
                icon = Status.ERROR
            print(f"  {icon} {message}")

        print()

    summary = validation_result["summary"]
    errors = summary["errors"]
    warnings = summary["warnings"]

    if errors == 0 and warnings == 0:
        print(f"{Status.SUCCESS} All checks passed!")
    else:
        parts = []
        if errors > 0:
            parts.append(f"{errors} error{'s' if errors != 1 else ''}")
        if warnings > 0:
            parts.append(f"{warnings} warning{'s' if warnings != 1 else ''}")
        print(f"Summary: {', '.join(parts)}")


def main():
    args = parse_args()

    # Determine feature directory
    if args.feature_dir:
        feature_dir = Path(args.feature_dir)
        if not feature_dir.exists():
            print(f"{Status.ERROR} Feature directory not found: {feature_dir}")
            sys.exit(EXIT_VALIDATION_ERROR)
    else:
        # Get from current branch
        paths = get_feature_paths()
        if "error" in paths:
            print(f"{Status.ERROR} {paths['error']}")
            sys.exit(EXIT_VALIDATION_ERROR)
        feature_dir = Path(paths.get("FEATURE_DIR", ""))

    if not feature_dir.exists():
        print(f"{Status.ERROR} Feature directory not found: {feature_dir}")
        sys.exit(EXIT_VALIDATION_ERROR)

    # Run validation
    result = validate_feature(feature_dir)

    # Print results
    print_results(result, args.json)

    # Determine exit code
    summary = result["summary"]
    if summary["errors"] > 0:
        sys.exit(EXIT_VALIDATION_ERROR)
    elif args.strict and summary["warnings"] > 0:
        sys.exit(2)  # Warnings with --strict
    else:
        sys.exit(EXIT_SUCCESS)


if __name__ == "__main__":
    main()
