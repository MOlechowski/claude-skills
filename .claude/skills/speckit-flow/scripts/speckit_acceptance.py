#!/usr/bin/env python3
"""
speckit_acceptance.py - Phase 5.5: ACCEPTANCE

Generates acceptance criteria and tests from spec.md user stories.

Usage:
    speckit_acceptance.py [OPTIONS]

Options:
    --json           Output in JSON format
    --help, -h       Show this help message

Examples:
    speckit_acceptance.py
    speckit_acceptance.py --json
"""

import sys
import json
import re
import argparse
from pathlib import Path
from datetime import date

# Add scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from common import (
    Status,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
    EXIT_BASH_ERROR,
    EXIT_MISSING_PREREQ,
    log_phase,
    validate_prerequisites,
    load_template,
    get_current_branch
)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 5.5: ACCEPTANCE - Generate acceptance criteria and tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s
    %(prog)s --json
"""
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    return parser.parse_args()


def parse_acceptance_criteria(spec_content: str) -> list:
    """
    Extract acceptance criteria from spec.md content.

    Looks for:
    - User stories (As a... I want... so that...)
    - Functional requirements (FR-XXX)
    - Success criteria (SC-XXX)
    - User scenarios (Given/When/Then)
    """
    criteria = []

    # Pattern 1: User stories
    story_pattern = r"As an?\s+([^,]+),\s+I\s+want\s+([^,]+?)(?:,?\s+so\s+that\s+([^.]+))?"
    for i, match in enumerate(re.finditer(story_pattern, spec_content, re.IGNORECASE), 1):
        user = match.group(1).strip()
        action = match.group(2).strip()
        benefit = match.group(3).strip() if match.group(3) else ""
        criteria.append({
            "id": f"AC-{i:03d}",
            "source": f"US-{i}",
            "user": user,
            "action": action,
            "benefit": benefit,
            "condition": f"{user} can {action}"
        })

    # Pattern 2: Functional requirements
    fr_pattern = r"###?\s*(FR-\d+)[:\s]*([^\n]+)"
    for match in re.finditer(fr_pattern, spec_content, re.IGNORECASE):
        fr_id = match.group(1).strip()
        description = match.group(2).strip()
        # Avoid duplicates by checking existing sources
        if not any(fr_id in c.get("source", "") for c in criteria):
            criteria.append({
                "id": f"AC-{len(criteria)+1:03d}",
                "source": fr_id,
                "user": "system",
                "action": description,
                "benefit": "",
                "condition": description
            })

    # Pattern 3: Success criteria
    sc_pattern = r"\|\s*(SC-\d+)\s*\|\s*([^|]+)\s*\|"
    for match in re.finditer(sc_pattern, spec_content):
        sc_id = match.group(1).strip()
        description = match.group(2).strip()
        if not any(sc_id in c.get("source", "") for c in criteria):
            criteria.append({
                "id": f"AC-{len(criteria)+1:03d}",
                "source": sc_id,
                "user": "system",
                "action": description,
                "benefit": "",
                "condition": description
            })

    return criteria


def generate_test_cases(criteria: list) -> list:
    """
    Generate acceptance test cases from criteria.

    Creates Gherkin scenarios for each acceptance criterion.
    """
    test_cases = []

    for criterion in criteria:
        test_id = criterion["id"].replace("AC-", "AT-")
        user = criterion.get("user", "user")
        action = criterion.get("action", "perform action")
        condition = criterion.get("condition", "condition is met")

        # Generate Gherkin scenario
        given = f"a {user} is authenticated" if user != "system" else "the system is running"
        when = f"the {user} {action}" if user != "system" else action
        then = condition

        test_cases.append({
            "id": test_id,
            "source_criterion": criterion["id"],
            "name": f"Test {criterion.get('source', criterion['id'])}",
            "gherkin": {
                "given": given,
                "when": when,
                "then": then
            }
        })

    return test_cases


def format_acceptance_content(criteria: list, test_cases: list, branch: str) -> str:
    """Format acceptance criteria and tests into markdown content."""
    today = date.today().isoformat()
    feature_name = branch.split("-", 1)[1] if "-" in branch else branch

    lines = [
        f"# Acceptance: {feature_name}",
        "",
        f"**Feature Branch**: `{branch}`",
        f"**Created**: {today}",
        "**Status**: Pending Acceptance",
        "",
        "## Acceptance Criteria",
        "",
    ]

    # Add criteria
    for criterion in criteria:
        lines.extend([
            f"### {criterion['id']}: {criterion.get('condition', 'Criterion')[:50]}",
            "",
            f"- **Source**: {criterion.get('source', 'N/A')}",
            f"- **Condition**: {criterion.get('condition', 'TBD')}",
            "- **Verified**: [ ] Pass / [ ] Fail",
            "",
        ])

    lines.extend([
        "---",
        "",
        "## Acceptance Tests",
        "",
    ])

    # Add test cases
    for test in test_cases:
        gherkin = test.get("gherkin", {})
        lines.extend([
            f"### {test['id']}: {test.get('name', 'Test')}",
            "",
            "```gherkin",
            f"Feature: {feature_name}",
            "",
            f"  Scenario: {test.get('name', 'Scenario')}",
            f"    Given {gherkin.get('given', 'precondition')}",
            f"    When {gherkin.get('when', 'action')}",
            f"    Then {gherkin.get('then', 'result')}",
            "```",
            "",
            "**Status**: [ ] Pass / [ ] Fail",
            "**Tested By**: [Name]",
            "**Date**: [Date]",
            "",
        ])

    lines.extend([
        "---",
        "",
        "## Automated Test Coverage",
        "",
        "- [ ] Unit tests cover acceptance criteria",
        "- [ ] Integration tests passing",
        "- [ ] E2E scenarios implemented in test framework",
        "",
        "---",
        "",
        "## Sign-off Checklist",
        "",
        "| Role | Name | Date | Signature |",
        "|------|------|------|-----------|",
        "| Developer | | | [ ] Approved |",
        "| QA | | | [ ] Approved |",
        "| Product Owner | | | [ ] Approved |",
        "",
        "---",
        "",
        "## Notes",
        "",
        "[Any additional acceptance notes]",
    ])

    return "\n".join(lines)


def execute_phase(args, paths: dict) -> dict:
    """
    Execute Phase 5.5: ACCEPTANCE.

    Generates acceptance.md from spec.md user stories and requirements.
    """
    log_phase(5, "ACCEPTANCE", "start")  # Using 5 since we can't use 5.5

    feature_dir = Path(paths.get("FEATURE_DIR", ""))
    spec_file = feature_dir / "spec.md"
    tasks_file = feature_dir / "tasks.md"
    acceptance_file = feature_dir / "acceptance.md"

    # Read spec.md
    if not spec_file.exists():
        log_phase(5, "ACCEPTANCE", "error")
        return {
            "status": "error",
            "phase": "5.5",
            "error": f"spec.md not found: {spec_file}"
        }

    spec_content = spec_file.read_text()

    # Check tasks.md exists (optional, for better context)
    tasks_exist = tasks_file.exists()
    if tasks_exist:
        print(f"  {Status.INFO} Found tasks.md for context")

    # Parse acceptance criteria from spec
    print(f"  {Status.RUNNING} Parsing acceptance criteria from spec...")
    criteria = parse_acceptance_criteria(spec_content)
    print(f"  {Status.INFO} Found {len(criteria)} acceptance criteria")

    # Generate test cases
    print(f"  {Status.RUNNING} Generating acceptance tests...")
    test_cases = generate_test_cases(criteria)
    print(f"  {Status.INFO} Generated {len(test_cases)} test cases")

    # Get branch name for template
    branch = get_current_branch()

    # Try to load template first, fall back to generated content
    template = load_template("acceptance-template.md")
    if template and not criteria:
        # Use template as-is if no criteria found
        content = template
        print(f"  {Status.INFO} Using acceptance template (no criteria parsed)")
    elif criteria:
        # Generate content from parsed criteria
        content = format_acceptance_content(criteria, test_cases, branch)
    else:
        # Use template as fallback
        content = template if template else format_acceptance_content([], [], branch)

    # Write acceptance file
    try:
        acceptance_file.write_text(content)
        print(f"  {Status.SUCCESS} Created acceptance.md: {acceptance_file}")
    except Exception as e:
        log_phase(5, "ACCEPTANCE", "error")
        return {
            "status": "error",
            "phase": "5.5",
            "error": f"Failed to write acceptance.md: {e}"
        }

    log_phase(5, "ACCEPTANCE", "complete")

    return {
        "status": "complete",
        "phase": "5.5",
        "acceptance_file": str(acceptance_file),
        "criteria_count": len(criteria),
        "test_cases_count": len(test_cases),
        "template_used": template is not None and not criteria
    }


def main():
    args = parse_args()

    # Validate prerequisites (need spec.md)
    validation = validate_prerequisites(require_tasks=False)
    if not validation["valid"]:
        print(f"{Status.ERROR} {validation['error']}")
        sys.exit(EXIT_MISSING_PREREQ)

    paths = validation["paths"]
    print(f"{Status.RUNNING} Generating acceptance criteria and tests...")

    result = execute_phase(args, paths)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "complete":
            print(f"\n{Status.SUCCESS} Phase 5.5 complete: ACCEPTANCE")
            print(f"  Acceptance file: {result['acceptance_file']}")
            print(f"  Criteria: {result['criteria_count']}")
            print(f"  Test cases: {result['test_cases_count']}")
            print(f"\n{Status.INFO} Next: Edit acceptance.md, then run speckit_checklist.py")
        else:
            print(f"\n{Status.ERROR} Phase 5.5 failed: {result.get('error', 'Unknown error')}")

    sys.exit(EXIT_SUCCESS if result["status"] == "complete" else EXIT_BASH_ERROR)


if __name__ == "__main__":
    main()
