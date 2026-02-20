#!/usr/bin/env python3
"""
speckit_validate.py - Comprehensive spec artifact validation

Validates spec.md, plan.md, tasks.md, and acceptance.md quality checklists against speckit-flow requirements.

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

# Fix types
FIX_TEMPLATE = "template"  # Section missing - show full template

# Task count limit
MAX_TASKS = 20

# Unresolved marker patterns
UNRESOLVED_MARKERS = [
    (r"\[TODO\]", "TODO marker"),
    (r"\[TBD\]", "TBD marker"),
    (r"NEEDS CLARIFICATION", "Needs clarification"),
    (r"\[unclear\]", "Unclear marker"),
    (r"\[PLACEHOLDER\]", "Placeholder"),
    (r"XXX", "XXX marker"),
]

# Required and recommended sections
SPEC_REQUIRED_SECTIONS = [
    "overview",
    "user scenarios",
    "requirements",
    "success criteria",
    "edge cases",
    "out of scope"
]
SPEC_RECOMMENDED_SECTIONS = ["acceptance criteria"]

PLAN_REQUIRED_SECTIONS = [
    "tech stack",
    "risks"
]
PLAN_RECOMMENDED_SECTIONS = ["rollback plan", "verification checklist"]

# Task categories
TASK_CATEGORIES = ["component", "integration", "verification"]

# Fix templates for missing sections
FIX_TEMPLATES = {
    "missing_user_scenarios": """
## User Scenarios

### US-1: [Scenario Name]

```gherkin
Given [precondition]
When [action]
Then [expected result]
```
""",
    "missing_success_criteria": """
## Success Criteria

| ID | Criteria | Validation |
|----|----------|------------|
| SC-1 | [What must be true] | [How to verify] |
| SC-2 | [What must be true] | [How to verify] |
""",
    "missing_edge_cases": """
## Edge Cases

| Case | Behavior | Mitigation |
|------|----------|------------|
| [failure mode] | [what happens] | [how to handle] |
""",
    "missing_out_of_scope": """
## Out of Scope

- [Feature or capability not included]
- [Boundary of this spec]
""",
    "missing_tech_stack": """
## Tech Stack

| Category | Technology | Version |
|----------|------------|---------|
| Language | Python | >= 3.11 |
| Framework | FastAPI | ~2.0 |
""",
    "missing_risks": """
## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| [what could go wrong] | Low/Medium/High | Low/Medium/High | [how to prevent/handle] |
""",
    "missing_quality_checklists": """
Add a Quality Checklists section to acceptance.md:

## Quality Checklists

### General Quality

- [ ] CHK-001 All requirements documented
- [ ] CHK-002 Acceptance criteria defined
- [ ] CHK-003 Edge cases identified

Run speckit_acceptance.py to auto-generate this section.
"""
}


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


def make_result(status: str, message: str, fix_type: str = None, fix: str = None) -> tuple:
    """Create a validation result tuple."""
    return (status, message, fix_type, fix)


def check_file_exists(file_path: Path) -> tuple:
    """Check if file exists."""
    if file_path.exists():
        return make_result(RESULT_PASS, "File exists")
    return make_result(RESULT_FAIL, "File not found")


def check_sections(content: str, required: list, recommended: list) -> list:
    """Check for required and recommended sections."""
    results = []
    content_lower = content.lower()

    for section in required:
        # Check for section header or inline reference
        section_patterns = [
            f"## {section}",
            f"### {section}",
            f"# {section}",
            section
        ]
        found = any(p in content_lower for p in section_patterns)

        if found:
            results.append(make_result(RESULT_PASS, f"Has {section} section"))
        else:
            # Missing section - show template
            fix_key = f"missing_{section.replace(' ', '_')}"
            fix = FIX_TEMPLATES.get(fix_key)
            results.append(make_result(
                RESULT_FAIL,
                f"Missing required section: {section}",
                FIX_TEMPLATE if fix else None,
                fix
            ))

    for section in recommended:
        section_patterns = [f"## {section}", f"### {section}", section]
        found = any(p in content_lower for p in section_patterns)

        if found:
            results.append(make_result(RESULT_PASS, f"Has {section} section"))
        else:
            # Missing recommended - no template (just warning)
            results.append(make_result(RESULT_WARN, f"Missing recommended section: {section}"))

    return results


def check_gherkin_format(content: str) -> tuple:
    """Check if User Scenarios use Gherkin format."""
    content_lower = content.lower()

    # Check for Given/When/Then pattern
    has_given = "given " in content_lower
    has_when = "when " in content_lower
    has_then = "then " in content_lower

    if has_given and has_when and has_then:
        return make_result(RESULT_PASS, "User scenarios use Gherkin format")

    # Section exists but malformed - no template
    return make_result(RESULT_FAIL, "User scenarios missing Gherkin format (add Given/When/Then)")


def check_success_criteria_format(content: str) -> tuple:
    """Check for SC-XXX format in success criteria."""
    # Look for SC-1, SC-01, SC-001 patterns
    if re.search(r'\bSC-\d+\b', content):
        return make_result(RESULT_PASS, "Success criteria use SC-XXX format")

    # Section exists but wrong format - no template
    return make_result(RESULT_WARN, "Success criteria not using SC-XXX format")


def check_requirements_format(content: str) -> tuple:
    """Check for FR-XXX and NFR-XXX format in requirements."""
    has_fr = bool(re.search(r'\bFR-\d+\b', content))
    has_nfr = bool(re.search(r'\bNFR-\d+\b', content))

    if has_fr and has_nfr:
        return make_result(RESULT_PASS, "Requirements use FR-XXX and NFR-XXX format")
    elif has_fr:
        return make_result(RESULT_PASS, "Requirements use FR-XXX format")

    # Section exists but wrong format - no template
    return make_result(RESULT_WARN, "Requirements not using FR-XXX/NFR-XXX format")


def check_tech_stack_table(content: str) -> tuple:
    """Check if tech stack section has table format."""
    # Find tech stack section
    tech_stack_match = re.search(
        r'##\s*tech\s*stack(.*?)(?=##|\Z)',
        content,
        re.IGNORECASE | re.DOTALL
    )

    if not tech_stack_match:
        # Missing section - show template
        return make_result(
            RESULT_FAIL,
            "Missing Tech Stack section",
            FIX_TEMPLATE,
            FIX_TEMPLATES.get("missing_tech_stack")
        )

    section_content = tech_stack_match.group(1)

    # Check for table format (| delimiter)
    if '|' in section_content and '---' in section_content:
        return make_result(RESULT_PASS, "Tech Stack uses table format")

    # Section exists but wrong format - no template
    return make_result(RESULT_WARN, "Tech Stack section should use table format")


def check_risks_table(content: str) -> tuple:
    """Check if risks section exists and has table format."""
    # Find risks section
    risks_match = re.search(
        r'##\s*risks(.*?)(?=##|\Z)',
        content,
        re.IGNORECASE | re.DOTALL
    )

    if not risks_match:
        # Missing section - show template
        return make_result(
            RESULT_FAIL,
            "Missing Risks section",
            FIX_TEMPLATE,
            FIX_TEMPLATES.get("missing_risks")
        )

    section_content = risks_match.group(1)

    # Check for table format
    if '|' in section_content and '---' in section_content:
        return make_result(RESULT_PASS, "Risks section uses table format")

    # Section exists but wrong format - no template
    return make_result(RESULT_WARN, "Risks section should use table format")


def check_unresolved_markers(content: str) -> list:
    """Check for unresolved markers in content."""
    results = []
    found_markers = []

    for pattern, description in UNRESOLVED_MARKERS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            found_markers.append(f"{description} ({len(matches)})")

    if found_markers:
        # Content issue - no template
        results.append(make_result(RESULT_FAIL, f"Unresolved markers: {', '.join(found_markers)}"))
    else:
        results.append(make_result(RESULT_PASS, "No unresolved markers"))

    return results


def check_tasks_format(content: str) -> list:
    """Check tasks.md format and constraints."""
    results = []

    # Check for checkbox format
    checkbox_pattern = r"^\s*-\s*\[([ xX~-])\]"
    tasks = re.findall(checkbox_pattern, content, re.MULTILINE)

    if tasks:
        completed = sum(1 for t in tasks if t.lower() == 'x')
        total = len(tasks)
        results.append(make_result(RESULT_PASS, f"Found {total} tasks ({completed} completed)"))

        # Check task count limit
        if total > MAX_TASKS:
            # Content issue - no template (user needs to split, not add)
            results.append(make_result(
                RESULT_FAIL,
                f"Task count ({total}) exceeds limit ({MAX_TASKS}) - split into multiple specs"
            ))
        else:
            results.append(make_result(RESULT_PASS, f"Task count within limit ({total}/{MAX_TASKS})"))
    else:
        results.append(make_result(RESULT_FAIL, "No tasks found (expected checkbox format: - [ ])"))

    # Check for phase structure
    phase_pattern = r"^##\s+(.+?)$"
    phases = re.findall(phase_pattern, content, re.MULTILINE)

    if phases:
        results.append(make_result(RESULT_PASS, f"Found {len(phases)} phases"))
    else:
        results.append(make_result(RESULT_WARN, "No phase sections found"))

    return results


def check_task_categories(content: str) -> list:
    """Check for Component/Integration/Verification task categories."""
    results = []
    content_lower = content.lower()

    found_categories = []
    missing_categories = []

    for category in TASK_CATEGORIES:
        # Look for category headers
        patterns = [
            f"### {category}",
            f"## {category}",
            f"{category} tasks"
        ]
        if any(p in content_lower for p in patterns):
            found_categories.append(category)
        else:
            missing_categories.append(category)

    if len(found_categories) == len(TASK_CATEGORIES):
        results.append(make_result(RESULT_PASS, "Has all task categories (Component/Integration/Verification)"))
    elif found_categories:
        # Partial - just warn, no template
        results.append(make_result(
            RESULT_WARN,
            f"Missing task categories: {', '.join(missing_categories)}"
        ))
    else:
        # No categories at all - just warn, no template
        results.append(make_result(
            RESULT_WARN,
            "No task categories found (expected: Component, Integration, Verification)"
        ))

    return results


def check_acceptance_checklists(feature_dir: Path) -> dict:
    """Validate quality checklists section in acceptance.md."""
    results = []
    acceptance_file = feature_dir / "acceptance.md"

    if not acceptance_file.exists():
        results.append(make_result(
            RESULT_FAIL,
            "Missing acceptance.md with Quality Checklists section",
            FIX_TEMPLATE,
            FIX_TEMPLATES.get("missing_quality_checklists")
        ))
        return {"file": "quality checklists", "results": results}

    content = acceptance_file.read_text()
    if "## Quality Checklists" not in content:
        results.append(make_result(
            RESULT_FAIL,
            "acceptance.md missing ## Quality Checklists section",
            FIX_TEMPLATE,
            FIX_TEMPLATES.get("missing_quality_checklists")
        ))
        return {"file": "quality checklists", "results": results}

    chk_items = re.findall(r"CHK-\d+", content)
    if chk_items:
        results.append(make_result(RESULT_PASS, f"Quality checklists in acceptance.md ({len(chk_items)} items)"))
    else:
        results.append(make_result(
            RESULT_FAIL,
            "Quality Checklists section exists but has no CHK items",
            FIX_TEMPLATE,
            FIX_TEMPLATES.get("missing_quality_checklists")
        ))

    return {"file": "quality checklists", "results": results}


def validate_spec(feature_dir: Path) -> dict:
    """Validate spec.md comprehensively."""
    spec_file = feature_dir / "spec.md"
    results = []

    # Check file exists
    exists_result = check_file_exists(spec_file)
    results.append(exists_result)

    if exists_result[0] == RESULT_FAIL:
        return {"file": "spec.md", "results": results}

    content = spec_file.read_text()

    # Check required sections
    results.extend(check_sections(content, SPEC_REQUIRED_SECTIONS, SPEC_RECOMMENDED_SECTIONS))

    # Check Gherkin format if user scenarios exist
    if "user scenario" in content.lower():
        results.append(check_gherkin_format(content))

    # Check success criteria format
    if "success criteria" in content.lower():
        results.append(check_success_criteria_format(content))

    # Check requirements format
    if "requirements" in content.lower():
        results.append(check_requirements_format(content))

    # Check unresolved markers
    results.extend(check_unresolved_markers(content))

    return {"file": "spec.md", "results": results}


def validate_plan(feature_dir: Path) -> dict:
    """Validate plan.md comprehensively."""
    plan_file = feature_dir / "plan.md"
    results = []

    # Check file exists
    exists_result = check_file_exists(plan_file)
    results.append(exists_result)

    if exists_result[0] == RESULT_FAIL:
        return {"file": "plan.md", "results": results}

    content = plan_file.read_text()

    # Check tech stack with table format
    results.append(check_tech_stack_table(content))

    # Check risks with table format
    results.append(check_risks_table(content))

    # Check other sections
    results.extend(check_sections(content, [], PLAN_RECOMMENDED_SECTIONS))

    # Check unresolved markers
    results.extend(check_unresolved_markers(content))

    return {"file": "plan.md", "results": results}


def validate_tasks(feature_dir: Path) -> dict:
    """Validate tasks.md comprehensively."""
    tasks_file = feature_dir / "tasks.md"
    results = []

    # Check file exists
    exists_result = check_file_exists(tasks_file)
    results.append(exists_result)

    if exists_result[0] == RESULT_FAIL:
        return {"file": "tasks.md", "results": results}

    content = tasks_file.read_text()

    # Check tasks format and count
    results.extend(check_tasks_format(content))

    # Check task categories
    results.extend(check_task_categories(content))

    # Check unresolved markers
    results.extend(check_unresolved_markers(content))

    return {"file": "tasks.md", "results": results}


def validate_branch() -> dict:
    """Validate feature branch naming."""
    results = []
    branch = get_current_branch()

    if re.match(r"^\d{3}-", branch):
        results.append(make_result(RESULT_PASS, f"Valid feature branch: {branch}"))
    elif branch in ["main", "master"]:
        results.append(make_result(RESULT_WARN, f"On {branch} branch, not a feature branch"))
    else:
        results.append(make_result(RESULT_WARN, f"Branch '{branch}' doesn't follow ###-name format"))

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
        for result in v["results"]:
            result_type = result[0]
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
        # Convert tuples to dicts for JSON
        output = {
            "feature_dir": validation_result["feature_dir"],
            "validations": [],
            "summary": validation_result["summary"]
        }
        for v in validation_result["validations"]:
            file_results = []
            for result in v["results"]:
                file_results.append({
                    "status": result[0],
                    "message": result[1],
                    "fix_type": result[2] if len(result) > 2 else None,
                    "fix": result[3] if len(result) > 3 else None
                })
            output["validations"].append({
                "file": v["file"],
                "results": file_results
            })
        print(json.dumps(output, indent=2))
        return

    feature_dir = validation_result["feature_dir"]
    print(f"🔍 Validating feature: {Path(feature_dir).name}\n")

    templates_to_show = []

    for v in validation_result["validations"]:
        file_name = v["file"]
        print(f"{file_name}")

        for result in v["results"]:
            result_type = result[0]
            message = result[1]
            fix_type = result[2] if len(result) > 2 else None
            fix = result[3] if len(result) > 3 else None

            if result_type == RESULT_PASS:
                icon = Status.SUCCESS
            elif result_type == RESULT_WARN:
                icon = Status.WARNING
            else:
                icon = Status.ERROR

            print(f"  {icon} {message}")

            # Collect templates for missing sections only
            if fix_type == FIX_TEMPLATE and fix:
                templates_to_show.append((message, fix))

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

    # Auto-show templates for missing sections
    if templates_to_show:
        print("\n" + "─" * 50)
        for issue, fix in templates_to_show:
            print(f"\n📋 FIX: {issue}")
            print(fix)
        print("─" * 50)


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
