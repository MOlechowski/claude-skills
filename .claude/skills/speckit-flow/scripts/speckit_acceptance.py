#!/usr/bin/env python3
"""
speckit_acceptance.py - Phase 6: ACCEPTANCE

Generates acceptance criteria, tests, and quality checklists from spec.md.

Usage:
    speckit_acceptance.py [OPTIONS]

Options:
    --type <type>    Force specific checklist type (api, ux, security, performance, general)
    --json           Output in JSON format
    --help, -h       Show this help message

Examples:
    speckit_acceptance.py
    speckit_acceptance.py --type api
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


# Domain keyword mappings
CHECKLIST_KEYWORDS = {
    "api": ["api", "endpoint", "rest", "graphql", "http", "request", "response", "route"],
    "ux": ["ui", "ux", "interface", "frontend", "user experience", "component", "page", "form", "button"],
    "security": ["auth", "security", "permission", "token", "password", "login", "role", "access"],
    "performance": ["performance", "latency", "throughput", "cache", "optimize", "speed", "load"]
}

# Checklist templates for each domain (with CHK-XXX numbering)
CHECKLIST_TEMPLATES = {
    "api": {
        "title": "API Quality",
        "items": [
            "All endpoints documented",
            "Request/response schemas defined",
            "Error responses specified",
            "Authentication requirements clear",
            "Input validation rules defined",
            "Required vs optional fields specified",
            "Data types documented",
            "Error codes defined",
            "Error message format consistent",
            "Edge cases covered",
            "Happy path tests planned",
            "Error case tests planned",
            "Integration tests planned",
        ]
    },
    "ux": {
        "title": "UX Quality",
        "items": [
            "All screens/pages identified",
            "Navigation flow documented",
            "Responsive design considered",
            "User journey mapped",
            "Error states designed",
            "Loading states designed",
            "Empty states designed",
            "Keyboard navigation",
            "Screen reader support",
            "Color contrast",
            "Focus indicators",
            "Usability testing planned",
            "Cross-browser testing",
            "Mobile testing",
        ]
    },
    "security": {
        "title": "Security Quality",
        "items": [
            "Auth method specified (JWT, OAuth, etc.)",
            "Session management defined",
            "Password requirements documented",
            "Role definitions clear",
            "Permission model documented",
            "Access control rules defined",
            "Sensitive data identified",
            "Encryption requirements specified",
            "Data retention policy defined",
            "Security testing planned",
            "Penetration testing scope",
            "Vulnerability scanning",
        ]
    },
    "performance": {
        "title": "Performance Quality",
        "items": [
            "Response time targets defined",
            "Throughput requirements specified",
            "Concurrent user estimates",
            "Caching strategy defined",
            "Database query optimization",
            "Asset optimization (images, JS, CSS)",
            "Performance metrics identified",
            "Alerting thresholds defined",
            "Profiling approach planned",
            "Load testing planned",
            "Stress testing scope",
            "Performance benchmarks defined",
        ]
    },
    "general": {
        "title": "General Quality",
        "items": [
            "All requirements documented",
            "Acceptance criteria defined",
            "Edge cases identified",
            "Architecture documented",
            "Dependencies identified",
            "Integration points clear",
            "Code structure planned",
            "Coding standards defined",
            "Documentation requirements",
            "Unit tests planned",
            "Integration tests planned",
            "Acceptance tests planned",
        ]
    }
}


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 6: ACCEPTANCE - Generate acceptance criteria, tests, and quality checklists",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Checklist Types:
    api         - API/endpoint specific checks
    ux          - User interface/experience checks
    security    - Security/auth checks
    performance - Performance/optimization checks
    general     - General quality checks

Examples:
    %(prog)s
    %(prog)s --type api
    %(prog)s --json
"""
    )
    parser.add_argument(
        "--type",
        choices=["api", "ux", "security", "performance", "general"],
        help="Force specific checklist type"
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


def detect_checklist_types(content: str) -> list:
    """
    Scan content for domain keywords to determine checklist types.

    Returns list of detected checklist types.
    """
    detected = []
    content_lower = content.lower()

    for checklist_type, keywords in CHECKLIST_KEYWORDS.items():
        # Count keyword matches
        match_count = sum(1 for kw in keywords if kw in content_lower)
        if match_count >= 2:  # Require at least 2 keyword matches
            detected.append({
                "type": checklist_type,
                "confidence": min(match_count / len(keywords), 1.0)
            })

    # Sort by confidence
    detected.sort(key=lambda x: x["confidence"], reverse=True)

    # Always include general if no specific matches
    if not detected:
        detected.append({"type": "general", "confidence": 1.0})

    return detected


def generate_quality_checklists(spec_content: str, forced_type: str = None) -> dict:
    """
    Generate quality checklists from spec content.

    Returns dict with checklist_types list and formatted checklist sections.
    """
    if forced_type:
        checklist_types = [{"type": forced_type, "confidence": 1.0}]
    else:
        checklist_types = detect_checklist_types(spec_content)

    sections = []
    chk_counter = 1

    for ct in checklist_types:
        ctype = ct["type"]
        template = CHECKLIST_TEMPLATES.get(ctype, CHECKLIST_TEMPLATES["general"])
        title = template["title"]
        items = template["items"]

        lines = [f"### {title}", ""]
        for item in items:
            lines.append(f"- [ ] CHK-{chk_counter:03d} {item}")
            chk_counter += 1
        lines.append("")

        sections.append("\n".join(lines))

    return {
        "checklist_types": [ct["type"] for ct in checklist_types],
        "checklists_count": chk_counter - 1,
        "sections_text": "\n".join(sections)
    }


def format_acceptance_content(criteria: list, test_cases: list, branch: str, checklist_data: dict = None) -> str:
    """Format acceptance criteria, tests, and quality checklists into markdown content."""
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
    ])

    # Add Quality Checklists section if checklist data provided
    if checklist_data and checklist_data.get("sections_text"):
        lines.extend([
            "---",
            "",
            "## Quality Checklists",
            "",
            checklist_data["sections_text"],
        ])

    lines.extend([
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
    Execute Phase 6: ACCEPTANCE.

    Generates acceptance.md from spec.md user stories and requirements,
    including quality checklists.
    """
    log_phase(6, "ACCEPTANCE", "start")

    feature_dir = Path(paths.get("FEATURE_DIR", ""))
    spec_file = feature_dir / "spec.md"
    tasks_file = feature_dir / "tasks.md"
    acceptance_file = feature_dir / "acceptance.md"

    # Read spec.md
    if not spec_file.exists():
        log_phase(6, "ACCEPTANCE", "error")
        return {
            "status": "error",
            "phase": 6,
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

    # Generate quality checklists (non-blocking)
    checklist_data = None
    checklist_types = []
    checklists_count = 0
    try:
        forced_type = getattr(args, 'type', None)
        if forced_type:
            print(f"  {Status.INFO} Using specified checklist type: {forced_type}")
        else:
            print(f"  {Status.RUNNING} Detecting checklist types from spec...")

        checklist_data = generate_quality_checklists(spec_content, forced_type)
        checklist_types = checklist_data.get("checklist_types", [])
        checklists_count = checklist_data.get("checklists_count", 0)
        print(f"  {Status.INFO} Detected checklist types: {', '.join(checklist_types)}")
        print(f"  {Status.INFO} Generated {checklists_count} checklist items")
    except Exception as e:
        print(f"  {Status.WARNING} Checklist generation failed (non-blocking): {e}")

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
        content = format_acceptance_content(criteria, test_cases, branch, checklist_data)
    else:
        # Use template as fallback
        content = template if template else format_acceptance_content([], [], branch, checklist_data)

    # Write acceptance file
    try:
        acceptance_file.write_text(content)
        print(f"  {Status.SUCCESS} Created acceptance.md: {acceptance_file}")
    except Exception as e:
        log_phase(6, "ACCEPTANCE", "error")
        return {
            "status": "error",
            "phase": 6,
            "error": f"Failed to write acceptance.md: {e}"
        }

    log_phase(6, "ACCEPTANCE", "complete")

    return {
        "status": "complete",
        "phase": 6,
        "acceptance_file": str(acceptance_file),
        "criteria_count": len(criteria),
        "test_cases_count": len(test_cases),
        "template_used": template is not None and not criteria,
        "checklist_types": checklist_types,
        "checklists_count": checklists_count
    }


def main():
    args = parse_args()

    # Validate prerequisites (need spec.md)
    validation = validate_prerequisites(require_tasks=False)
    if not validation["valid"]:
        print(f"{Status.ERROR} {validation['error']}")
        sys.exit(EXIT_MISSING_PREREQ)

    paths = validation["paths"]
    print(f"{Status.RUNNING} Generating acceptance criteria, tests, and quality checklists...")

    result = execute_phase(args, paths)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "complete":
            print(f"\n{Status.SUCCESS} Phase 6 complete: ACCEPTANCE")
            print(f"  Acceptance file: {result['acceptance_file']}")
            print(f"  Criteria: {result['criteria_count']}")
            print(f"  Test cases: {result['test_cases_count']}")
            print(f"  Checklist types: {', '.join(result.get('checklist_types', []))}")
            print(f"  Checklist items: {result.get('checklists_count', 0)}")
            print(f"\n{Status.INFO} Next: Review acceptance.md, then run speckit_pr.py")
        else:
            print(f"\n{Status.ERROR} Phase 6 failed: {result.get('error', 'Unknown error')}")

    sys.exit(EXIT_SUCCESS if result["status"] == "complete" else EXIT_BASH_ERROR)


if __name__ == "__main__":
    main()
