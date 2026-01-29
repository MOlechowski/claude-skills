#!/usr/bin/env python3
"""
speckit_tasks.py - Phase 5: TASKS

Generates task list from spec.md and plan.md.

Usage:
    speckit_tasks.py [OPTIONS]

Options:
    --json           Output in JSON format
    --help, -h       Show this help message

Examples:
    speckit_tasks.py
    speckit_tasks.py --json
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
    EXIT_BASH_ERROR,
    EXIT_MISSING_PREREQ,
    log_phase,
    validate_prerequisites,
    load_template,
    get_repo_root
)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 5: TASKS - Generate task list from spec and plan",
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


def parse_user_stories(spec_content: str) -> list:
    """
    Extract user stories from spec.md content.

    Looks for patterns like:
    - As a [user], I want [action] so that [benefit]
    - User stories section with bullet points
    """
    stories = []

    # Pattern 1: Standard user story format
    story_pattern = r"As an?\s+([^,]+),\s+I\s+want\s+([^,]+?)(?:,?\s+so\s+that\s+([^.]+))?"
    matches = re.finditer(story_pattern, spec_content, re.IGNORECASE)
    for match in matches:
        stories.append({
            "user": match.group(1).strip(),
            "action": match.group(2).strip(),
            "benefit": match.group(3).strip() if match.group(3) else ""
        })

    # Pattern 2: Numbered requirements
    req_pattern = r"^\s*\d+\.\s+(.+)$"
    for match in re.finditer(req_pattern, spec_content, re.MULTILINE):
        text = match.group(1).strip()
        if text and len(text) > 10:  # Filter out short items
            stories.append({
                "user": "user",
                "action": text,
                "benefit": ""
            })

    return stories


def extract_plan_phases(plan_content: str) -> list:
    """Extract phases from plan.md content."""
    phases = []

    # Look for phase headings
    phase_pattern = r"^##\s*Phase\s*(\d+)[:\s]*(.+?)$"
    matches = re.finditer(phase_pattern, plan_content, re.MULTILINE | re.IGNORECASE)

    for match in matches:
        phases.append({
            "number": int(match.group(1)),
            "name": match.group(2).strip()
        })

    return phases


def execute_phase(args, paths: dict) -> dict:
    """
    Execute Phase 5: TASKS.

    Generates tasks.md from spec.md and plan.md.
    """
    log_phase(5, "TASKS", "start")

    feature_dir = Path(paths.get("FEATURE_DIR", ""))
    spec_file = feature_dir / "spec.md"
    plan_file = feature_dir / "plan.md"
    tasks_file = feature_dir / "tasks.md"

    # Read spec.md
    if not spec_file.exists():
        log_phase(5, "TASKS", "error")
        return {
            "status": "error",
            "phase": 5,
            "error": f"spec.md not found: {spec_file}"
        }

    spec_content = spec_file.read_text()

    # Read plan.md
    if not plan_file.exists():
        log_phase(5, "TASKS", "error")
        return {
            "status": "error",
            "phase": 5,
            "error": f"plan.md not found: {plan_file}\nRun speckit_plan.py first."
        }

    plan_content = plan_file.read_text()

    # Parse user stories and phases
    user_stories = parse_user_stories(spec_content)
    phases = extract_plan_phases(plan_content)

    print(f"  {Status.INFO} Found {len(user_stories)} user stories")
    print(f"  {Status.INFO} Found {len(phases)} phases in plan")

    # Load tasks template
    template = load_template("tasks-template.md")
    if not template:
        # Create a basic template if not found
        template = """# Tasks

## Phase 1: Setup

- [ ] Task 1
- [ ] Task 2

## Phase 2: Implementation

- [ ] Task 3
- [ ] Task 4

## Phase 3: Testing

- [ ] Write tests
- [ ] Run tests
"""

    # Write tasks file (template for Claude to fill in)
    try:
        tasks_file.write_text(template)
        print(f"  {Status.SUCCESS} Created tasks.md: {tasks_file}")
    except Exception as e:
        log_phase(5, "TASKS", "error")
        return {
            "status": "error",
            "phase": 5,
            "error": f"Failed to write tasks.md: {e}"
        }

    log_phase(5, "TASKS", "complete")

    return {
        "status": "complete",
        "phase": 5,
        "tasks_file": str(tasks_file),
        "user_stories_count": len(user_stories),
        "phases_count": len(phases),
        "template_loaded": template is not None
    }


def main():
    args = parse_args()

    # Validate prerequisites (need plan.md)
    validation = validate_prerequisites(require_tasks=False)
    if not validation["valid"]:
        print(f"{Status.ERROR} {validation['error']}")
        sys.exit(EXIT_MISSING_PREREQ)

    paths = validation["paths"]
    print(f"{Status.RUNNING} Generating task list...")

    result = execute_phase(args, paths)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "complete":
            print(f"\n{Status.SUCCESS} Phase 5 complete: TASKS")
            print(f"  Tasks file: {result['tasks_file']}")
            print(f"  User stories: {result['user_stories_count']}")
            print(f"\n{Status.INFO} Next: Edit tasks.md, then run speckit_acceptance.py")
        else:
            print(f"\n{Status.ERROR} Phase 5 failed: {result.get('error', 'Unknown error')}")

    sys.exit(EXIT_SUCCESS if result["status"] == "complete" else EXIT_BASH_ERROR)


if __name__ == "__main__":
    main()
