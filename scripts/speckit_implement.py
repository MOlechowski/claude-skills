#!/usr/bin/env python3
"""
speckit_implement.py - Phase 8: IMPLEMENT

Executes implementation tasks (conditional on implementation repo).

Usage:
    speckit_implement.py [OPTIONS]

Options:
    --force          Run even in non-implementation repos
    --json           Output in JSON format
    --help, -h       Show this help message

Examples:
    speckit_implement.py
    speckit_implement.py --force
    speckit_implement.py --json
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
    validate_prerequisites,
    is_impl_repo
)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 8: IMPLEMENT - Execute implementation tasks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This phase only runs in implementation repos (repos with source directories
like src/, lib/, app/, or project files like package.json, go.mod, etc.)

Examples:
    %(prog)s
    %(prog)s --force
    %(prog)s --json
"""
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Run even in non-implementation repos"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    return parser.parse_args()


def parse_tasks(tasks_content: str) -> list:
    """
    Parse tasks.md content to extract tasks.

    Returns list of task dictionaries.
    """
    tasks = []
    current_phase = "Unknown"

    lines = tasks_content.split("\n")
    for line in lines:
        # Detect phase headings
        if line.startswith("## "):
            current_phase = line.replace("##", "").strip()
            continue

        # Detect tasks (checkbox items)
        task_match = re.match(r"^\s*-\s*\[([ xX])\]\s*(.+)$", line)
        if task_match:
            completed = task_match.group(1).lower() == "x"
            description = task_match.group(2).strip()

            # Check for parallel marker [P]
            is_parallel = "[P]" in description
            description = description.replace("[P]", "").strip()

            tasks.append({
                "phase": current_phase,
                "description": description,
                "completed": completed,
                "parallel": is_parallel
            })

    return tasks


def calculate_progress(tasks: list) -> dict:
    """Calculate task completion progress."""
    total = len(tasks)
    completed = sum(1 for t in tasks if t["completed"])

    return {
        "total": total,
        "completed": completed,
        "remaining": total - completed,
        "percentage": round(completed / total * 100, 1) if total > 0 else 0
    }


def execute_phase(args, paths: dict) -> dict:
    """
    Execute Phase 8: IMPLEMENT.

    Tracks and orchestrates implementation tasks.
    """
    log_phase(8, "IMPLEMENT", "start")

    # Check if implementation repo
    if not args.force and not is_impl_repo():
        print(f"  {Status.SKIP} Not an implementation repo")
        log_phase(8, "IMPLEMENT", "skip")
        return {
            "status": "skipped",
            "phase": 8,
            "reason": "not_impl_repo",
            "message": "This repo doesn't appear to be an implementation repo. Use --force to override."
        }

    feature_dir = Path(paths.get("FEATURE_DIR", ""))
    tasks_file = feature_dir / "tasks.md"

    if not tasks_file.exists():
        log_phase(8, "IMPLEMENT", "error")
        return {
            "status": "error",
            "phase": 8,
            "error": f"tasks.md not found: {tasks_file}\nRun speckit_tasks.py first."
        }

    # Parse tasks
    print(f"  {Status.RUNNING} Loading tasks...")
    tasks_content = tasks_file.read_text()
    tasks = parse_tasks(tasks_content)

    if not tasks:
        print(f"  {Status.WARNING} No tasks found in tasks.md")
        log_phase(8, "IMPLEMENT", "complete")
        return {
            "status": "complete",
            "phase": 8,
            "message": "No tasks found",
            "progress": {"total": 0, "completed": 0, "remaining": 0, "percentage": 100}
        }

    # Calculate progress
    progress = calculate_progress(tasks)
    print(f"  {Status.INFO} Tasks: {progress['completed']}/{progress['total']} completed ({progress['percentage']}%)")

    # Group tasks by phase
    phases = {}
    for task in tasks:
        phase = task["phase"]
        if phase not in phases:
            phases[phase] = []
        phases[phase].append(task)

    # Report on phases
    print(f"  {Status.INFO} Phases:")
    for phase_name, phase_tasks in phases.items():
        phase_completed = sum(1 for t in phase_tasks if t["completed"])
        phase_total = len(phase_tasks)
        status_icon = Status.SUCCESS if phase_completed == phase_total else Status.RUNNING
        print(f"    {status_icon} {phase_name}: {phase_completed}/{phase_total}")

    # Find remaining tasks
    remaining_tasks = [t for t in tasks if not t["completed"]]

    if remaining_tasks:
        print(f"\n  {Status.INFO} Next tasks to complete:")
        for task in remaining_tasks[:5]:  # Show first 5
            parallel_marker = " [P]" if task["parallel"] else ""
            print(f"    - [ ] {task['description']}{parallel_marker}")

        if len(remaining_tasks) > 5:
            print(f"    ... and {len(remaining_tasks) - 5} more")

    log_phase(8, "IMPLEMENT", "complete")

    return {
        "status": "complete",
        "phase": 8,
        "progress": progress,
        "phases": {name: len(tasks) for name, tasks in phases.items()},
        "remaining_tasks": [t["description"] for t in remaining_tasks[:10]]
    }


def main():
    args = parse_args()

    # Validate prerequisites (need tasks.md)
    validation = validate_prerequisites(require_tasks=True)
    if not validation["valid"]:
        # Try without requiring tasks for better error message
        validation = validate_prerequisites(require_tasks=False)
        if not validation["valid"]:
            print(f"{Status.ERROR} {validation['error']}")
            sys.exit(EXIT_MISSING_PREREQ)

    paths = validation["paths"]
    print(f"{Status.RUNNING} Checking implementation status...")

    result = execute_phase(args, paths)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "complete":
            progress = result.get("progress", {})
            print(f"\n{Status.SUCCESS} Phase 8 complete: IMPLEMENT")
            print(f"  Progress: {progress.get('completed', 0)}/{progress.get('total', 0)} tasks ({progress.get('percentage', 0)}%)")

            if progress.get("remaining", 0) > 0:
                print(f"\n{Status.INFO} Implementation in progress. Mark tasks complete in tasks.md as you work.")
            else:
                print(f"\n{Status.SUCCESS} All tasks completed!")
        elif result["status"] == "skipped":
            print(f"\n{Status.SKIP} Phase 8 skipped: {result.get('reason', 'unknown')}")
            print(f"  {result.get('message', '')}")
        else:
            print(f"\n{Status.ERROR} Phase 8 failed: {result.get('error', 'Unknown error')}")

    sys.exit(EXIT_SUCCESS if result["status"] in ["complete", "skipped"] else EXIT_VALIDATION_ERROR)


if __name__ == "__main__":
    main()
