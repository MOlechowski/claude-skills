#!/usr/bin/env python3
"""
speckit_specify.py - Phase 1: CREATE (Specification)

Creates a new feature specification by generating a branch and spec.md file.

Usage:
    speckit_specify.py <feature-description> [OPTIONS]

Options:
    --short-name <name>  Custom short name for branch (2-4 words)
    --number <N>         Specify branch number manually
    --json               Output in JSON format
    --help, -h           Show this help message

Examples:
    speckit_specify.py "Add user authentication system"
    speckit_specify.py "OAuth2 integration" --short-name "oauth-api"
    speckit_specify.py "New dashboard feature" --number 5 --json
"""

import sys
import json
import argparse
from pathlib import Path

# Add scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from common import (
    Status,
    EXIT_SUCCESS,
    EXIT_VALIDATION_ERROR,
    EXIT_BASH_ERROR,
    log_phase,
    run_bash_script,
    get_repo_root
)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 1: CREATE (Specification) - Create feature branch and spec.md",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s "Add user authentication system"
    %(prog)s "OAuth2 integration" --short-name "oauth-api"
    %(prog)s "New dashboard feature" --number 5 --json
"""
    )
    parser.add_argument(
        "description",
        nargs="?",
        help="Feature description (can also be passed via stdin)"
    )
    parser.add_argument(
        "--short-name",
        help="Custom short name for branch (2-4 words)"
    )
    parser.add_argument(
        "--number",
        type=int,
        help="Specify branch number manually"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    args = parser.parse_args()

    # Try to get description from stdin if not provided
    if not args.description and not sys.stdin.isatty():
        args.description = sys.stdin.read().strip()

    if not args.description:
        parser.error("Feature description required")

    return args


def execute_phase(args) -> dict:
    """
    Execute Phase 1: CREATE (Specification).

    Wraps create-new-feature.sh to:
    - Generate a feature branch name
    - Create the branch (if git available)
    - Create spec.md from template
    """
    log_phase(1, "CREATE (specification)", "start")

    # Build bash script arguments
    bash_args = [args.description]
    if args.short_name:
        bash_args.extend(["--short-name", args.short_name])
    if args.number:
        bash_args.extend(["--number", str(args.number)])

    # Execute bash script
    exit_code, output = run_bash_script(
        "create-new-feature.sh",
        args=bash_args,
        json_mode=True
    )

    if exit_code != 0:
        error_msg = output.get("stderr", output.get("error", "Unknown error"))
        log_phase(1, "CREATE (specification)", "error")
        return {
            "status": "error",
            "phase": 1,
            "error": error_msg
        }

    # Extract outputs from JSON response
    branch_name = output.get("BRANCH_NAME", "")
    spec_file = output.get("SPEC_FILE", "")
    feature_num = output.get("FEATURE_NUM", "")

    if not branch_name or not spec_file:
        log_phase(1, "CREATE (specification)", "error")
        return {
            "status": "error",
            "phase": 1,
            "error": "Failed to parse output from create-new-feature.sh",
            "raw_output": output
        }

    # Derive feature directory from spec file path
    feature_dir = str(Path(spec_file).parent)

    log_phase(1, "CREATE (specification)", "complete")

    return {
        "status": "complete",
        "phase": 1,
        "branch_name": branch_name,
        "spec_file": spec_file,
        "feature_dir": feature_dir,
        "feature_num": feature_num
    }


def main():
    args = parse_args()

    print(f"{Status.RUNNING} Creating specification for: {args.description[:50]}...")

    result = execute_phase(args)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "complete":
            print(f"\n{Status.SUCCESS} Phase 1 complete: CREATE (specification)")
            print(f"  Branch: {result['branch_name']}")
            print(f"  Spec:   {result['spec_file']}")
            print(f"\n{Status.INFO} Next: Edit spec.md, then run speckit_plan.py")
        else:
            print(f"\n{Status.ERROR} Phase 1 failed: {result.get('error', 'Unknown error')}")

    sys.exit(EXIT_SUCCESS if result["status"] == "complete" else EXIT_BASH_ERROR)


if __name__ == "__main__":
    main()
