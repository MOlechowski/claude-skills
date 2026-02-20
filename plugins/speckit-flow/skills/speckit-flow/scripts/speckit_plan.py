#!/usr/bin/env python3
"""
speckit_plan.py - Phase 2: CREATE (Planning)

Creates implementation plan and artifacts for a feature.

Usage:
    speckit_plan.py [OPTIONS]

Options:
    --agent <type>   Specific agent to update (claude, gemini, copilot, etc.)
    --skip-agent     Skip agent context update
    --json           Output in JSON format
    --help, -h       Show this help message

Examples:
    speckit_plan.py
    speckit_plan.py --agent claude
    speckit_plan.py --skip-agent --json
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
    EXIT_MISSING_PREREQ,
    log_phase,
    run_bash_script,
    get_feature_paths,
    get_repo_root
)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 2: CREATE (Planning) - Create implementation plan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Agent types:
    claude, gemini, copilot, cursor-agent, qwen, opencode,
    codex, windsurf, kilocode, auggie, roo, codebuddy,
    qoder, amp, shai, q, bob

Examples:
    %(prog)s
    %(prog)s --agent claude
    %(prog)s --skip-agent --json
"""
    )
    parser.add_argument(
        "--agent",
        help="Specific agent type to update context for"
    )
    parser.add_argument(
        "--skip-agent",
        action="store_true",
        help="Skip agent context update"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    return parser.parse_args()


def validate_feature_branch() -> dict:
    """Validate we're on a feature branch with spec.md."""
    paths = get_feature_paths()

    if "error" in paths:
        return {"valid": False, "error": paths["error"]}

    feature_dir = Path(paths.get("FEATURE_DIR", ""))
    spec_file = Path(paths.get("FEATURE_SPEC", ""))

    if not feature_dir.exists():
        return {
            "valid": False,
            "error": f"Feature directory not found: {feature_dir}\nRun speckit_specify.py first."
        }

    if not spec_file.exists():
        return {
            "valid": False,
            "error": f"spec.md not found: {spec_file}\nRun speckit_specify.py first."
        }

    return {"valid": True, "paths": paths}


def execute_phase(args) -> dict:
    """
    Execute Phase 2: CREATE (Planning).

    Steps:
    1. Run setup-plan.sh to create plan.md from template
    2. Run update-agent-context.sh to update agent files (optional)
    """
    log_phase(2, "CREATE (planning)", "start")

    # Step 1: Setup plan from template
    print(f"  {Status.RUNNING} Setting up plan template...")

    exit_code, output = run_bash_script(
        "setup-plan.sh",
        json_mode=True
    )

    if exit_code != 0:
        error_msg = output.get("stderr", output.get("error", "Unknown error"))
        log_phase(2, "CREATE (planning)", "error")
        return {
            "status": "error",
            "phase": 2,
            "step": "setup-plan",
            "error": error_msg
        }

    # Extract outputs
    plan_file = output.get("IMPL_PLAN", "")
    feature_spec = output.get("FEATURE_SPEC", "")
    feature_dir = output.get("SPECS_DIR", "")
    branch = output.get("BRANCH", "")

    print(f"  {Status.SUCCESS} Plan template created: {plan_file}")

    # Step 2: Update agent context (unless skipped)
    agent_update_status = "skipped"
    agent_update_error = None

    if not args.skip_agent:
        print(f"  {Status.RUNNING} Updating agent context...")

        agent_args = [args.agent] if args.agent else []

        exit_code, agent_output = run_bash_script(
            "update-agent-context.sh",
            args=agent_args,
            json_mode=False  # This script uses text output
        )

        if exit_code != 0:
            # Agent context update is non-blocking
            agent_update_status = "warning"
            agent_update_error = agent_output.get("stderr", "Agent context update had issues")
            print(f"  {Status.WARNING} Agent context update had issues (non-blocking)")
        else:
            agent_update_status = "complete"
            print(f"  {Status.SUCCESS} Agent context updated")
    else:
        print(f"  {Status.SKIP} Agent context update skipped")

    log_phase(2, "CREATE (planning)", "complete")

    result = {
        "status": "complete",
        "phase": 2,
        "plan_file": plan_file,
        "spec_file": feature_spec,
        "feature_dir": feature_dir,
        "branch": branch,
        "agent_update": agent_update_status,
        "artifacts": ["plan.md"]
    }

    if agent_update_error:
        result["agent_update_warning"] = agent_update_error

    return result


def main():
    args = parse_args()

    # Validate prerequisites
    validation = validate_feature_branch()
    if not validation["valid"]:
        print(f"{Status.ERROR} {validation['error']}")
        sys.exit(EXIT_MISSING_PREREQ)

    print(f"{Status.RUNNING} Creating implementation plan...")

    result = execute_phase(args)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "complete":
            print(f"\n{Status.SUCCESS} Phase 2 complete: CREATE (planning)")
            print(f"  Plan:   {result['plan_file']}")
            print(f"  Branch: {result['branch']}")
            print(f"\n{Status.INFO} Next steps:")
            print("  1. Edit plan.md to add technical details")
            print("  2. Run speckit_clarify.py to resolve ambiguities")
        else:
            print(f"\n{Status.ERROR} Phase 2 failed: {result.get('error', 'Unknown error')}")

    sys.exit(EXIT_SUCCESS if result["status"] == "complete" else EXIT_BASH_ERROR)


if __name__ == "__main__":
    main()
