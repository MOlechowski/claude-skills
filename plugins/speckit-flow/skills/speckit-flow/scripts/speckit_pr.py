#!/usr/bin/env python3
"""
speckit_pr.py - Phase 7: PR

Creates pull request for spec artifacts.

Usage:
    speckit_pr.py [OPTIONS]

Options:
    --draft          Create as draft PR
    --no-push        Skip pushing to remote
    --json           Output in JSON format
    --help, -h       Show this help message

Examples:
    speckit_pr.py
    speckit_pr.py --draft
    speckit_pr.py --no-push --json
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
    validate_prerequisites,
    run_git_command,
    run_gh_command,
    get_current_branch,
    get_repo_root
)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Phase 7: PR - Create pull request for spec artifacts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s
    %(prog)s --draft
    %(prog)s --no-push --json
"""
    )
    parser.add_argument(
        "--draft",
        action="store_true",
        help="Create as draft PR"
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="Skip pushing to remote"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    return parser.parse_args()


def extract_spec_summary(spec_file: Path) -> str:
    """Extract summary from spec.md for PR description."""
    if not spec_file.exists():
        return "Specification artifacts for new feature"

    content = spec_file.read_text()
    lines = content.split("\n")

    # Look for summary or description section
    summary_lines = []
    in_summary = False

    for line in lines:
        if line.lower().startswith("## summary") or line.lower().startswith("## overview"):
            in_summary = True
            continue
        elif line.startswith("## ") and in_summary:
            break
        elif in_summary and line.strip():
            summary_lines.append(line.strip())
            if len(summary_lines) >= 3:
                break

    if summary_lines:
        return "\n".join(f"- {line}" for line in summary_lines)

    # Fallback: use first non-heading paragraph
    for line in lines:
        if line.strip() and not line.startswith("#"):
            return f"- {line.strip()[:200]}"

    return "- Specification artifacts for new feature"


def execute_phase(args, paths: dict) -> dict:
    """
    Execute Phase 7: PR.

    Steps:
    1. Stage changes
    2. Create commit
    3. Push branch
    4. Create PR
    """
    log_phase(7, "PR", "start")

    feature_dir = Path(paths.get("FEATURE_DIR", ""))
    branch_name = get_current_branch()
    spec_file = feature_dir / "spec.md"

    # Step 1: Stage changes
    print(f"  {Status.RUNNING} Staging changes...")
    exit_code, stdout, stderr = run_git_command(["add", "-A"])

    if exit_code != 0:
        log_phase(7, "PR", "error")
        return {
            "status": "error",
            "phase": 7,
            "step": "git-add",
            "error": stderr or "Failed to stage changes"
        }
    print(f"  {Status.SUCCESS} Changes staged")

    # Check if there are changes to commit
    exit_code, stdout, stderr = run_git_command(["diff", "--cached", "--quiet"])
    if exit_code == 0:
        print(f"  {Status.INFO} No changes to commit")
        return {
            "status": "complete",
            "phase": 7,
            "message": "No changes to commit",
            "branch_name": branch_name
        }

    # Step 2: Create commit
    print(f"  {Status.RUNNING} Creating commit...")

    # Extract feature name from branch (e.g., "001-user-auth" -> "user-auth")
    feature_name = "-".join(branch_name.split("-")[1:]) if "-" in branch_name else branch_name

    commit_msg = f"""feat({branch_name}): add specification

Adds specification artifacts for {feature_name}

- spec.md: Feature specification
- plan.md: Technical design
- tasks.md: Implementation tasks"""

    exit_code, stdout, stderr = run_git_command(["commit", "-m", commit_msg])

    if exit_code != 0:
        log_phase(7, "PR", "error")
        return {
            "status": "error",
            "phase": 7,
            "step": "git-commit",
            "error": stderr or "Failed to create commit"
        }
    print(f"  {Status.SUCCESS} Commit created")

    # Step 3: Push branch (unless --no-push)
    pr_url = None

    if not args.no_push:
        print(f"  {Status.RUNNING} Pushing branch...")
        exit_code, stdout, stderr = run_git_command(["push", "-u", "origin", branch_name])

        if exit_code != 0:
            log_phase(7, "PR", "error")
            return {
                "status": "error",
                "phase": 7,
                "step": "git-push",
                "error": stderr or "Failed to push branch"
            }
        print(f"  {Status.SUCCESS} Branch pushed")

        # Step 4: Create PR
        print(f"  {Status.RUNNING} Creating pull request...")

        summary = extract_spec_summary(spec_file)

        pr_body = f"""## Summary
{summary}

## Spec Artifacts
- [spec.md](specs/{branch_name}/spec.md) - Feature specification
- [plan.md](specs/{branch_name}/plan.md) - Technical design
- [tasks.md](specs/{branch_name}/tasks.md) - Implementation tasks

## Next Steps
- [ ] Review spec artifacts
- [ ] Approve for implementation"""

        gh_args = [
            "pr", "create",
            "--title", f"spec: {feature_name}",
            "--body", pr_body
        ]

        if args.draft:
            gh_args.append("--draft")

        exit_code, stdout, stderr = run_gh_command(gh_args)

        if exit_code != 0:
            # PR creation failed, but commit and push succeeded
            print(f"  {Status.WARNING} PR creation failed: {stderr}")
            log_phase(7, "PR", "complete")
            return {
                "status": "complete",
                "phase": 7,
                "branch_name": branch_name,
                "pr_created": False,
                "pr_error": stderr
            }

        pr_url = stdout.strip()
        print(f"  {Status.SUCCESS} PR created: {pr_url}")
    else:
        print(f"  {Status.SKIP} Push and PR skipped (--no-push)")

    log_phase(7, "PR", "complete")

    result = {
        "status": "complete",
        "phase": 7,
        "branch_name": branch_name,
        "pr_created": pr_url is not None
    }

    if pr_url:
        result["pr_url"] = pr_url

    return result


def main():
    args = parse_args()

    # Validate prerequisites
    validation = validate_prerequisites(require_tasks=False)
    if not validation["valid"]:
        print(f"{Status.ERROR} {validation['error']}")
        sys.exit(EXIT_MISSING_PREREQ)

    paths = validation["paths"]
    print(f"{Status.RUNNING} Creating pull request for spec artifacts...")

    result = execute_phase(args, paths)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "complete":
            print(f"\n{Status.SUCCESS} Phase 7 complete: PR")
            print(f"  Branch: {result['branch_name']}")
            if result.get("pr_url"):
                print(f"  PR: {result['pr_url']}")
            if result.get("pr_error"):
                print(f"  {Status.WARNING} PR creation issue: {result['pr_error']}")
        else:
            print(f"\n{Status.ERROR} Phase 7 failed: {result.get('error', 'Unknown error')}")

    sys.exit(EXIT_SUCCESS if result["status"] == "complete" else EXIT_BASH_ERROR)


if __name__ == "__main__":
    main()
