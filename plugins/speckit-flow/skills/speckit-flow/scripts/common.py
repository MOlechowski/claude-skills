#!/usr/bin/env python3
"""
Common utilities for speckit-flow scripts.

Provides:
- Status emojis and formatted output
- Exit code constants
- Bash script wrapper utilities
- Path validation and feature detection
- Template loading
"""

import sys
import subprocess
import json
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# Exit codes following skill-creator patterns
EXIT_SUCCESS = 0
EXIT_VALIDATION_ERROR = 1
EXIT_BASH_ERROR = 2
EXIT_USER_ABORT = 3
EXIT_MISSING_PREREQ = 4


class Status:
    """Status emojis for consistent output."""
    SUCCESS = "✅"
    ERROR = "❌"
    WARNING = "⚠️"
    INFO = "ℹ️"
    RUNNING = "🔄"
    SKIP = "⏭️"
    COMPLETE = "✓"


def log_phase(phase_num: int, name: str, status: str = "start"):
    """Log phase transitions with consistent formatting."""
    if status == "start":
        print(f"{Status.RUNNING} Phase {phase_num}: {name}")
    elif status == "complete":
        print(f"{Status.SUCCESS} Phase {phase_num} complete: {name}")
    elif status == "skip":
        print(f"{Status.SKIP} Phase {phase_num} skipped: {name}")
    elif status == "error":
        print(f"{Status.ERROR} Phase {phase_num} failed: {name}")


def get_repo_root() -> Path:
    """Get repository root path."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except Exception:
        pass

    # Fallback: walk up from current directory looking for .git or .specify
    current = Path.cwd()
    while current != current.parent:
        if (current / ".git").exists() or (current / ".specify").exists():
            return current
        current = current.parent

    return Path.cwd()


def get_specify_scripts_path() -> Path:
    """Get path to .specify/scripts/bash directory."""
    return get_repo_root() / ".specify" / "scripts" / "bash"


def run_bash_script(
    script_name: str,
    args: list = None,
    json_mode: bool = False
) -> Tuple[int, Dict[str, Any]]:
    """
    Execute bash script and capture output.

    Args:
        script_name: Name of script in .specify/scripts/bash/
        args: Command line arguments to pass
        json_mode: If True, adds --json flag and parses JSON output

    Returns:
        Tuple of (exit_code, parsed_output_dict)
    """
    scripts_path = get_specify_scripts_path()
    script_path = scripts_path / script_name

    if not script_path.exists():
        return 1, {"error": f"Script not found: {script_path}"}

    cmd = [str(script_path)]
    if json_mode:
        cmd.append("--json")
    if args:
        cmd.extend(args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(get_repo_root())
        )

        output = {}
        if json_mode and result.returncode == 0 and result.stdout.strip():
            try:
                output = json.loads(result.stdout.strip())
            except json.JSONDecodeError:
                output = {"raw": result.stdout, "stderr": result.stderr}
        else:
            output = {"raw": result.stdout, "stderr": result.stderr}

        return result.returncode, output

    except Exception as e:
        return 1, {"error": str(e)}


def get_feature_paths() -> Dict[str, str]:
    """
    Call check-prerequisites.sh --paths-only --json and parse output.

    Returns dict with: REPO_ROOT, BRANCH, FEATURE_DIR, FEATURE_SPEC, IMPL_PLAN, TASKS
    """
    exit_code, output = run_bash_script(
        "check-prerequisites.sh",
        args=["--paths-only"],
        json_mode=True
    )

    if exit_code != 0:
        return {"error": output.get("stderr", output.get("error", "Unknown error"))}

    return output


def validate_prerequisites(require_tasks: bool = False) -> Dict[str, Any]:
    """
    Validate feature directory and required files exist.

    Args:
        require_tasks: If True, also require tasks.md to exist

    Returns:
        Dict with 'valid' bool and either 'paths' or 'error'
    """
    args = []
    if require_tasks:
        args.extend(["--require-tasks", "--include-tasks"])

    exit_code, output = run_bash_script(
        "check-prerequisites.sh",
        args=args,
        json_mode=True
    )

    if exit_code != 0:
        error_msg = output.get("stderr", output.get("error", "Prerequisite check failed"))
        return {"valid": False, "error": error_msg}

    return {"valid": True, "paths": output}


def load_template(template_name: str) -> Optional[str]:
    """
    Load template from .specify/templates/

    Args:
        template_name: Name of template file (e.g., 'spec-template.md')

    Returns:
        Template content as string, or None if not found
    """
    repo_root = get_repo_root()
    template_path = repo_root / ".specify" / "templates" / template_name

    if not template_path.exists():
        print(f"{Status.ERROR} Template not found: {template_path}")
        return None

    try:
        return template_path.read_text()
    except Exception as e:
        print(f"{Status.ERROR} Error reading template: {e}")
        return None


def is_impl_repo() -> bool:
    """
    Detect if current repo supports implementation.

    Checks for common source directories and project files.
    """
    repo_root = get_repo_root()

    # Check for source directories
    source_dirs = ["src", "lib", "app", "packages"]
    for dir_name in source_dirs:
        if (repo_root / dir_name).is_dir():
            return True

    # Check for project files
    project_files = [
        "package.json",
        "go.mod",
        "Cargo.toml",
        "pyproject.toml",
        "setup.py",
        "pom.xml",
        "build.gradle"
    ]
    for file_name in project_files:
        if (repo_root / file_name).exists():
            return True

    return False


def get_current_branch() -> str:
    """Get current git branch name."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass

    return "main"


def run_git_command(args: list, capture: bool = True) -> Tuple[int, str, str]:
    """
    Run a git command.

    Args:
        args: Git command arguments (without 'git')
        capture: If True, capture output; if False, inherit stdio

    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    cmd = ["git"] + args

    try:
        if capture:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(get_repo_root())
            )
            return result.returncode, result.stdout, result.stderr
        else:
            result = subprocess.run(cmd, cwd=str(get_repo_root()))
            return result.returncode, "", ""
    except Exception as e:
        return 1, "", str(e)


def run_gh_command(args: list) -> Tuple[int, str, str]:
    """
    Run a GitHub CLI (gh) command.

    Args:
        args: gh command arguments (without 'gh')

    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    cmd = ["gh"] + args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(get_repo_root())
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)


def main():
    """CLI for testing common utilities."""
    import argparse

    parser = argparse.ArgumentParser(description="Speckit common utilities")
    parser.add_argument("--check-paths", action="store_true", help="Get feature paths")
    parser.add_argument("--check-prereqs", action="store_true", help="Validate prerequisites")
    parser.add_argument("--require-tasks", action="store_true", help="Require tasks.md")
    parser.add_argument("--is-impl-repo", action="store_true", help="Check if implementation repo")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    if args.check_paths:
        paths = get_feature_paths()
        if args.json:
            print(json.dumps(paths))
        else:
            for key, value in paths.items():
                print(f"{key}: {value}")
        sys.exit(0 if "error" not in paths else 1)

    if args.check_prereqs:
        result = validate_prerequisites(require_tasks=args.require_tasks)
        if args.json:
            print(json.dumps(result))
        else:
            if result["valid"]:
                print(f"{Status.SUCCESS} Prerequisites validated")
                for key, value in result.get("paths", {}).items():
                    print(f"  {key}: {value}")
            else:
                print(f"{Status.ERROR} {result['error']}")
        sys.exit(0 if result["valid"] else 1)

    if args.is_impl_repo:
        is_impl = is_impl_repo()
        if args.json:
            print(json.dumps({"is_impl_repo": is_impl}))
        else:
            print(f"Implementation repo: {is_impl}")
        sys.exit(0)

    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
