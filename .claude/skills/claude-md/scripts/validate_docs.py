#!/usr/bin/env python3
"""
Validate CLAUDE.md and AGENTS.md for structure and codebase consistency.

Usage:
    validate_docs.py [--path <project>] [--fix]

Examples:
    validate_docs.py
    validate_docs.py --path /path/to/project
    validate_docs.py --fix  # Auto-fix issues
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

TREE_IGNORE = "node_modules|.git|__pycache__|.venv|venv|dist|build|.next|.cache|coverage|.pytest_cache|.mypy_cache|.DS_Store|.idea|.vscode"

REQUIRED_SECTIONS = [
    "Repository Overview",
    "Repository Structure",
    "Development Guidelines",
    "Git Workflow",
]


class ValidationResult:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.fixes_applied = []

    def add_error(self, msg: str):
        self.errors.append(msg)

    def add_warning(self, msg: str):
        self.warnings.append(msg)

    def add_fix(self, msg: str):
        self.fixes_applied.append(msg)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0


def parse_frontmatter(content: str) -> Tuple[Optional[dict], str]:
    """Parse YAML frontmatter from markdown content."""
    if not content.startswith("---"):
        return None, content

    match = re.match(r"^---\n(.*?)\n---\n?", content, re.DOTALL)
    if not match:
        return None, content

    frontmatter_text = match.group(1)
    body = content[match.end() :]

    # Simple YAML parsing
    frontmatter = {}
    for line in frontmatter_text.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            frontmatter[key.strip()] = value.strip()

    return frontmatter, body


def check_structure(content: str, result: ValidationResult):
    """Check for required sections."""
    for section in REQUIRED_SECTIONS:
        pattern = rf"^##\s+{re.escape(section)}"
        if not re.search(pattern, content, re.MULTILINE):
            result.add_error(f"Missing required section: ## {section}")


def check_content_quality(content: str, result: ValidationResult):
    """Check for content quality issues."""
    # Check for TODO/FIXME placeholders
    if re.search(r"\[TODO\]|\[FIXME\]|TODO:|FIXME:", content, re.IGNORECASE):
        result.add_warning("Contains TODO/FIXME placeholders")

    # Check for empty sections (## Header followed by ## or end)
    if re.search(r"^##[^\n]+\n+(?=##|\Z)", content, re.MULTILINE):
        result.add_warning("Contains empty sections")


def check_paths_exist(content: str, project_path: Path, result: ValidationResult):
    """Check that referenced paths exist."""
    # Find paths in code blocks that look like file paths
    code_block_pattern = r"```[^\n]*\n(.*?)```"
    for match in re.finditer(code_block_pattern, content, re.DOTALL):
        block = match.group(1)
        # Look for file-like patterns
        for line in block.split("\n"):
            # Match patterns like src/, ./file.py, path/to/file
            path_matches = re.findall(r"(?:^|\s)([.a-zA-Z0-9_/-]+(?:\.[a-z]+)?/?)", line)
            for path_str in path_matches:
                if "/" in path_str and not path_str.startswith("#"):
                    check_path = project_path / path_str.lstrip("./")
                    # Only warn for specific file references, not directory patterns
                    if "." in path_str.split("/")[-1] and not check_path.exists():
                        if not any(c in path_str for c in ["*", "{", "}", "$"]):
                            result.add_warning(f"Referenced path may not exist: {path_str}")


def check_commands_exist(content: str, project_path: Path, result: ValidationResult):
    """Check that npm commands exist in package.json."""
    package_json = project_path / "package.json"
    if not package_json.exists():
        return

    try:
        data = json.loads(package_json.read_text())
        scripts = set(data.get("scripts", {}).keys())
    except (json.JSONDecodeError, OSError):
        return

    # Find npm run commands in content
    for match in re.finditer(r"npm run (\w+)", content):
        cmd = match.group(1)
        if cmd not in scripts:
            result.add_error(f"Command 'npm run {cmd}' not found in package.json scripts")


def check_tree_freshness(
    content: str, project_path: Path, frontmatter: dict, result: ValidationResult
) -> Optional[str]:
    """Check if directory tree is outdated, return updated tree if needed."""
    if not frontmatter or "last_validated" not in frontmatter:
        result.add_warning("No last_validated timestamp in frontmatter")
        return None

    try:
        last_validated = datetime.fromisoformat(frontmatter["last_validated"].replace("Z", "+00:00"))
    except (ValueError, TypeError):
        result.add_warning("Invalid last_validated timestamp format")
        return None

    # Check for files modified since last validation
    modified_count = 0
    for root, dirs, files in os.walk(project_path):
        # Skip ignored directories
        dirs[:] = [
            d
            for d in dirs
            if d not in {".git", "node_modules", "__pycache__", ".venv", "dist", "build"}
        ]
        for f in files:
            filepath = Path(root) / f
            try:
                mtime = datetime.fromtimestamp(filepath.stat().st_mtime, tz=timezone.utc)
                if mtime > last_validated:
                    modified_count += 1
            except OSError:
                pass

    if modified_count > 0:
        result.add_warning(f"Structure may be outdated - {modified_count} files modified since last validation")

        # Generate fresh tree
        try:
            proc = subprocess.run(
                ["tree", str(project_path), "-L", "3", "-I", TREE_IGNORE, "--noreport"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode == 0:
                return proc.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    return None


def update_tree_in_content(content: str, new_tree: str) -> str:
    """Replace the directory tree in content with new tree."""
    # Find the Repository Structure section and its code block
    pattern = r"(## Repository Structure\s*\n+```[^\n]*\n)(.*?)(```)"

    def replacer(match):
        return match.group(1) + new_tree + "\n" + match.group(3)

    return re.sub(pattern, replacer, content, flags=re.DOTALL)


def update_timestamp(content: str) -> str:
    """Update the last_validated timestamp in frontmatter."""
    new_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return re.sub(
        r"(last_validated:\s*)[\d\-T:Z]+",
        rf"\g<1>{new_timestamp}",
        content,
    )


def validate_agents_md(project_path: Path, fix: bool = False) -> ValidationResult:
    """Validate AGENTS.md file."""
    result = ValidationResult()
    agents_md = project_path / "AGENTS.md"

    if not agents_md.exists():
        result.add_error("AGENTS.md not found")
        return result

    content = agents_md.read_text()
    frontmatter, body = parse_frontmatter(content)

    # Check frontmatter
    if not frontmatter:
        result.add_error("AGENTS.md missing frontmatter")
    elif "last_validated" not in frontmatter:
        result.add_error("Frontmatter missing last_validated timestamp")

    # Check structure
    check_structure(body, result)

    # Check content quality
    check_content_quality(body, result)

    # Check paths exist
    check_paths_exist(body, project_path, result)

    # Check commands exist
    check_commands_exist(body, project_path, result)

    # Check tree freshness
    new_tree = check_tree_freshness(content, project_path, frontmatter, result)

    # Apply fixes if requested
    if fix:
        updated_content = content

        if new_tree:
            updated_content = update_tree_in_content(updated_content, new_tree)
            result.add_fix("Updated directory tree")

        # Update timestamp if any fixes applied or validation passed
        if result.fixes_applied or result.is_valid:
            updated_content = update_timestamp(updated_content)
            result.add_fix("Updated last_validated timestamp")

        if updated_content != content:
            agents_md.write_text(updated_content)

    return result


def validate_claude_md(project_path: Path) -> ValidationResult:
    """Validate CLAUDE.md file."""
    result = ValidationResult()
    claude_md = project_path / "CLAUDE.md"

    if not claude_md.exists():
        result.add_error("CLAUDE.md not found")
        return result

    content = claude_md.read_text()

    # Check it references AGENTS.md
    if "AGENTS.md" not in content:
        result.add_warning("CLAUDE.md doesn't reference AGENTS.md")

    return result


def main():
    parser = argparse.ArgumentParser(description="Validate CLAUDE.md and AGENTS.md")
    parser.add_argument("--path", default=".", help="Project path")
    parser.add_argument("--fix", action="store_true", help="Auto-fix issues")

    args = parser.parse_args()
    project_path = Path(args.path).resolve()

    if not project_path.is_dir():
        print(f"Error: Not a directory: {project_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Validating docs in: {project_path}")
    print()

    # Validate CLAUDE.md
    print("Checking CLAUDE.md...")
    claude_result = validate_claude_md(project_path)

    # Validate AGENTS.md
    print("Checking AGENTS.md...")
    agents_result = validate_agents_md(project_path, fix=args.fix)

    # Report results
    print()
    all_errors = claude_result.errors + agents_result.errors
    all_warnings = claude_result.warnings + agents_result.warnings
    all_fixes = claude_result.fixes_applied + agents_result.fixes_applied

    if all_errors:
        print("ERRORS:")
        for err in all_errors:
            print(f"  - {err}")
        print()

    if all_warnings:
        print("WARNINGS:")
        for warn in all_warnings:
            print(f"  - {warn}")
        print()

    if all_fixes:
        print("FIXES APPLIED:")
        for fix in all_fixes:
            print(f"  - {fix}")
        print()

    if not all_errors and not all_warnings:
        print("All checks passed!")

    sys.exit(0 if not all_errors else 1)


if __name__ == "__main__":
    main()
