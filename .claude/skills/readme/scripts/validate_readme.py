#!/usr/bin/env python3
"""
Validate README.md for completeness and accuracy.

Usage:
    validate_readme.py [--path <project>] [--fix]

Examples:
    validate_readme.py
    validate_readme.py --path /path/to/project
    validate_readme.py --fix  # Auto-fix issues where possible
"""

import argparse
import re
import sys
from pathlib import Path

from common import detect_package_manager


REQUIRED_SECTIONS = [
    "installation",
    "usage",
]

RECOMMENDED_SECTIONS = [
    "features",
    "contributing",
    "license",
]


def extract_sections(content: str) -> dict[str, str]:
    """Extract sections from README content."""
    sections = {}
    current_section = "intro"
    current_content = []

    for line in content.split("\n"):
        if line.startswith("## "):
            if current_content:
                sections[current_section] = "\n".join(current_content)
            current_section = line[3:].strip().lower()
            current_content = []
        else:
            current_content.append(line)

    if current_content:
        sections[current_section] = "\n".join(current_content)

    return sections


def check_file_references(content: str, project_path: Path) -> list[str]:
    """Check that referenced files exist."""
    warnings = []

    # Find markdown links to local files
    links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)
    for text, href in links:
        if href.startswith(('http://', 'https://', '#', 'mailto:')):
            continue
        file_path = project_path / href
        if not file_path.exists():
            warnings.append(f"Referenced file not found: {href}")

    return warnings


def check_install_command(content: str, project_path: Path) -> list[str]:
    """Check if install command matches current package manager."""
    warnings = []
    expected_install, _, _ = detect_package_manager(project_path)

    if not expected_install:
        return warnings

    # Check for common install commands in content
    install_patterns = [
        (r'npm install', 'npm'),
        (r'yarn\b(?! test)', 'yarn'),
        (r'pnpm install', 'pnpm'),
        (r'bun install', 'bun'),
        (r'pip install', 'pip'),
        (r'poetry install', 'poetry'),
        (r'uv sync', 'uv'),
        (r'cargo build', 'cargo'),
        (r'go build', 'go'),
        (r'bundle install', 'bundle'),
        (r'composer install', 'composer'),
    ]

    found_manager = None
    for pattern, manager in install_patterns:
        if re.search(pattern, content):
            found_manager = manager
            break

    if found_manager:
        expected_manager = expected_install.split()[0]
        if found_manager != expected_manager:
            warnings.append(
                f"Install command mismatch: README uses '{found_manager}' "
                f"but project uses '{expected_manager}'"
            )

    return warnings


def validate_readme(project_path: Path) -> tuple[list[str], list[str], list[str]]:
    """
    Validate README.md.

    Returns (errors, warnings, suggestions).
    """
    errors = []
    warnings = []
    suggestions = []

    readme_path = project_path / "README.md"
    if not readme_path.exists():
        errors.append("README.md not found")
        return errors, warnings, suggestions

    content = readme_path.read_text()

    # Check for empty README
    if len(content.strip()) < 50:
        errors.append("README.md is too short (less than 50 characters)")
        return errors, warnings, suggestions

    # Extract sections
    sections = extract_sections(content)

    # Check required sections
    for section in REQUIRED_SECTIONS:
        if section not in sections:
            errors.append(f"Missing required section: {section}")

    # Check recommended sections
    for section in RECOMMENDED_SECTIONS:
        if section not in sections:
            suggestions.append(f"Consider adding section: {section}")

    # Check for placeholder content
    if "<!-- " in content and "-->" in content:
        placeholder_count = content.count("<!--")
        if placeholder_count > 0:
            warnings.append(f"Found {placeholder_count} HTML comment(s) - may be unfilled placeholders")

    # Check file references
    file_warnings = check_file_references(content, project_path)
    warnings.extend(file_warnings)

    # Check install command
    install_warnings = check_install_command(content, project_path)
    warnings.extend(install_warnings)

    # Check for auto sections
    auto_count = len(re.findall(r'<auto>', content))
    if auto_count == 0:
        suggestions.append("No <auto> sections found - consider adding for easier updates")

    return errors, warnings, suggestions


def apply_fixes(project_path: Path, errors: list[str], warnings: list[str]) -> int:
    """Apply automatic fixes where possible. Returns number of fixes applied."""
    fixes = 0
    readme_path = project_path / "README.md"

    if not readme_path.exists():
        return fixes

    content = readme_path.read_text()
    original = content

    # Fix install command mismatch
    for warning in warnings:
        if "Install command mismatch" in warning:
            expected_install, _, _ = detect_package_manager(project_path)
            if expected_install:
                # Update auto sections
                pattern = r'(<auto>)(.*?)(</auto>)'

                def update_install(match):
                    nonlocal fixes
                    inner = match.group(2)
                    if any(cmd in inner for cmd in ['npm install', 'yarn', 'pnpm install', 'pip install', 'poetry install', 'uv sync']):
                        fixes += 1
                        return f"<auto>\n\n```bash\n{expected_install}\n```\n\n</auto>"
                    return match.group(0)

                content = re.sub(pattern, update_install, content, flags=re.DOTALL)

    if content != original:
        readme_path.write_text(content)

    return fixes


def main():
    parser = argparse.ArgumentParser(description="Validate README.md")
    parser.add_argument("--path", default=".", help="Project path")
    parser.add_argument("--fix", action="store_true", help="Auto-fix issues where possible")

    args = parser.parse_args()
    project_path = Path(args.path).resolve()

    if not project_path.is_dir():
        print(f"Error: Not a directory: {project_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Validating: {project_path / 'README.md'}")
    print()

    errors, warnings, suggestions = validate_readme(project_path)

    # Print results
    if errors:
        print("Errors:")
        for e in errors:
            print(f"  - {e}")
        print()

    if warnings:
        print("Warnings:")
        for w in warnings:
            print(f"  - {w}")
        print()

    if suggestions:
        print("Suggestions:")
        for s in suggestions:
            print(f"  - {s}")
        print()

    # Apply fixes if requested
    if args.fix and (errors or warnings):
        fixes = apply_fixes(project_path, errors, warnings)
        if fixes:
            print(f"Applied {fixes} fix(es)")
        else:
            print("No automatic fixes available")
        print()

    # Summary
    if not errors and not warnings:
        print("README.md looks good!")
        sys.exit(0)
    elif errors:
        print(f"Found {len(errors)} error(s), {len(warnings)} warning(s)")
        sys.exit(1)
    else:
        print(f"Found {len(warnings)} warning(s)")
        sys.exit(0)


if __name__ == "__main__":
    main()
