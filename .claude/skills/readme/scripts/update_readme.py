#!/usr/bin/env python3
"""
Update README.md by refreshing auto-generated sections.

Usage:
    update_readme.py [--path <project>]

Examples:
    update_readme.py
    update_readme.py --path /path/to/project
"""

import argparse
import re
import sys
from pathlib import Path

from common import detect_package_manager


def find_section_context(content: str, auto_start: int) -> str:
    """Find which section an <auto> tag is in by looking at preceding headers."""
    preceding = content[:auto_start]
    headers = re.findall(r'^##+ (.+)$', preceding, re.MULTILINE)
    if headers:
        return headers[-1].lower().strip()
    return ""


def generate_auto_content(section: str, project_path: Path) -> str:
    """Generate new content for an auto section based on context."""
    install_cmd, _, test_cmd = detect_package_manager(project_path)

    if "install" in section:
        if install_cmd:
            return f"\n```bash\n{install_cmd}\n```\n"
        return "\n<!-- Add installation instructions -->\n"

    if "test" in section:
        if test_cmd:
            return f"\n```bash\n{test_cmd}\n```\n"
        return "\n<!-- Add test instructions -->\n"

    # Default: keep existing or return placeholder
    return "\n<!-- Auto-generated content -->\n"


def update_auto_sections(content: str, project_path: Path) -> tuple[str, int]:
    """Update all <auto> sections in content. Returns (updated_content, update_count)."""
    pattern = r'<auto>(.*?)</auto>'
    updates = 0

    def replace_auto(match):
        nonlocal updates
        start = match.start()

        # Find which section this auto tag is in
        section = find_section_context(content, start)

        # Generate new content
        new_content = generate_auto_content(section, project_path)
        updates += 1

        return f"<auto>{new_content}</auto>"

    updated = re.sub(pattern, replace_auto, content, flags=re.DOTALL)
    return updated, updates


def main():
    parser = argparse.ArgumentParser(description="Update README.md auto sections")
    parser.add_argument("--path", default=".", help="Project path")

    args = parser.parse_args()
    project_path = Path(args.path).resolve()

    if not project_path.is_dir():
        print(f"Error: Not a directory: {project_path}", file=sys.stderr)
        sys.exit(1)

    readme_path = project_path / "README.md"

    if not readme_path.exists():
        print(f"Error: README.md not found at {readme_path}", file=sys.stderr)
        print("Run init_readme.py first to create one.")
        sys.exit(1)

    print(f"Updating: {readme_path}")

    # Read current content
    content = readme_path.read_text()

    # Check for auto sections
    auto_count = len(re.findall(r'<auto>', content))
    if auto_count == 0:
        print("No <auto> sections found in README.md")
        print("Add <auto>...</auto> tags around sections you want auto-updated.")
        sys.exit(0)

    print(f"Found {auto_count} auto section(s)")

    # Update auto sections
    updated_content, updates = update_auto_sections(content, project_path)

    if updated_content == content:
        print("No changes needed.")
        sys.exit(0)

    # Write updated content
    readme_path.write_text(updated_content)
    print(f"Updated {updates} section(s)")
    print("Done!")


if __name__ == "__main__":
    main()
