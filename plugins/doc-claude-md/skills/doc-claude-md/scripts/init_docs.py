#!/usr/bin/env python3
"""
Initialize CLAUDE.md and AGENTS.md for a project.

Usage:
    init_docs.py [--path <project>] [--force]

Examples:
    init_docs.py
    init_docs.py --path /path/to/project
    init_docs.py --force  # Overwrite existing files
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TREE_IGNORE = "node_modules|.git|__pycache__|.venv|venv|dist|build|.next|.cache|coverage|.pytest_cache|.mypy_cache|.DS_Store|.idea|.vscode"


def detect_project_type(project_path: Path) -> tuple[str, dict]:
    """Detect project type and extract metadata."""
    info = {
        "name": project_path.name,
        "description": "",
        "commands": {},
        "has_skills": False,
    }

    # Check for skills framework
    if (project_path / ".claude" / "skills").is_dir():
        info["has_skills"] = True

    # Check for package.json (Node.js)
    package_json = project_path / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text())
            info["name"] = data.get("name", info["name"])
            info["description"] = data.get("description", "")
            info["commands"] = data.get("scripts", {})

            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

            if "next" in deps:
                return "nodejs-next", info
            if "react" in deps or "react-dom" in deps:
                return "nodejs-react", info
            if "express" in deps or "fastify" in deps or "koa" in deps:
                return "nodejs-api", info
            return "nodejs-library", info
        except (json.JSONDecodeError, OSError):
            pass

    # Check for pyproject.toml (Python)
    pyproject = project_path / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text()
            # Simple TOML parsing for name and description
            for line in content.split("\n"):
                if line.startswith("name = "):
                    info["name"] = line.split("=", 1)[1].strip().strip('"\'')
                if line.startswith("description = "):
                    info["description"] = line.split("=", 1)[1].strip().strip('"\'')
            return "python", info
        except OSError:
            pass

    # Check for setup.py (Python legacy)
    if (project_path / "setup.py").exists():
        return "python", info

    # Check for Cargo.toml (Rust)
    cargo = project_path / "Cargo.toml"
    if cargo.exists():
        try:
            content = cargo.read_text()
            for line in content.split("\n"):
                if line.startswith("name = "):
                    info["name"] = line.split("=", 1)[1].strip().strip('"\'')
                if line.startswith("description = "):
                    info["description"] = line.split("=", 1)[1].strip().strip('"\'')
            return "rust", info
        except OSError:
            pass

    # Check for go.mod (Go)
    gomod = project_path / "go.mod"
    if gomod.exists():
        try:
            content = gomod.read_text()
            first_line = content.split("\n")[0]
            if first_line.startswith("module "):
                info["name"] = first_line.split()[-1].split("/")[-1]
            return "go", info
        except OSError:
            pass

    # Check for monorepo patterns
    packages_dir = project_path / "packages"
    if packages_dir.is_dir():
        subpackages = [p for p in packages_dir.iterdir() if (p / "package.json").exists()]
        if len(subpackages) > 1:
            return "monorepo", info

    return "unknown", info


def extract_readme_summary(project_path: Path) -> str:
    """Extract first paragraph from README as summary."""
    for readme_name in ["README.md", "readme.md", "README", "README.rst"]:
        readme = project_path / readme_name
        if readme.exists():
            try:
                content = readme.read_text()
                lines = content.split("\n")
                # Skip title and empty lines, get first paragraph
                in_paragraph = False
                paragraph_lines = []
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if not stripped:
                        if in_paragraph:
                            break
                        continue
                    in_paragraph = True
                    paragraph_lines.append(stripped)
                if paragraph_lines:
                    return " ".join(paragraph_lines)[:500]
            except OSError:
                pass
    return ""


def generate_tree(project_path: Path) -> str:
    """Generate directory tree using system tree command."""
    try:
        result = subprocess.run(
            ["tree", str(project_path), "-L", "3", "-I", TREE_IGNORE, "--noreport"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        return f"{project_path.name}/\n├── [tree command not installed]\n└── Run: brew install tree (macOS) or apt install tree (Linux)"
    except (subprocess.TimeoutExpired, OSError):
        pass

    return f"{project_path.name}/\n├── [tree generation failed]\n└── ..."


def generate_claude_md() -> str:
    """Generate CLAUDE.md content."""
    return """# Claude Code Instructions

See @AGENTS.md for detailed instructions.
"""


def generate_agents_md(project_path: Path, project_type: str, info: dict) -> str:
    """Generate AGENTS.md content."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Get description
    description = info.get("description", "") or extract_readme_summary(project_path)

    # Generate tree
    tree = generate_tree(project_path)

    # Build content
    lines = [
        "---",
        f"last_validated: {timestamp}",
        f"project_type: {project_type}",
        "---",
        "",
        f"# Agent Instructions: {info['name']}",
        "",
        "This file provides guidance to Claude Code when working with code in this repository.",
        "",
        "## Repository Overview",
        "",
    ]

    if description:
        lines.append(description)
    else:
        lines.append(f"This is a {project_type.replace('-', ' ')} project.")
    lines.append("")

    # Repository Structure
    lines.extend([
        "## Repository Structure",
        "",
        "```",
        tree,
        "```",
        "",
    ])

    # Skills Framework section (if detected)
    if info.get("has_skills"):
        lines.extend([
            "## Skills Framework",
            "",
            "This project includes Claude Skills in `.claude/skills/`. Skills provide specialized capabilities through progressive disclosure:",
            "",
            "1. **Metadata** - Always loaded (name + description)",
            "2. **SKILL.md body** - Loaded when skill activates",
            "3. **Bundled resources** - Loaded as needed",
            "",
        ])

    # Development Guidelines
    lines.extend([
        "## Development Guidelines",
        "",
        "### Code Style",
        "",
        "- Follow existing code patterns and conventions",
        "- Keep changes focused and minimal",
        "- Write clear, self-documenting code",
        "",
    ])

    # Available Commands (if any)
    if info.get("commands"):
        lines.extend([
            "## Available Commands",
            "",
        ])
        for cmd, script in info["commands"].items():
            lines.append(f"- `npm run {cmd}` - {script[:50]}{'...' if len(script) > 50 else ''}")
        lines.append("")

    # Testing section
    lines.extend([
        "## Testing",
        "",
    ])
    if "test" in info.get("commands", {}):
        lines.append("Run tests with: `npm test`")
    elif project_type == "python":
        lines.append("Run tests with: `pytest`")
    elif project_type == "rust":
        lines.append("Run tests with: `cargo test`")
    elif project_type == "go":
        lines.append("Run tests with: `go test ./...`")
    else:
        lines.append("Configure testing for this project.")
    lines.append("")

    # Git Workflow
    lines.extend([
        "## Git Workflow",
        "",
        "```bash",
        "# Check status first",
        "git status",
        "",
        "# Create feature branch",
        "git checkout -b feat/description",
        "",
        "# Make changes, then commit",
        "git add .",
        "git commit -m \"type: description\"",
        "",
        "# Push and create PR",
        "git push -u origin HEAD",
        "```",
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Initialize CLAUDE.md and AGENTS.md")
    parser.add_argument("--path", default=".", help="Project path")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")

    args = parser.parse_args()
    project_path = Path(args.path).resolve()

    if not project_path.is_dir():
        print(f"Error: Not a directory: {project_path}", file=sys.stderr)
        sys.exit(1)

    claude_md = project_path / "CLAUDE.md"
    agents_md = project_path / "AGENTS.md"

    # Check for existing files
    if not args.force:
        if claude_md.exists():
            print(f"CLAUDE.md already exists. Use --force to overwrite.")
            sys.exit(1)
        if agents_md.exists():
            print(f"AGENTS.md already exists. Use --force to overwrite.")
            sys.exit(1)

    print(f"Analyzing project: {project_path}")

    # Detect project type
    project_type, info = detect_project_type(project_path)
    print(f"Detected project type: {project_type}")
    print(f"Project name: {info['name']}")
    if info.get("has_skills"):
        print("Skills framework detected")

    # Generate files
    print("\nGenerating CLAUDE.md...")
    claude_md.write_text(generate_claude_md())
    print(f"Created: {claude_md}")

    print("\nGenerating AGENTS.md...")
    agents_md.write_text(generate_agents_md(project_path, project_type, info))
    print(f"Created: {agents_md}")

    print("\nDone! Review the generated files and customize as needed.")


if __name__ == "__main__":
    main()
