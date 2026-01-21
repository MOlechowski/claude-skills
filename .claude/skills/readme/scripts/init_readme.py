#!/usr/bin/env python3
"""
Initialize README.md for a project.

Usage:
    init_readme.py [--path <project>] [--force]

Examples:
    init_readme.py
    init_readme.py --path /path/to/project
    init_readme.py --force  # Overwrite existing file
"""

import argparse
import json
import sys
from pathlib import Path

from common import detect_package_manager


def detect_project_type(project_path: Path) -> tuple[str, dict]:
    """Detect project type and extract metadata."""
    info = {
        "name": project_path.name,
        "description": "",
        "version": "",
        "license": "",
        "commands": {},
    }

    # Check for package.json (Node.js)
    package_json = project_path / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text())
            info["name"] = data.get("name", info["name"])
            info["description"] = data.get("description", "")
            info["version"] = data.get("version", "")
            info["license"] = data.get("license", "")
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
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("name = "):
                    info["name"] = line.split("=", 1)[1].strip().strip('"\'')
                if line.startswith("description = "):
                    info["description"] = line.split("=", 1)[1].strip().strip('"\'')
                if line.startswith("version = "):
                    info["version"] = line.split("=", 1)[1].strip().strip('"\'')
            return "python", info
        except OSError:
            pass

    if (project_path / "setup.py").exists():
        return "python", info

    # Check for Cargo.toml (Rust)
    cargo = project_path / "Cargo.toml"
    if cargo.exists():
        try:
            content = cargo.read_text()
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("name = "):
                    info["name"] = line.split("=", 1)[1].strip().strip('"\'')
                if line.startswith("description = "):
                    info["description"] = line.split("=", 1)[1].strip().strip('"\'')
                if line.startswith("version = "):
                    info["version"] = line.split("=", 1)[1].strip().strip('"\'')
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

    # Check for Gemfile (Ruby)
    if (project_path / "Gemfile").exists():
        return "ruby", info

    # Check for composer.json (PHP)
    composer = project_path / "composer.json"
    if composer.exists():
        try:
            data = json.loads(composer.read_text())
            info["name"] = data.get("name", info["name"]).split("/")[-1]
            info["description"] = data.get("description", "")
            info["license"] = data.get("license", "")
            return "php", info
        except (json.JSONDecodeError, OSError):
            pass

    return "unknown", info


def detect_license(project_path: Path, info: dict) -> str:
    """Detect license from LICENSE file or package metadata."""
    # Check package metadata first
    if info.get("license"):
        return info["license"]

    # Check for LICENSE file
    for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"]:
        license_file = project_path / name
        if license_file.exists():
            try:
                content = license_file.read_text()[:500].lower()
                if "mit license" in content or "permission is hereby granted" in content:
                    return "MIT"
                if "apache license" in content:
                    return "Apache-2.0"
                if "gnu general public license" in content:
                    if "version 3" in content:
                        return "GPL-3.0"
                    return "GPL-2.0"
                if "bsd" in content:
                    return "BSD"
                return "See LICENSE file"
            except OSError:
                pass

    return ""


def generate_readme(project_path: Path, project_type: str, info: dict) -> str:
    """Generate README.md content."""
    install_cmd, dev_install_cmd, test_cmd = detect_package_manager(project_path)
    license_type = detect_license(project_path, info)

    name = info["name"]
    description = info.get("description", "")

    lines = [
        f"# {name}",
        "",
    ]

    if description:
        lines.append(description)
        lines.append("")

    # What is section
    lines.extend([
        f"## What is {name}?",
        "",
        f"<!-- Describe what {name} does and its primary use case -->",
        "",
    ])

    # Features section
    lines.extend([
        "## Features",
        "",
        "- **Feature 1**: Description",
        "- **Feature 2**: Description",
        "- **Feature 3**: Description",
        "",
    ])

    # Installation section
    lines.append("## Installation")
    lines.append("")
    if install_cmd:
        lines.extend([
            "<auto>",
            "",
            "```bash",
            install_cmd,
            "```",
            "",
            "</auto>",
        ])
    else:
        lines.append("<!-- Add installation instructions -->")
    lines.append("")

    # Quick Start section
    lines.extend([
        "## Quick Start",
        "",
        "```bash",
        f"# Example usage of {name}",
        "```",
        "",
    ])

    # Usage section
    lines.extend([
        "## Usage",
        "",
        "<!-- Add detailed usage examples -->",
        "",
    ])

    # Development section
    lines.extend([
        "## Development",
        "",
        "### Prerequisites",
        "",
    ])

    # Prerequisites based on project type
    if project_type.startswith("nodejs"):
        lines.append("- Node.js 18+")
    elif project_type == "python":
        lines.append("- Python 3.10+")
    elif project_type == "rust":
        lines.append("- Rust 1.70+")
    elif project_type == "go":
        lines.append("- Go 1.21+")
    elif project_type == "ruby":
        lines.append("- Ruby 3.0+")
    elif project_type == "php":
        lines.append("- PHP 8.1+")
    else:
        lines.append("<!-- List prerequisites -->")
    lines.append("")

    # Setup
    lines.extend([
        "### Setup",
        "",
    ])
    if dev_install_cmd:
        lines.extend([
            "```bash",
            f"git clone <repository-url>",
            f"cd {name}",
            dev_install_cmd,
            "```",
        ])
    else:
        lines.append("<!-- Add setup instructions -->")
    lines.append("")

    # Testing
    lines.extend([
        "### Testing",
        "",
    ])
    if test_cmd:
        lines.extend([
            "<auto>",
            "",
            "```bash",
            test_cmd,
            "```",
            "",
            "</auto>",
        ])
    else:
        lines.append("<!-- Add test instructions -->")
    lines.append("")

    # Contributing
    if (project_path / "CONTRIBUTING.md").exists():
        lines.extend([
            "## Contributing",
            "",
            "See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.",
            "",
        ])
    else:
        lines.extend([
            "## Contributing",
            "",
            "Contributions are welcome! Please open an issue or submit a pull request.",
            "",
        ])

    # License
    if license_type:
        lines.extend([
            "## License",
            "",
            f"{license_type}",
            "",
        ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Initialize README.md")
    parser.add_argument("--path", default=".", help="Project path")
    parser.add_argument("--force", action="store_true", help="Overwrite existing file")

    args = parser.parse_args()
    project_path = Path(args.path).resolve()

    if not project_path.is_dir():
        print(f"Error: Not a directory: {project_path}", file=sys.stderr)
        sys.exit(1)

    readme_path = project_path / "README.md"

    # Check for existing file
    if readme_path.exists() and not args.force:
        print(f"README.md already exists. Use --force to overwrite.")
        sys.exit(1)

    print(f"Analyzing project: {project_path}")

    # Detect project type
    project_type, info = detect_project_type(project_path)
    print(f"Detected project type: {project_type}")
    print(f"Project name: {info['name']}")

    # Generate README
    print("\nGenerating README.md...")
    content = generate_readme(project_path, project_type, info)
    readme_path.write_text(content)
    print(f"Created: {readme_path}")

    print("\nDone! Review the generated file and customize as needed.")


if __name__ == "__main__":
    main()
