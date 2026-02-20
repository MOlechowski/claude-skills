"""
Shared utilities for README skill scripts.
"""

from pathlib import Path


def detect_package_manager(project_path: Path) -> tuple[str, str, str]:
    """
    Detect package manager and return (install_cmd, dev_install_cmd, test_cmd).

    Returns empty strings if no package manager is detected.
    """
    # Check for Node.js lockfiles
    if (project_path / "pnpm-lock.yaml").exists():
        return "pnpm install", "pnpm install", "pnpm test"
    if (project_path / "yarn.lock").exists():
        return "yarn", "yarn", "yarn test"
    if (project_path / "bun.lockb").exists():
        return "bun install", "bun install", "bun test"
    if (project_path / "package-lock.json").exists() or (project_path / "package.json").exists():
        return "npm install", "npm install", "npm test"

    # Check for Python
    pyproject = project_path / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text()
        if "[tool.poetry]" in content:
            return "poetry install", "poetry install --with dev", "poetry run pytest"
        if (project_path / "uv.lock").exists():
            return "uv sync", "uv sync --all-extras", "uv run pytest"
        return "pip install -e .", "pip install -e '.[dev]'", "pytest"

    if (project_path / "setup.py").exists():
        return "pip install -e .", "pip install -e '.[dev]'", "pytest"

    # Rust
    if (project_path / "Cargo.toml").exists():
        return "cargo build --release", "cargo build", "cargo test"

    # Go
    if (project_path / "go.mod").exists():
        return "go build ./...", "go mod download", "go test ./..."

    # Ruby
    if (project_path / "Gemfile").exists():
        return "bundle install", "bundle install", "bundle exec rspec"

    # PHP
    if (project_path / "composer.json").exists():
        return "composer install", "composer install", "composer test"

    return "", "", ""
