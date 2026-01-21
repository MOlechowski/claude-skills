---
name: readme
description: "Create and update README.md files. Use when: (1) generating README for a new project, (2) updating stale README content, (3) validating README matches codebase."
---

# README

Create, update, and validate README.md files with auto-detection of project type and install commands.

## Workflow

### Creating New README

For projects without README.md:

```bash
scripts/init_readme.py [--path <project>] [--force]
```

This will:
1. Detect project type from package files
2. Extract metadata (name, description, license)
3. Extract install/test commands from package manager
4. Generate structured README from template

### Updating Existing README

For projects with README.md:

```bash
scripts/update_readme.py [--path <project>]
```

This will:
1. Parse existing README sections
2. Refresh content within `<auto>` tags
3. Preserve all user-written content outside tags

### Validating README

Check README for staleness:

```bash
scripts/validate_readme.py [--path <project>] [--fix]
```

This will:
1. Check required sections are present
2. Verify install commands are current
3. Check referenced files exist
4. Apply fixes if `--fix` provided

## Project Type Detection

| Files Present | Type | Install Command |
|---------------|------|-----------------|
| `package.json` + pnpm-lock.yaml | nodejs | `pnpm install` |
| `package.json` + yarn.lock | nodejs | `yarn` |
| `package.json` + bun.lockb | nodejs | `bun install` |
| `package.json` | nodejs | `npm install` |
| `pyproject.toml` (poetry) | python | `poetry install` |
| `pyproject.toml` (uv) | python | `uv sync` |
| `pyproject.toml` | python | `pip install -e .` |
| `Cargo.toml` | rust | `cargo build` |
| `go.mod` | go | `go build ./...` |

## Auto-Generated Sections

Content within `<auto>` tags is refreshed on update:

```markdown
## Installation

<auto>
npm install my-package
</auto>

Your custom notes here are preserved.
```

Auto-updatable content:
- Installation commands
- Test commands
- Prerequisites/versions

## Template

See `references/template.md` for the full README template structure.
