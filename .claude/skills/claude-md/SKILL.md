---
name: claude-md
description: "Create and update CLAUDE.md and AGENTS.md files. Use when: (1) setting up Claude documentation for a project, (2) updating agent instructions after codebase changes, (3) validating docs match current structure."
---

# Claude MD

Create and maintain CLAUDE.md and AGENTS.md documentation files.

## Workflow

### Creating New Docs

For projects without CLAUDE.md/AGENTS.md:

```bash
scripts/init_docs.py [--path <project>]
```

This will:
1. Analyze codebase (detect project type, extract info)
2. Generate directory tree (using tree skill)
3. Create CLAUDE.md (pointer file)
4. Create AGENTS.md (full documentation with frontmatter)

### Validating/Updating Existing Docs

For projects with existing documentation:

```bash
scripts/validate_docs.py [--path <project>] [--fix]
```

This will:
1. Check structure (required sections present)
2. Verify codebase consistency (paths exist, commands valid)
3. Detect staleness (files changed since last validation)
4. Apply fixes if `--fix` flag provided
5. Update `last_validated` timestamp

## Project Type Detection

The init script auto-detects project type:

| Files Present | Detected Type |
|---------------|---------------|
| `package.json` with react/next | `nodejs-react` |
| `package.json` with express | `nodejs-api` |
| `package.json` (other) | `nodejs-library` |
| `pyproject.toml` / `setup.py` | `python` |
| `Cargo.toml` | `rust` |
| `go.mod` | `go` |
| Multiple `package.json` | `monorepo` |
| `.claude/skills/` present | Adds skills framework section |

## Generated Files

**CLAUDE.md:**
```markdown
# Claude Code Instructions

See @AGENTS.md for detailed instructions.
```

**AGENTS.md:**
```yaml
---
last_validated: 2026-01-21T12:00:00Z
project_type: nodejs-library
---

# Agent Instructions: project-name

[Content based on template and codebase analysis]
```

## Validation Checks

1. **Structure:** Required sections exist
2. **Content:** No TODO placeholders, valid links
3. **Consistency:** Paths in docs exist, commands in package.json/pyproject.toml
4. **Freshness:** Compares file modification dates vs last_validated

## Template

See `references/template.md` for the AGENTS.md template structure.
