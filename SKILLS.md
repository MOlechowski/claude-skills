# Project Skills

Development skills for working on this repository, managed via `skills-lock.json`.

## Setup

```bash
# Install all project skills from the lock file (one command)
skills experimental_install
```

This reads `skills-lock.json` and installs all 9 skills to `.agents/skills/` (project-local).

## Included Skills

| Skill | Purpose |
|-------|---------|
| **dev-skill-create** | Create new skills following marketplace conventions |
| **dev-review-pr** | Review PRs with structured analysis |
| **doc-claude-md** | Create and validate CLAUDE.md/AGENTS.md files |
| **doc-changelog** | Generate CHANGELOG.md from git history |
| **doc-project** | Update all project docs in one pass |
| **doc-readme** | Create and validate README.md files |
| **doc-skills-md** | Generate SKILLS.md with plugin recommendations |
| **git-commit** | Generate Conventional Commits messages |
| **git-ship** | Commit, PR, and merge with CI skipped |

## Adding a Skill

```bash
# Add a skill from the marketplace (updates skills-lock.json)
skills add MOlechowski/claude-skills -s <skill-name> --yes

# Commit the updated lock file
git add skills-lock.json && git commit -m "chore: add <skill-name> to project skills"
```

## Full Catalog

Browse all available plugins in the [README](README.md#available-skills).
