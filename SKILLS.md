# Project Skills

Recommended marketplace plugins for working on this repository.

## Setup

```bash
# 1. Add the marketplace (one-time, requires trust approval)
/plugin marketplace add MOlechowski/claude-skills

# 2. Install required skills
claude plugin install dev-skill-create@claude-skills --scope project
```

## Required

Skills needed for contributing to this repository.

| Skill | Purpose | Install |
|-------|---------|---------|
| **dev-skill-create** | Create new skills following best practices | `claude plugin install dev-skill-create@claude-skills --scope project` |

## Recommended

Optional skills that improve the development workflow.

| Skill | Purpose | Install |
|-------|---------|---------|
| **git-commit** | Generate Conventional Commits messages | `claude plugin install git-commit@claude-skills` |
| **dev-review-pr** | Review PRs with structured analysis | `claude plugin install dev-review-pr@claude-skills` |
| **doc-readme** | Create and validate README.md files | `claude plugin install doc-readme@claude-skills` |

## Full Catalog

Browse all 94 available plugins: `/plugin` > Discover tab, or see the [README](README.md#available-skills-94-total).
