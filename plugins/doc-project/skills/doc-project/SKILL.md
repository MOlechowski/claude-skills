---
name: doc-project
description: "Update all project documentation in one pass: CLAUDE.md, AGENTS.md, README.md, SKILLS.md, CHANGELOG.md. Orchestrates doc-claude-md, doc-readme, doc-skills-md, and doc-changelog skills sequentially. Use when: project docs are stale, after major changes, initial project setup, sync all docs. Triggers: update all docs, update project docs, sync documentation, refresh docs, doc-project."
---

# Project Documentation Sync

Update all project documentation files in one pass by delegating to specialized skills.

## Workflow

```
1. Analyze codebase → 2. CLAUDE.md + AGENTS.md → 3. README.md → 4. SKILLS.md → 5. CHANGELOG.md → 6. Summary
```

### 1. Analyze Codebase

Before updating any docs, gather project state:

```bash
# Project type signals
ls package.json go.mod pyproject.toml Cargo.toml Dockerfile *.tf 2>/dev/null

# Current doc state
ls CLAUDE.md AGENTS.md README.md SKILLS.md 2>/dev/null

# Recent changes since docs were last updated
git log --oneline -20

# Plugin/skill count if marketplace repo
ls plugins/ 2>/dev/null | wc -l
```

### 2. CLAUDE.md + AGENTS.md

Delegate to `doc-claude-md` skill:

```
Skill(skill="doc-claude-md")
```

This handles:
- Creating or validating CLAUDE.md (pointer file)
- Creating or updating AGENTS.md (full project instructions, structure, conventions)
- Updating `last_validated` timestamp and counts in frontmatter

### 3. README.md

Delegate to `doc-readme` skill:

```
Skill(skill="doc-readme")
```

This handles:
- Creating or updating README.md
- Syncing with current codebase state (features, structure, install steps)

### 4. SKILLS.md

Delegate to `doc-skills-md` skill:

```
Skill(skill="doc-skills-md")
```

This handles:
- Analyzing project to recommend relevant marketplace plugins
- Creating or updating Required/Recommended tables
- Updating plugin counts

Skip this step if the project does not use a plugin marketplace.

### 5. CHANGELOG.md

Delegate to `doc-changelog` skill:

```
Skill(skill="doc-changelog")
```

This handles:
- Generating changelog entries from git history since last release/tag
- Classifying commits by type (Added, Changed, Fixed, Removed)
- Enriching entries with PR references
- Updating the Unreleased section

Skip this step if the project does not maintain a CHANGELOG.md.

### 6. Summary

After all updates, report what changed:

```
## Documentation Updated

| File | Action | Changes |
|------|--------|---------|
| CLAUDE.md | Updated/Created/No change | ... |
| AGENTS.md | Updated/Created/No change | ... |
| README.md | Updated/Created/No change | ... |
| SKILLS.md | Updated/Created/Skipped | ... |
| CHANGELOG.md | Updated/Created/Skipped | ... |
```

## Modes

### Full Sync (default)

Update all five files. Use for initial setup or after major changes.

> "Update all project docs"

### Selective

Update only specified files. Name them explicitly.

> "Update AGENTS.md and README.md"

### Validate Only

Check docs without modifying. Report what's stale.

> "Check if project docs are up to date"

For validate-only, read each file and compare against codebase state. Report discrepancies without editing.
