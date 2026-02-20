---
name: dev-learn
description: "Capture learnings into documentation. Use when: completing work that revealed missing instructions, finding workarounds for undocumented blockers, discovering patterns that work better than documented, capturing session learnings. Triggers: update the instructions based on what we learned, add this pattern to the docs, capture this workaround, improve the workflow documentation."
---

# Self-Improvement Protocol

Governs how instruction documents improve by capturing learnings, patterns, and workarounds.

## Core Principle

Documents get better with every use. When you discover something that would have helped earlier, add it for future sessions.

## Scope

Documents subject to self-improvement:

- `CLAUDE.md` / `AGENTS.md` - Project-level instructions
- Workflow prompts and task instructions
- Skill documentation (SKILL.md files)
- Any instruction file guiding autonomous work

**Not in scope:** Source code, generated files, external documentation

## Update Triggers

Update documents when:

### 1. Missing Instructions
You figured out something not documented.

*Example: "Had to run `go generate ./...` before tests would pass."*

### 2. Workaround Discovery
You found a way around an undocumented blocker.

*Example: "Pre-commit hooks fail on generated files - run generation first."*

### 3. Better Pattern Found
You discovered a better approach than documented.

*Example: "Interfaces with mocks are cleaner than inline stubs."*

### 4. New Blocker Category
You hit a type of blocked task not previously documented.

*Example: "E2E tests need GitHub App credentials not in CI."*

### 5. Confusion or Ambiguity
Documentation led to confusion or wrong assumptions.

*Example: "Unclear whether 'deploy' meant local or production."*

## Update Rules

### 1. Prove Before Adding
Add patterns that worked in practice. Don't add theoretical improvements.

### 2. Extend, Don't Duplicate
Add to existing sections first. Create new sections only when content doesn't fit.

### 3. Be Concrete
Include commands, code snippets, and file paths.

```markdown
# Bad
"Make sure to handle errors properly"

# Good
"Wrap external calls with error handling:
```go
if err := client.Call(); err != nil {
    return fmt.Errorf("client call failed: %w", err)
}
```"
```

### 4. Stay General
No task-specific details. Keep it reusable.

```markdown
# Bad
"For PR #42, use --skip-validation"

# Good
"When validation blocks legitimate changes, use --skip-validation"
```

### 5. Preserve History
Don't remove rules without documenting why.

```markdown
# Deprecated (2024-01-15): No longer needed after v2.0 migration
~~Old rule about X~~
```

## Update Process

### Step 1: Identify the Learning
What would have helped earlier?

### Step 2: Determine Location
- Project setup -> CLAUDE.md / AGENTS.md
- Workflow steps -> Relevant prompt file
- Tool usage -> Skill documentation

### Step 3: Write the Addition
Concise, actionable, with examples.

### Step 4: Commit the Change
```bash
git add <document>
git commit -m "docs: improve <filename> - <brief description>"
```

### Step 5: Log in History
```markdown
## Document History

**Rules**
- 2024-01-15: Added error handling pattern for external calls

**Patterns**
- 2024-01-14: Added mock generation workflow

**Blockers**
- 2024-01-13: Documented E2E test credential requirements
```

## History Categories

| Category | Description |
|----------|-------------|
| **Rules** | Constraints or requirements |
| **Patterns** | Reusable approaches |
| **Blockers** | Limitations and workarounds |
| **Workflow** | Process improvements |

## Document History Template

```markdown
## Document History

Track changes by category:

**Rules**
<!-- YYYY-MM-DD: Description -->

**Patterns**
<!-- YYYY-MM-DD: Description -->

**Blockers**
<!-- YYYY-MM-DD: Description -->

**Workflow**
<!-- YYYY-MM-DD: Description -->
```

## Quick Reference

See `references/quick-reference.md` for checklists and templates.
