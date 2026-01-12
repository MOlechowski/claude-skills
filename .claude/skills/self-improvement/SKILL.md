---
name: self-improvement
description: |
  Protocol for documents that evolve through use - capturing learnings as they're discovered.

  Use this skill when:
  - Completing work that revealed missing instructions
  - Finding workarounds for undocumented blockers
  - Discovering patterns that work better than documented
  - Wanting to capture learnings for future sessions

  Examples:
  - "update the instructions based on what we learned"
  - "add this pattern to the docs"
  - "capture this workaround"
  - "improve the workflow documentation"
---

# Self-Improvement Protocol

You are an expert at maintaining living documents that evolve through use. This protocol governs how instruction documents improve over time by capturing learnings, patterns, and workarounds.

## Core Principle

Documents should get better with every use. When you discover something that would have helped you earlier, add it so future sessions benefit.

## Scope

Documents subject to self-improvement:

- `CLAUDE.md` / `AGENTS.md` - Project-level instructions
- Workflow prompts and task instructions
- Skill documentation (SKILL.md files)
- Any instruction file that guides autonomous work

**Not in scope:**
- Source code (use normal development practices)
- Generated files
- External documentation you don't control

## Update Triggers

Update documents when any of these occur:

### 1. Missing Instructions
You completed a task but had to figure out something not documented.

*Example: "I had to run `go generate ./...` before tests would pass, but this wasn't mentioned."*

### 2. Workaround Discovery
You found a way around an undocumented blocker.

*Example: "Pre-commit hooks fail on generated files - solution is to run generation first."*

### 3. Better Pattern Found
You discovered an approach that works better than what's documented.

*Example: "Using interfaces with mocks is cleaner than the inline stub approach shown."*

### 4. New Blocker Category
You hit a type of blocked task not previously documented.

*Example: "E2E tests need GitHub App credentials that aren't available in CI."*

### 5. Confusion or Ambiguity
The documentation led to confusion or wrong assumptions.

*Example: "Unclear whether 'deploy' meant local or production - clarify scope."*

## Update Rules

### 1. Prove Before Adding
Only add patterns that worked in practice. Don't add theoretical improvements - wait until you've verified they work.

### 2. Extend, Don't Duplicate
Add to existing sections first. Create new sections only when content doesn't fit anywhere.

### 3. Be Concrete
Include commands, code snippets, and file paths. Vague guidance isn't useful.

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
No task-specific details. Keep it reusable across similar situations.

```markdown
# Bad
"For PR #42, use the special flag --skip-validation"

# Good
"When validation blocks legitimate changes, use --skip-validation flag"
```

### 5. Preserve History
Don't remove rules without documenting why. If something seems obsolete, add a note rather than deleting.

```markdown
# Deprecated (2024-01-15): No longer needed after v2.0 migration
~~Old rule about X~~
```

## Update Process

### Step 1: Identify the Learning
What did you discover that would have helped earlier?

### Step 2: Determine Location
Which document and section should contain this?

- Project setup → CLAUDE.md / AGENTS.md
- Workflow steps → Relevant prompt file
- Tool usage → Skill documentation

### Step 3: Write the Addition
Concise, actionable, with examples where helpful.

### Step 4: Commit the Change
```bash
git add <document>
git commit -m "docs: improve <filename> - <brief description>"
```

### Step 5: Log in History
Add entry to the Document History section:

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

Track changes by type:

| Category | Description |
|----------|-------------|
| **Rules** | New constraints or requirements |
| **Patterns** | Reusable approaches and techniques |
| **Blockers** | Known limitations and workarounds |
| **Workflow** | Process improvements |

## Document History Template

Add this section to documents under self-improvement:

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

See `quick-reference.md` for checklists and templates.
