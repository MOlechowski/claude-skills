---
name: dev-review
description: "Code review orchestrator. Auto-detects context and routes to the appropriate reviewer. Handles: file/directory review (static analysis), PR review (GitHub PRs), diff review (staged/unstaged changes). Scores code on six pillars with numeric 1-10 grading. Use when: reviewing code, code review, give me feedback. Triggers: review this, code review, review my code, review PR, review these files."
---

# Code Review

Route review requests to the correct sub-skill. Never perform reviews directly.

## Detection Logic

Run checks in order. Stop at first match.

### Check 1: Explicit PR Reference

User message contains PR number (`#123`), PR URL, or words "pull request" / "PR":

→ Delegate to `dev-review-pr` with PR context.

### Check 2: Explicit File/Directory Reference

User message contains file paths (`*.py`, `src/`, `./main.go`), directory names, or "this file":

→ Delegate to `dev-review-file` with those paths.

### Check 3: Implicit Diff Context

```bash
# Check for staged changes
git diff --cached --stat 2>/dev/null

# Check for unstaged changes
git diff --stat 2>/dev/null
```

If either has output:

→ Delegate to `dev-review-pr` in diff mode. Prefer staged changes if both exist.

### Check 4: Ambiguous

No context detected.

→ Ask: "What should I review? Options: (1) provide file paths or a directory, (2) provide a PR number, (3) I can review your staged/unstaged changes."

## Output Mode

Detect from user request:
- "inline comments", "annotate", "comment on the code", "inline" → inline mode
- Otherwise → structured report (default)

Pass the detected mode to the sub-skill.

## Delegation

Delegate entirely. Do not perform the dev-review yourself. Do not add your own scoring or summary on top of the sub-skill output.

## Sub-skills

| Skill | Purpose |
|-------|---------|
| `dev-review-file` | Static code analysis of files and directories |
| `dev-review-pr` | Change-focused review of diffs and GitHub PRs |

Both sub-skills analyze six pillars (Security, Performance, Architecture, Error Handling, Testing, Maintainability), score 1-10 with harsh grading, and produce structured reports or inline comments.
