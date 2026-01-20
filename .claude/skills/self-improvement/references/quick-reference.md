# Self-Improvement Quick Reference

## Trigger Checklist

After completing work:

- [ ] Figured out something not documented?
- [ ] Found a workaround for a blocker?
- [ ] Discovered a better approach?
- [ ] Hit a new type of blocked task?
- [ ] Found something confusing or ambiguous?

If any checked, update the relevant document.

## Update Rules Summary

| Rule | Do | Don't |
|------|-----|-------|
| **Prove first** | Add patterns that worked | Add theoretical ideas |
| **Extend** | Add to existing sections | Create duplicates |
| **Be concrete** | Include commands, code, paths | Vague guidance |
| **Stay general** | Make it reusable | Task-specific details |
| **Preserve history** | Note why rules changed | Delete silently |

## Commit Format

```bash
git commit -m "docs: improve <filename> - <brief description>"
```

Examples:
```bash
git commit -m "docs: improve CLAUDE.md - add mock generation workflow"
git commit -m "docs: improve workflow.md - document E2E test blockers"
git commit -m "docs: improve AGENTS.md - clarify deployment scope"
```

## History Entry Format

```markdown
**Category**
- YYYY-MM-DD: Brief description
```

Example:
```markdown
**Patterns**
- 2024-01-15: Added interface-based mocking for external clients
- 2024-01-14: Documented parallel PR workflow with git worktrees

**Blockers**
- 2024-01-13: E2E tests require GitHub App credentials not in CI
```

## History Categories

| Category | When to Use |
|----------|-------------|
| **Rules** | Constraints, requirements |
| **Patterns** | Reusable techniques |
| **Blockers** | Limitations, workarounds |
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

## Good vs Bad Examples

### Being Concrete

```markdown
# Bad
"Handle errors appropriately"

# Good
"Wrap external calls:
```go
if err := client.Do(); err != nil {
    return fmt.Errorf("client failed: %w", err)
}
```"
```

### Staying General

```markdown
# Bad
"For the auth service PR, skip the linter check"

# Good
"When linter blocks generated code, add to .lintignore"
```

### Preserving History

```markdown
# Bad
(just delete the old rule)

# Good
"# Deprecated (2024-01-15): No longer needed after v2.0
~~Old approach: manually run X before Y~~
New approach: Automated in pre-commit hook"
```

## Quick Decision Tree

```
Did I learn something useful?
    |
    +-> No -> Done
    |
    +-> Yes -> Is it documented?
                |
                +-> Yes -> Correct? -> Yes -> Done
                |                  -> No -> Update
                |
                +-> No -> Add it
```

## Files Commonly Updated

| File | Contains |
|------|----------|
| `CLAUDE.md` | Project instructions, setup |
| `AGENTS.md` | Agent-specific guidance |
| `*-prompt.md` | Workflow instructions |
| `SKILL.md` | Skill documentation |
