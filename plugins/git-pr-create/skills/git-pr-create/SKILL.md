---
name: git-pr-create
description: "Create GitHub PRs with structured title and body. Use when: opening PRs, creating pull requests after pushing. Triggers: /git-pr-create, create PR, open pull request."
---

# PR Create

Create GitHub pull requests via `gh pr create`.

## Format

**Title:** Commit subject or change summary

**Body:**
```
## Summary
- Change description (bullets OK)

## Test plan
- [ ] Verification steps
```

## Workflow

1. Verify not on main/master
2. Check for existing PR on branch
3. Detect base branch
4. Generate title from commits
5. Build body with summary + test plan
6. Create PR

## Commands

```bash
# Check current branch
git branch --show-current

# Check for existing PR
gh pr list --head $(git branch --show-current)

# Create PR
gh pr create --title "$TITLE" --body "$(cat <<'EOF'
## Summary
- Change 1
- Change 2

## Test plan
- [ ] Test item
EOF
)"
```

## Title Generation

Use first commit subject from branch, or summarize if multiple commits:

```bash
# Single commit - use subject
git log origin/main..HEAD --format='%s' | head -1

# Multiple commits - summarize changes
git log origin/main..HEAD --oneline
```

## Body Style

Bullets allowed in PR body (unlike commit messages):
- Summary section lists changes
- Test plan uses checkboxes

Keep concise. One line per logical change.

## Draft PRs

Use `--draft` when:
- Work in progress
- User requests draft
- Waiting for CI setup

```bash
gh pr create --draft --title "$TITLE" --body "$BODY"
```

## Base Branch

Detect automatically:
```bash
gh repo view --json defaultBranchRef --jq '.defaultBranchRef.name'
```

Override with `--base`:
```bash
gh pr create --base develop --title "$TITLE" --body "$BODY"
```

## Safety

- Verify branch is not main/master before creating
- Check for existing PR to avoid duplicates
- Never create PR from main to main
