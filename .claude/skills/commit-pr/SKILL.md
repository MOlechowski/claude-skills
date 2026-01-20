---
name: commit-pr
description: Commit changes and create PR in one flow.
---

# Commit & PR: Ship Changes

Use this skill when:
- You want to commit and create a PR in one step
- You finished a feature and want to ship it
- You need to commit, push, and open a PR

Examples:
- "commit and create PR"
- "ship this"
- "commit and PR"
- "push and create PR"

You handle the full commit-to-PR flow: generate commit message, create feature branch, push, and open PR.

## Workflow

```
1. Check changes → 2. Create branch → 3. Commit → 4. Push → 5. Create PR
```

## Steps

### 1. Check Changes

```bash
git status
git diff --staged
git diff
```

If nothing staged, stage all changes:
```bash
git add -A
```

### 2. Detect Repo Style

```bash
git log --oneline -10
```

Match language and format from recent commits.

### 3. Create Feature Branch

If on main/master, create feature branch:

```bash
BRANCH="feat/$(echo "$COMMIT_MSG" | sed 's/^[a-z]*(\([^)]*\)).*/\1/' | tr ' ' '-')"
git checkout -b "$BRANCH"
```

Branch naming:
- `feat/scope-name` for features
- `fix/scope-name` for fixes

### 4. Commit

Generate commit message following repo style:

```bash
git commit -m "$(cat <<'EOF'
type(scope): description

Optional body.
EOF
)"
```

Commit types: feat, fix, docs, style, refactor, perf, test, build, ci, chore

### 5. Push

```bash
git push -u origin "$BRANCH"
```

### 6. Create PR

```bash
gh pr create --title "$COMMIT_SUBJECT" --body "$(cat <<'EOF'
## Summary
- Change 1
- Change 2

## Test plan
- [ ] Test item
EOF
)"
```

PR body:
- Summary from commit message
- Test plan with checkboxes

### 7. Report

Output PR URL when done:
```
PR created: https://github.com/owner/repo/pull/123
```

## Atomic Commits

One commit = one logical change.

If changes need different types (feat + fix), split into separate commits and PRs.

## Safety

- Never commit secrets
- Create feature branch (don't commit to main)
- Verify staged files before commit

## Quick Reference

| Step | Command |
|------|---------|
| Stage | `git add -A` |
| Branch | `git checkout -b feat/name` |
| Commit | `git commit -m "type(scope): msg"` |
| Push | `git push -u origin branch` |
| PR | `gh pr create --title "..." --body "..."` |
