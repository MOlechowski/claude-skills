---
name: commit-pr
description: "Commit changes and create PR in one flow. Use when: committing and creating PR in one step, shipping a feature, pushing changes with PR. Triggers: /commit-pr, ship this, commit and PR, push and create PR."
---

# Commit & PR

Full commit-to-PR flow: generate commit message, create feature branch, push, open PR.

## Workflow

```
1. Check changes → 2. Create branch → 3. Commit → 4. Push → 5. Create PR → 6. Merge
```

## Steps

### 1. Check Changes

```bash
git status
git diff --staged
git diff
```

If nothing staged:
```bash
git add -A
```

### 2. Detect Repo Style

```bash
git log --oneline -10
```

Match language and format from recent commits.

### 3. Create Feature Branch

If on main/master:

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

Output PR URL:
```
PR created: https://github.com/owner/repo/pull/123
```

### 8. Merge

Chain to gh-pr skill:

```
Skill(skill="gh-pr", args="PR_NUMBER")
```

gh-pr handles:
- CI status checks
- Review processing
- Auto-merge when ready

Skip only if user requests "create PR only" or "no merge".

## Atomic Commits

One commit = one logical change.

If changes need different types (feat + fix), split into separate commits and PRs.

## Safety

- Never commit secrets
- Create feature branch (not main)
- Verify staged files before commit

## Quick Reference

| Step | Command |
|------|---------|
| Stage | `git add -A` |
| Branch | `git checkout -b feat/name` |
| Commit | `git commit -m "type(scope): msg"` |
| Push | `git push -u origin branch` |
| PR | `gh pr create --title "..." --body "..."` |
| Merge | Chain to `gh-pr` skill (automatic) |
