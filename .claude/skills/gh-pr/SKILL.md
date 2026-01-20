---
name: gh-pr
description: Autonomous PR lifecycle management. Use when: checking PR status, merging PRs, processing reviews, handling CI failures. Triggers: /gh-pr, "merge the PR", "check PR status", "is this ready to merge?", "handle review comments".
---

# GH-PR

Handle PRs autonomously using GitHub CLI (`gh`). Works with GitHub native reviews, bot reviewers, and human reviewers.

## Core Workflow

```
Status Check → Fix Issues → Request Review → Merge
```

## Decision Matrix

Apply this matrix for every PR action:

| Review State | CI Status | Action |
|--------------|-----------|--------|
| Any | FAILING | Fix lint/test errors, push |
| CHANGES_REQUESTED | PASSING | Address comments, push, re-review |
| COMMENTED | PASSING | Merge (minor suggestions) |
| APPROVED | CLEAN | Merge |
| empty | CLEAN | Merge (no review required) |
| PENDING | BLOCKED | Wait for review |

## Autonomy

When invoked without specific PR number:
1. List all open PRs in single call
2. Apply decision matrix to each
3. Act immediately on mergeable PRs
4. Report results after actions

Do not ask "Merge?" - merge if conditions met.

## Workflow Steps

### 1. Status Check

Single call for all open PRs:

```bash
gh pr list --state open --json number,title,headRefName,reviewDecision,mergeStateStatus,mergeable,isDraft
```

For specific PR:

```bash
gh pr view $PR --json number,title,reviewDecision,mergeStateStatus,mergeable
```

### 2. Check Reviews

```bash
# All reviews (human + bot)
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq '.[] | {user: .user.login, type: .user.type, state: .state}'

# Latest review per reviewer
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq 'group_by(.user.login) | map({user: .[0].user.login, state: .[-1].state})'

# Bot reviewers only
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq '[.[] | select(.user.type == "Bot")] | .[-1]'
```

### 3. Fix Cycle

When CI fails or comments need addressing:

```bash
MAX_FIX_CYCLES=5
fix_count=0

while [ $fix_count -lt $MAX_FIX_CYCLES ]; do
    # 1. Read failure logs
    gh pr checks $PR --json name,state,conclusion \
      --jq '.[] | select(.conclusion == "FAILURE")'

    # 2. Fix the issues (lint, test, review comments)
    # ... apply fixes ...

    # 3. Commit and push
    git add -A && git commit -m "fix: address review feedback" && git push

    # 4. Wait for CI
    sleep 30

    # 5. Re-check status
    status=$(gh pr view $PR --json mergeStateStatus --jq '.mergeStateStatus')
    if [ "$status" = "CLEAN" ]; then
        break
    fi

    ((fix_count++))
done

if [ $fix_count -ge $MAX_FIX_CYCLES ]; then
    echo "ERROR: Max fix cycles ($MAX_FIX_CYCLES) reached. Manual intervention required."
    exit 1
fi
```

### 4. Request Re-review

After addressing CHANGES_REQUESTED:

```bash
# For human reviewers - re-request review
gh pr edit $PR --add-reviewer $REVIEWER

# For bot reviewers - typically triggered by:
# - Pushing new commits (automatic)
# - Comment with @bot review (check bot's docs)
```

### 5. Merge

When APPROVED + CLEAN:

```bash
# Squash merge (recommended)
gh pr merge $PR --squash --delete-branch

# Merge commit (preserves history)
gh pr merge $PR --merge --delete-branch

# Auto-merge when checks pass
gh pr merge $PR --auto --squash
```

## Multi-PR Queue Processing

```bash
# List all open PRs
prs=$(gh pr list --state open --json number --jq '.[].number')

# Process each
for pr in $prs; do
    echo "Processing PR #$pr"

    # Get status
    status=$(gh pr view $pr --json reviewDecision,mergeStateStatus,isDraft \
      --jq '{review: .reviewDecision, merge: .mergeStateStatus, draft: .isDraft}')

    # Skip drafts
    if echo "$status" | grep -q '"draft":true'; then
        echo "  SKIPPED (draft)"
        continue
    fi

    # Apply decision matrix
    # ... process based on status ...
done

# Summary
gh pr list --state open --json number,title,reviewDecision
```

## Error Handling

### Rate Limits

```bash
remaining=$(gh api rate_limit --jq '.rate.remaining')
if [ "$remaining" -lt 100 ]; then
    reset=$(gh api rate_limit --jq '.rate.reset')
    sleep_time=$((reset - $(date +%s)))
    echo "Rate limited. Waiting ${sleep_time}s"
    sleep $sleep_time
fi
```

### Merge Conflicts

If `mergeable: CONFLICTING`:
1. Report conflict to user
2. Do NOT attempt auto-resolve
3. Suggest: `git fetch origin && git rebase origin/main`

### Branch Protection

If merge blocked by protection rules:
1. Check required reviewers
2. Report missing approvals
3. Do NOT bypass protections

## Output Format

Action mode (merging):

```
Merging #18, #20...
#18: merged
#20: merged
```

Status mode (check only):

```
#18: CLEAN, mergeable
#20: BLOCKED (conflicts)
#21: WAITING (CI running)
```

## Safety Rules

1. **Never force push** to shared branches
2. **Never bypass** branch protection
3. **Always verify** CI passes before merge
4. **Stop on conflicts** - require human resolution
5. **Max 5 fix cycles** - prevent infinite loops
6. **Log all actions** for audit trail

See `quick-reference.md` for full gh CLI reference.
See `decision-tree.md` for edge case handling.
