---
name: pr-manage
description: "Autonomous PR lifecycle management. Use when: checking PR status, merging PRs, processing reviews, handling CI failures. Triggers: /pr-manage, merge the PR, check PR status, is this ready to merge?, handle review comments."
---

# PR Manage

Autonomous PR lifecycle management via GitHub CLI (`gh`). Works with GitHub native reviews, bot reviewers, and human reviewers.

## Core Workflow

```
Status Check -> Fix Issues -> Request Review -> Merge
```

## Decision Matrix

| Review State | CI Status | Action |
|--------------|-----------|--------|
| Any | FAILING | Fix lint/test errors, push |
| CHANGES_REQUESTED | PASSING | Address comments, push, re-review |
| COMMENTED | PASSING | Merge (minor suggestions) |
| APPROVED | CLEAN | Merge |
| empty | CLEAN | Merge (no review required) |
| PENDING | BLOCKED | Wait for review |

## Autonomy

Without specific PR number:
1. List all open PRs in single call
2. Apply decision matrix to each
3. Act on mergeable PRs immediately
4. Report results after actions

Never ask "Merge?" - merge if conditions met.

## Workflow Steps

### 1. Status Check

```bash
# All open PRs
gh pr list --state open --json number,title,headRefName,reviewDecision,mergeStateStatus,mergeable,isDraft

# Specific PR
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

```bash
MAX_FIX_CYCLES=5
fix_count=0

while [ $fix_count -lt $MAX_FIX_CYCLES ]; do
    # 1. Read failures
    gh pr checks $PR --json name,state,conclusion \
      --jq '.[] | select(.conclusion == "FAILURE")'

    # 2. Fix issues
    # ... apply fixes ...

    # 3. Commit and push
    git add -A && git commit -m "fix: address review feedback" && git push

    # 4. Wait and re-check
    sleep 30
    status=$(gh pr view $PR --json mergeStateStatus --jq '.mergeStateStatus')
    [ "$status" = "CLEAN" ] && break

    ((fix_count++))
done

[ $fix_count -ge $MAX_FIX_CYCLES ] && echo "ERROR: Max fix cycles reached" && exit 1
```

### 4. Request Re-review

```bash
# Human reviewers
gh pr edit $PR --add-reviewer $REVIEWER

# Bot reviewers - push new commits or comment @bot review
```

### 5. Merge

```bash
gh pr merge $PR --squash --delete-branch    # Squash (recommended)
gh pr merge $PR --merge --delete-branch     # Merge commit
gh pr merge $PR --auto --squash             # Auto-merge when checks pass
```

## Multi-PR Queue Processing

```bash
prs=$(gh pr list --state open --json number --jq '.[].number')

for pr in $prs; do
    echo "Processing PR #$pr"
    status=$(gh pr view $pr --json reviewDecision,mergeStateStatus,isDraft \
      --jq '{review: .reviewDecision, merge: .mergeStateStatus, draft: .isDraft}')

    # Skip drafts
    echo "$status" | grep -q '"draft":true' && echo "  SKIPPED (draft)" && continue

    # Apply decision matrix...
done

gh pr list --state open --json number,title,reviewDecision
```

## Error Handling

### Rate Limits
```bash
remaining=$(gh api rate_limit --jq '.rate.remaining')
if [ "$remaining" -lt 100 ]; then
    reset=$(gh api rate_limit --jq '.rate.reset')
    sleep $((reset - $(date +%s)))
fi
```

### Merge Conflicts
If `mergeable: CONFLICTING`: Report to user, do NOT auto-resolve. Suggest: `git fetch origin && git rebase origin/main`

### Branch Protection
If blocked: Check required reviewers, report missing approvals, do NOT bypass.

## Output Format

Action mode:
```
Merging #18, #20...
#18: merged
#20: merged
```

Status mode:
```
#18: CLEAN, mergeable
#20: BLOCKED (conflicts)
#21: WAITING (CI running)
```

## Safety Rules

1. **Never force push** to shared branches
2. **Never bypass** branch protection
3. **Verify CI passes** before merge
4. **Stop on conflicts** - require human resolution
5. **Max 5 fix cycles** - prevent infinite loops
6. **Log all actions** for audit

## References

- [references/quick-reference.md](references/quick-reference.md) - gh CLI reference
- [references/decision-tree.md](references/decision-tree.md) - Complex PR scenarios
