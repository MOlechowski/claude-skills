# GH-PR Quick Reference

## PR Listing

```bash
gh pr list --state open
gh pr list --state open --json number,title,headRefName,reviewDecision,mergeable
gh pr list --author @me --state open
gh pr list --search "review:required"
gh pr list --search "review:approved status:success"
```

## PR Status

```bash
# Full details
gh pr view $PR --json number,title,state,body,author,reviewDecision,mergeStateStatus,mergeable,statusCheckRollup,labels

# Quick status
gh pr view $PR --json reviewDecision,mergeStateStatus,mergeable \
  --jq '{review: .reviewDecision, merge: .mergeStateStatus, mergeable: .mergeable}'

# Current branch PR
gh pr view --json number,reviewDecision,mergeStateStatus

# CI checks
gh pr checks $PR
gh pr checks $PR --json name,conclusion --jq '.[] | select(.conclusion != "SUCCESS")'
```

## Review Operations

```bash
# All reviews
gh api repos/{owner}/{repo}/pulls/$PR/reviews

# Latest per user
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq 'group_by(.user.login) | map({user: .[0].user.login, type: .[0].user.type, state: .[-1].state})'

# Bot reviewers only
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq '[.[] | select(.user.type == "Bot")] | .[-1]'

# Request re-review
gh pr edit $PR --add-reviewer $USERNAME
```

## Merge Operations

```bash
gh pr merge $PR --squash --delete-branch    # Squash (recommended)
gh pr merge $PR --merge --delete-branch     # Merge commit
gh pr merge $PR --rebase --delete-branch    # Rebase
gh pr merge $PR --auto --squash             # Auto-merge when checks pass
gh pr merge $PR --disable-auto              # Disable auto-merge
```

## Branch Operations

```bash
gh pr view --json number --jq '.number'                           # Current branch PR
gh pr list --head $(git branch --show-current) --json number      # Branch has PR?
gh pr list --head feature/my-branch --json number,state           # PR for branch
```

## Merge State Values

| `mergeStateStatus` | Meaning |
|--------------------|---------|
| `CLEAN` | Ready to merge |
| `BLOCKED` | Protected by rules |
| `BEHIND` | Needs rebase |
| `DIRTY` | Has conflicts |
| `UNSTABLE` | Checks failing |

| `mergeable` | Meaning |
|-------------|---------|
| `MERGEABLE` | Can be merged |
| `CONFLICTING` | Has conflicts |
| `UNKNOWN` | Not computed |

| `reviewDecision` | Meaning |
|------------------|---------|
| `APPROVED` | All approvals |
| `CHANGES_REQUESTED` | Changes requested |
| `REVIEW_REQUIRED` | Needs review |
| `null` | No reviews |

## Error Checking

```bash
gh pr view $PR --json mergeable --jq '.mergeable'
gh pr view $PR --json mergeStateStatus --jq '.mergeStateStatus'
gh pr view $PR --json isDraft --jq '.isDraft'

# Blocking details
gh pr view $PR --json mergeStateStatus,statusCheckRollup \
  --jq '{state: .mergeStateStatus, failed: [.statusCheckRollup[] | select(.conclusion != "SUCCESS") | .name]}'
```

## Rate Limiting

```bash
gh api rate_limit --jq '.rate | {remaining, reset: (.reset | strftime("%H:%M:%S"))}'
gh api rate_limit --jq '.rate.remaining'
```

## jq Patterns

```bash
--jq '.statusCheckRollup[] | select(.conclusion == "FAILURE") | .name'
--jq '"\(.number): \(.title) [\(.reviewDecision // "PENDING")]"'
--jq '[.statusCheckRollup[].conclusion] | all(. == "SUCCESS")'
--jq 'sort_by(.reviewDecision == "APPROVED" | not)'
```
