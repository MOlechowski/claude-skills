# GH-PR Quick Reference

## PR Listing

```bash
# List all open PRs
gh pr list --state open

# With details
gh pr list --state open --json number,title,headRefName,reviewDecision,mergeable

# List PRs by author
gh pr list --author @me --state open

# List PRs needing review
gh pr list --search "review:required"

# List approved PRs ready to merge
gh pr list --search "review:approved status:success"
```

## PR Status

```bash
# Full PR details
gh pr view $PR --json number,title,state,body,author,reviewDecision,mergeStateStatus,mergeable,statusCheckRollup,labels

# Quick status check
gh pr view $PR --json reviewDecision,mergeStateStatus,mergeable \
  --jq '{review: .reviewDecision, merge: .mergeStateStatus, mergeable: .mergeable}'

# Current branch PR
gh pr view --json number,reviewDecision,mergeStateStatus

# CI checks status
gh pr checks $PR
gh pr checks $PR --json name,state,conclusion
gh pr checks $PR --json name,conclusion --jq '.[] | select(.conclusion != "SUCCESS")'
```

## Review Operations

```bash
# Get all reviews
gh api repos/{owner}/{repo}/pulls/$PR/reviews

# Latest review per user
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq 'group_by(.user.login) | map({user: .[0].user.login, type: .[0].user.type, state: .[-1].state})'

# Bot reviewers only
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq '[.[] | select(.user.type == "Bot")] | .[-1]'

# Human reviewers only
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq '[.[] | select(.user.type == "User")]'

# Request re-review
gh pr edit $PR --add-reviewer $USERNAME

# Review comments count
gh api repos/{owner}/{repo}/pulls/$PR/comments --jq 'length'
```

## Merge Operations

```bash
# Squash merge with branch deletion (recommended)
gh pr merge $PR --squash --delete-branch

# Merge commit (preserves history)
gh pr merge $PR --merge --delete-branch

# Rebase merge
gh pr merge $PR --rebase --delete-branch

# Auto-merge when checks pass
gh pr merge $PR --auto --squash

# Disable auto-merge
gh pr merge $PR --disable-auto
```

## Branch Operations

```bash
# Get current branch's PR number
gh pr view --json number --jq '.number'

# Check if branch has open PR
gh pr list --head $(git branch --show-current) --json number --jq '.[0].number'

# Get PR for specific branch
gh pr list --head feature/my-branch --json number,state
```

## Merge State Values

| `mergeStateStatus` | Meaning |
|--------------------|---------|
| `CLEAN` | Ready to merge |
| `BLOCKED` | Protected by rules |
| `BEHIND` | Needs rebase/update |
| `DIRTY` | Has merge conflicts |
| `UNKNOWN` | State not determined |
| `UNSTABLE` | Checks failing |

| `mergeable` | Meaning |
|-------------|---------|
| `MERGEABLE` | Can be merged |
| `CONFLICTING` | Has conflicts |
| `UNKNOWN` | Not yet computed |

| `reviewDecision` | Meaning |
|------------------|---------|
| `APPROVED` | All required approvals |
| `CHANGES_REQUESTED` | Changes requested |
| `REVIEW_REQUIRED` | Needs review |
| `null` | No reviews yet |

## Error Checking

```bash
# Check for merge conflicts
gh pr view $PR --json mergeable --jq '.mergeable'

# Check merge state
gh pr view $PR --json mergeStateStatus --jq '.mergeStateStatus'

# Get blocking details
gh pr view $PR --json mergeStateStatus,statusCheckRollup \
  --jq '{state: .mergeStateStatus, failed: [.statusCheckRollup[] | select(.conclusion != "SUCCESS") | .name]}'

# Check if draft
gh pr view $PR --json isDraft --jq '.isDraft'
```

## Rate Limiting

```bash
# Check API rate limit
gh api rate_limit --jq '.rate | {remaining, reset: (.reset | strftime("%H:%M:%S"))}'

# Check GraphQL rate limit
gh api rate_limit --jq '.resources.graphql | {remaining, reset: (.reset | strftime("%H:%M:%S"))}'

# Remaining calls
gh api rate_limit --jq '.rate.remaining'
```

## Useful jq Patterns

```bash
# Extract failed checks
--jq '.statusCheckRollup[] | select(.conclusion == "FAILURE") | .name'

# Format PR summary
--jq '"\(.number): \(.title) [\(.reviewDecision // "PENDING")]"'

# Check if all checks pass
--jq '[.statusCheckRollup[].conclusion] | all(. == "SUCCESS")'

# Sort PRs by approval status
--jq 'sort_by(.reviewDecision == "APPROVED" | not)'
```
