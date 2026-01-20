# GH-PR Decision Tree

## Main Decision Flow

```
START: PR #N
    |
    +-> Check CI Status
    |       |
    |       +-> FAILING --------------> FIX: Address failures, push
    |       |                                    |
    |       |                                    +-> RETRY (max 5 cycles)
    |       |
    |       +-> PASSING --------------> Check Review State
    |                                          |
    +------------------------------------------+
    |
    +-> Review State
    |       |
    |       +-> PENDING --------------> WAIT: Review not started
    |       |
    |       +-> CHANGES_REQUESTED ----> Check Comments
    |       |       |
    |       |       +-> Unresolved ---> FIX: Address comments, push
    |       |       |
    |       |       +-> All resolved -> REQUEST: Re-review
    |       |
    |       +-> COMMENTED ------------> MERGE: Safe (minor suggestions)
    |       |
    |       +-> APPROVED -------------> Check Merge State
    |                                          |
    +------------------------------------------+
    |
    +-> Merge State
            |
            +-> CLEAN ----------------> MERGE: gh pr merge --squash
            |
            +-> BEHIND ---------------> UPDATE: Rebase on main
            |
            +-> BLOCKED --------------> WAIT: Protection rules
            |
            +-> DIRTY ----------------> STOP: Merge conflict
            |
            +-> UNKNOWN --------------> RETRY: Check again
```

## Edge Cases

### 1. Stale Review

**Condition:** APPROVED but commits pushed after review

```bash
# Check if review is stale
last_review=$(gh api repos/{owner}/{repo}/pulls/$PR/reviews --jq '.[-1].submitted_at')
last_commit=$(gh api repos/{owner}/{repo}/pulls/$PR/commits --jq '.[-1].commit.committer.date')

# Compare timestamps
# If last_commit > last_review, review may be stale
```

**Action:** Request fresh review from original reviewer.

### 2. Multiple Reviewers

**Condition:** Multiple reviewers (human + bot)

```bash
# Get all review states
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq 'group_by(.user.login) | map({user: .[0].user.login, type: .[0].user.type, state: .[-1].state})'
```

**Action:**
- All required reviewers must approve
- Address each reviewer's comments separately
- Track approval vs changes requested per reviewer

### 3. Required Status Checks

**Condition:** Branch protection requires specific checks

```bash
# Get required checks
gh api repos/{owner}/{repo}/branches/main/protection/required_status_checks \
  --jq '.contexts[]'
```

**Action:** Wait for all required checks, do not merge early.

### 4. Draft PR

**Condition:** Draft state

```bash
gh pr view $PR --json isDraft --jq '.isDraft'
```

**Action:** Skip in queue, report as "DRAFT - skipping".

### 5. Merge Queue

**Condition:** Repository uses GitHub merge queue

```bash
# Check if in merge queue
gh pr view $PR --json mergeStateStatus --jq '.mergeStateStatus'
# Returns "QUEUED" if in merge queue
```

**Action:** Use `gh pr merge --auto` instead of direct merge.

### 6. CI Flaky Tests

**Condition:** CI fails intermittently on same code.

**Detection:**

```bash
# Check if same commit has passed before
gh run list --commit $(git rev-parse HEAD) --json conclusion --jq '.[].conclusion'
```

**Action:**
1. Re-run failed workflow: `gh run rerun $RUN_ID --failed`
2. If fails 2x on same commit, treat as real failure
3. Max 2 re-runs for flaky tests.

### 7. Rate Limiting

**Condition:** GitHub API rate limit approached

```bash
remaining=$(gh api rate_limit --jq '.rate.remaining')
if [ "$remaining" -lt 100 ]; then
    reset=$(gh api rate_limit --jq '.rate.reset')
    sleep_time=$((reset - $(date +%s)))
    echo "Rate limited. Waiting ${sleep_time}s"
    sleep $sleep_time
fi
```

### 8. Large PR Queue

**Condition:** Many PRs (>5).

**Action:**
1. Sort: APPROVED first, then oldest first
2. Process in batches of 3
3. Report progress after each batch.

```bash
# Sort PRs by review state and creation date
gh pr list --state open --json number,reviewDecision,createdAt \
  --jq 'sort_by(.reviewDecision == "APPROVED" | not) | sort_by(.createdAt) | .[].number'
```

### 9. Auto-merge Enabled

**Condition:** PR has auto-merge already enabled

```bash
gh pr view $PR --json autoMergeRequest --jq '.autoMergeRequest'
```

**Action:** Skip merge, monitor and report status.

### 10. Required Approvals Not Met

**Condition:** Branch requires N approvals, has fewer

```bash
# Get required approvals
gh api repos/{owner}/{repo}/branches/main/protection/required_pull_request_reviews \
  --jq '.required_approving_review_count'

# Get current approvals
gh api repos/{owner}/{repo}/pulls/$PR/reviews \
  --jq '[.[] | select(.state == "APPROVED")] | length'
```

**Action:** Report missing approvals, wait for reviewers.

## Retry Logic

```yaml
Max retries: 3
Backoff: Exponential (30s, 60s, 120s)
Max fix cycles: 5

Retry conditions:
  - API timeout
  - Rate limit hit
  - Unknown merge state
  - CI still running

No retry:
  - Merge conflict
  - Review rejected
  - Branch protection block
  - Authentication failure
```

## Abort Conditions

Stop immediately if:

1. **Merge conflict** - Requires human resolution
2. **Auth failure** - Token expired/invalid
3. **Repo not found** - Wrong remote or permissions
4. **Branch deleted** - PR source branch removed
5. **User cancellation** - Manual interrupt
6. **Max fix cycles** - 5 attempts exhausted

## Status Codes

| Code | Meaning | Action |
|------|---------|--------|
| `MERGED` | PR successfully merged | Report success |
| `WAITING_CI` | CI checks running | Wait and retry |
| `WAITING_REVIEW` | Pending review | No action needed |
| `NEEDS_FIX` | Comments or CI to address | Fix and push |
| `NEEDS_REREVIEW` | Fixed, needs re-review | Request review |
| `BLOCKED` | Protection rules | Report blocker |
| `CONFLICT` | Merge conflict | Stop, report |
| `SKIPPED` | Draft or closed | Report skip |
| `MAX_CYCLES` | Fix limit reached | Stop, escalate |

## Queue Processing Algorithm

```bash
#!/bin/bash
# process_pr_queue.sh

MAX_FIX_CYCLES=5
BATCH_SIZE=3
processed=0

# Get sorted PRs (approved first, then oldest)
prs=$(gh pr list --state open --json number,reviewDecision,createdAt,isDraft \
  --jq '[.[] | select(.isDraft == false)] | sort_by(.reviewDecision == "APPROVED" | not) | sort_by(.createdAt) | .[].number')

for pr in $prs; do
    echo "=== Processing PR #$pr ==="

    # Get status
    status=$(gh pr view $pr --json reviewDecision,mergeStateStatus,mergeable)

    review=$(echo "$status" | jq -r '.reviewDecision // "PENDING"')
    merge=$(echo "$status" | jq -r '.mergeStateStatus')
    mergeable=$(echo "$status" | jq -r '.mergeable')

    # Decision tree
    case "$merge" in
        "DIRTY")
            echo "  CONFLICT - requires manual resolution"
            continue
            ;;
        "BLOCKED")
            echo "  BLOCKED - waiting for protection rules"
            continue
            ;;
    esac

    case "$review" in
        "APPROVED")
            if [ "$merge" = "CLEAN" ]; then
                gh pr merge $pr --squash --delete-branch
                echo "  MERGED"
            else
                echo "  WAITING - merge state: $merge"
            fi
            ;;
        "CHANGES_REQUESTED")
            echo "  NEEDS_FIX - changes requested"
            ;;
        *)
            echo "  WAITING_REVIEW - review: $review"
            ;;
    esac

    ((processed++))
    if [ $((processed % BATCH_SIZE)) -eq 0 ]; then
        echo "--- Batch complete, pausing ---"
        sleep 5
    fi
done

echo "=== Queue processing complete ==="
gh pr list --state open --json number,title,reviewDecision
```
