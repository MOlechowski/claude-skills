# Speckit Retro Quick Reference

## Learning Signal Patterns

### Phrases Indicating Learnings

```
turns out          -> Something behaved differently than expected
actually           -> Correction to an assumption
discovered         -> New finding during implementation
had to             -> Workaround or requirement discovered
needed to          -> Missing requirement found
can't / cannot     -> Limitation discovered
only works when    -> Environment or config requirement
takes longer       -> Timing assumption incorrect
race condition     -> Concurrency issue found
timeout            -> Timing-related discovery
cleanup            -> Lifecycle issue found
```

### NOT Learnings (Skip These)

```
refactor           -> Code quality, not spec issue
cleanup code       -> Internal improvement
add tests          -> Unless revealing new edge case
update docs        -> Unless correcting spec
rename             -> Internal naming
style / format     -> Code style changes
```

## Section Formats

### Edge Cases (Q&A)

```markdown
### Edge Cases

- **What happens when X?** Y happens. (Learned from: commit abc123)

- **What happens when the container stops before cleanup completes?**
  The system detects the stopped state and falls back to GitHub API
  removal. (Learned from: PR #411)
```

### State Machine (Failure Modes Table)

```markdown
## State Machine

| Transition | Can Fail? | Recovery |
|------------|-----------|----------|
| cleanup | Yes | Retry after 30s, then GitHub API fallback (PR #411) |
| token_refresh | Yes | Exponential backoff, max 5 retries (commit c2f62d2) |
```

### Testability Requirements (Env Var Table)

```markdown
## Testability Requirements

| Variable | Purpose | Default |
|----------|---------|---------|
| `GH_RUNNER_TOKEN_TIMEOUT` | Token request timeout | `30s` (was 10s) |
| `GH_RUNNER_SEQUENTIAL_TESTS` | Force sequential test execution | `false` |
```

### Assumptions (Bullets)

```markdown
## Assumptions

- **Token Request Timing**: Token requests need 30s timeout, not 10s
  as originally assumed. Network latency on cold starts can exceed 10s.
  (commit c2f62d2)

- **Podman Parallelism**: Podman container tests cannot run in parallel
  due to shared machine state. Must be executed sequentially.
  (PR #417)
```

### Changelog Entry

```markdown
## Changelog

### Retroactive Learnings (2026-01-15)

Analysis of implementation commits and PRs revealed:

| Source | Learning | Section Updated |
|--------|----------|-----------------|
| PR #411 | Container cleanup can fail silently | State Machine |
| commit c2f62d2 | Token timeout needs 30s | Assumptions |
| PR #417 | Podman tests must run sequentially | Edge Cases |
```

## Command Cheatsheet

```bash
# Get commits from impl repo
git log --oneline -50

# Get merged PRs
gh pr list --state merged --limit 20 --json number,title,body

# Get PR details with comments
gh pr view 123 --json body,comments,reviews

# Filter commits by keyword
git log --oneline --grep="timeout"

# Get commit details
git show --stat abc123
```

## Categorization Decision Tree

```
Is it about timing/delays?
  -> Testability Requirements (env var) + Assumptions

Is it about something failing?
  -> State Machine (failure modes table)

Is it about unexpected behavior?
  -> Edge Cases (Q&A format)

Is it about environment/config?
  -> Testability Requirements (env var table)

Is it correcting an original assumption?
  -> Assumptions section
```

## File Selection Guide

```
Which file should receive the learning?

Is it core behavior or contract?
  -> spec.md

Is it a quick command or snippet?
  -> quick-reference.md

Is it explaining WHY a decision was made?
  -> decision-tree.md

Is it how to debug or troubleshoot?
  -> quick-reference.md
```

| Learning Type | Target File | Target Section |
|---------------|-------------|----------------|
| Edge case | spec.md | Edge Cases |
| Timing issue | spec.md | Testability Requirements |
| Race condition | spec.md | State Machine |
| Command pattern | quick-reference.md | Commands |
| Troubleshooting | quick-reference.md | Troubleshooting |
| Decision rationale | decision-tree.md | Decisions |

## Cross-Spec Propagation Signals

When a learning might apply to multiple specs:

```
Shared infrastructure signals:
  "GitHub API"     -> All specs using GH API
  "rate limit"     -> All specs making external calls
  "authentication" -> All specs using auth tokens

Platform constraint signals:
  "Podman"         -> All container specs
  "Docker"         -> All container specs
  "systemd"        -> All service specs

Common pattern signals:
  "timeout"        -> All async operation specs
  "retry"          -> All network operation specs
  "cleanup"        -> All resource lifecycle specs
```

### Cross-Spec Commands

```bash
# Find specs sharing a component
grep -l "GitHub API" specs/*/spec.md

# Find all container-related specs
grep -l "container\|podman\|docker" specs/*/spec.md

# Find specs with similar patterns
grep -l "timeout" specs/*/spec.md
```
