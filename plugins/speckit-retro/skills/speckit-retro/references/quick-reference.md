# Speckit Retro Quick Reference

## Learning Signal Patterns

### Phrases Indicating Learnings

```
turns out          -> Behaved differently than expected
actually           -> Assumption correction
discovered         -> New finding
had to             -> Workaround discovered
needed to          -> Missing requirement
can't / cannot     -> Limitation found
only works when    -> Environment/config requirement
takes longer       -> Timing assumption wrong
race condition     -> Concurrency issue
timeout            -> Timing discovery
cleanup            -> Lifecycle issue
```

### NOT Learnings (Skip)

```
refactor           -> Code quality
cleanup code       -> Internal improvement
add tests          -> Unless reveals edge case
update docs        -> Unless corrects spec
rename             -> Internal naming
style / format     -> Code style
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
| `GH_RUNNER_TOKEN_TIMEOUT` | Token request timeout | `30s` |
| `GH_RUNNER_SEQUENTIAL_TESTS` | Force sequential tests | `false` |
```

### Assumptions (Bullets)

```markdown
## Assumptions

- **Token Request Timing**: Token requests need 30s timeout, not 10s.
  Network latency on cold starts can exceed 10s. (commit c2f62d2)

- **Podman Parallelism**: Podman tests cannot run parallel due to shared
  machine state. Execute sequentially. (PR #417)
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
Timing/delays?          -> Testability Requirements + Assumptions
Something failing?      -> State Machine (failure modes)
Unexpected behavior?    -> Edge Cases (Q&A)
Environment/config?     -> Testability Requirements
Correcting assumption?  -> Assumptions section
```

## File Selection Guide

```
Core behavior/contract?    -> spec.md
Quick command/snippet?     -> quick-reference.md
WHY decision was made?     -> decision-tree.md
Debug/troubleshoot?        -> quick-reference.md
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

When a learning applies to multiple specs:

```
Shared infrastructure:
  "GitHub API"     -> Specs using GH API
  "rate limit"     -> Specs with external calls
  "authentication" -> Specs using auth tokens

Platform constraints:
  "Podman/Docker"  -> Container specs
  "systemd"        -> Service specs

Common patterns:
  "timeout"        -> Async operation specs
  "retry"          -> Network operation specs
  "cleanup"        -> Resource lifecycle specs
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
