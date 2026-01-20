---
name: speckit-audit
description: "Find unspecced work and fix spec drift. Use when: (1) auditing spec coverage, (2) finding features implemented without specs, (3) creating retroactive specs, (4) identifying technical debt from unspecced changes, (5) detecting and fixing spec drift. Triggers: run speckit-audit, find unspecced work, what PRs don't have specs, audit spec coverage, fix spec drift."
---

# Speckit Audit: Find Unspecced Work and Fix Drift

Audit implementation repos to find work without specs and detect drift between specs and implementation. Identifies gaps, fixes drift, and offers to create retroactive specs.

## Purpose

In spec-driven development, all significant work should have a spec, and specs should stay in sync with implementation. This skill:
1. Scans implementation repos for PRs and significant commits
2. Compares against existing specs
3. Reports gaps (work without specs)
4. Detects and auto-fixes drift in matched specs
5. Offers to create specs via `/speckit-flow`

## Workflow

### 1. SCAN Implementation Repo

Find the implementation repository and gather work items:

```bash
# Auto-detect impl repo in submodules
IMPL_REPO=$(ls -d submodules/*/ 2>/dev/null | head -1)

# Or use current directory if it's an impl repo
[ -f "go.mod" ] || [ -f "package.json" ] && IMPL_REPO="."

cd $IMPL_REPO

# Get merged PRs (significant work)
gh pr list --state merged --limit 50 --json number,title,body,mergedAt,headRefName

# Get feature commits not from PRs
git log --oneline --no-merges -50
```

**Extract from each PR/commit:**
- Title/description
- Branch name
- Files changed (for scope assessment)
- Keywords for matching

### 2. SCAN Specs Directory

Build inventory of existing specs:

```bash
# List all specs
ls -d specs/*/ 2>/dev/null

# For each spec, extract:
# - Spec number (e.g., 001, 010)
# - Short name (e.g., hybrid-runner, ephemeral-pool)
# - Title from spec.md
# - Keywords from content
```

**Build spec inventory:**

| Spec | Short Name | Title | Keywords |
|------|------------|-------|----------|
| 001 | hybrid-runner | Hybrid Runner | tart, podman, vm, container |
| 010 | ephemeral-pool | Pool Replenishment | pool, replenish, ephemeral |

### 3. MATCH Implementation to Specs

For each implementation item, check if a spec exists:

**Matching criteria (in order of strength):**

1. **Explicit reference** - PR/commit mentions spec number
   - "Spec 010", "(#010)", "010-ephemeral"

2. **Branch name match** - Branch follows spec pattern
   - `010-ephemeral-pool` matches spec `010-ephemeral-pool`

3. **Keyword overlap** - Significant keyword match with spec
   - PR about "pool replenishment" matches spec with those keywords

**Classification:**
- **Specced**: Clear match to existing spec
- **Unspecced**: No match found (GAP)
- **Uncertain**: Weak match, needs review

### 4. VERIFY Matched Specs (Drift Detection)

For each "Specced" match, check if the spec is still accurate:

```bash
# Discover all spec files
SPEC_DIR="specs/$SPEC_ID"
ls $SPEC_DIR/*.md

# Common files: spec.md, quick-reference.md, plan.md, tasks.md
```

**Extract claims from ALL spec files:**
- `spec.md`: Core requirements, config values, behavior
- `quick-reference.md`: Commands, flags, patterns
- `plan.md`: Implementation approach
- `tasks.md`: Task completion status

**Lightweight drift detection (Tier 1 + Tier 2 only):**

| Tier | Check Type | Method |
|------|------------|--------|
| T1 | Config values | `grep -E "[0-9]+(s\|ms\|m\|h)" spec.md` |
| T1 | Env vars | `grep -E '\$[A-Z_]+' spec.md` |
| T1 | Constants | `grep -E "MAX\|LIMIT\|DEFAULT" spec.md` |
| T2 | Features | `grep -i "support\|implement" spec.md` |
| T2 | Commands | `grep -E '^\s*\$\|```bash' quick-reference.md` |

**Compare spec claims against implementation:**

```bash
# For each claim, verify in implementation
cd $IMPL_REPO

# Check config values
grep -rn "timeout\|Timeout" src/

# Check env vars
grep -rn "os.Getenv\|process.env" src/

# Check feature presence
grep -rn "$FEATURE_KEYWORD" src/
```

**Drift classification:**
- **SYNCED**: Spec matches implementation
- **DRIFTED**: Spec differs from implementation (auto-fix)
- **UNKNOWN**: Cannot verify (skip)

**Track drift per file:**

| Spec | File | Claim | Spec Value | Impl Value | Status |
|------|------|-------|------------|------------|--------|
| 010 | spec.md | Timeout | 10s | 30s | DRIFTED |
| 010 | quick-reference.md | --verbose flag | Yes | Yes | SYNCED |
| 010 | tasks.md | Task 3 | pending | done | DRIFTED |

### 5. REPORT Gaps + Drift

Present findings to user:

```markdown
## Speckit Audit Report

### Summary
- Total PRs analyzed: 50
- Specced: 42 (84%)
  - Synced: 38
  - Drifted: 4 (auto-fixed)
- Unspecced: 6 (12%)
- Uncertain: 2 (4%)

### Drifted Specs (Auto-Fixed)

| Spec | File | Change | Source PR |
|------|------|--------|-----------|
| 010-ephemeral-pool | spec.md | Timeout: 10s -> 30s | PR #421 |
| 010-ephemeral-pool | quick-reference.md | Added --force flag | PR #421 |
| 014-runner-cache | spec.md | MAX_CACHE_SIZE: 1GB -> 5GB | PR #418 |
| 014-runner-cache | tasks.md | Task 3: pending -> done | PR #418 |

### Unspecced Work (Gaps)

| # | PR/Commit | Title | Scope | Action |
|---|-----------|-------|-------|--------|
| 1 | PR #415 | fix(e2e): properly check Podman machine state | Medium | Create spec? |
| 2 | PR #413 | fix(ci): install Podman on macOS runners | Small | Skip (infra) |
| 3 | commit abc123 | Add retry logic to deregistration | Medium | Create spec? |
| 4 | PR #401 | Complete mock migration for tests | Large | Create spec? |

### Uncertain Matches (Review Needed)

| PR | Title | Possible Spec | Confidence |
|----|-------|---------------|------------|
| PR #410 | Migrate E2E tests to self-hosted | 011-ci-migration? | 60% |

### Specced Work (Synced)

| PR | Title | Matched Spec | Status |
|----|-------|--------------|--------|
| PR #421 | Runner binary cache | 014-runner-binary-cache | Synced |
| PR #422 | Tart Linux VMs | 015-tart-linux-runners | Synced |
```

### 6. UPDATE Drifted Specs (Auto-Fix)

For each DRIFTED spec, automatically update all affected files:

```bash
# Discover all spec files
SPEC_DIR="specs/$SPEC_ID"
SPEC_FILES=$(ls $SPEC_DIR/*.md)

# Common files and what to update:
# - spec.md: Config values, env vars, constants, behavior
# - quick-reference.md: Commands, flags, patterns
# - plan.md: Implementation approach changes
# - tasks.md: Task completion status
```

**Update each affected file:**

| File | What to Update |
|------|----------------|
| `spec.md` | Config values, env vars, constants, behavior descriptions |
| `quick-reference.md` | Command patterns, flags, troubleshooting tips |
| `plan.md` | Implementation approach if significantly changed |
| `tasks.md` | Mark completed tasks, add discovered tasks |

**For each drift fix:**

```markdown
# In spec.md, update the value:
- Timeout: 10s -> 30s

# In quick-reference.md, update commands:
- Added: --force flag

# In tasks.md, mark tasks done:
- [x] Task 3: Implement timeout handling (PR #418)
```

**Add changelog entry to spec.md:**

```markdown
## Changelog

### Drift Auto-Fix (YYYY-MM-DD)

Audit detected and fixed drift from implementation:

| File | Change | Source |
|------|--------|--------|
| spec.md | Timeout: 10s -> 30s | PR #418 |
| quick-reference.md | Added --force flag | PR #418 |
| tasks.md | Task 3 marked complete | PR #418 |
```

### 7. OFFER Spec Creation

For each unspecced item the user wants to spec:

```markdown
## Create Spec for PR #415?

**PR Title**: fix(e2e): properly check Podman machine state
**PR Body**:
> Tests were failing because we didn't properly check if Podman machine
> was running before starting containers. Added state checks for:
> not running, starting, already running.

**Files Changed**: 3 files (e2e tests, podman runtime)

**Generated Feature Description**:
```
Feature: Podman Machine State Management

The system needs to properly check Podman machine state before starting
containers. Handle states: not running, starting, already running.
Prevent test failures from unexpected machine states.
```

Create full spec with /speckit-flow? [Y/n]
```

### 8. INVOKE speckit-flow

When user approves, invoke the full spec creation pipeline:

```bash
# speckit-flow will handle:
# 1. CREATE: spec.md + plan.md + research.md
# 2. CLARIFY: resolve ambiguities
# 3. ANALYZE: validate consistency
# 4. TASKS: generate tasks.md (mark existing work as done)
# 5. CHECKLIST: quality checklists
# 6. PR: create PR for spec artifacts
```

**Special handling for retroactive specs:**
- Note in spec that this is retroactive documentation
- Tasks should reflect already-completed work
- Reference the original implementation PRs

## Filtering Rules

See `references/quick-reference.md` for filtering rules and output format templates.

## Rules

1. **Be conservative** - Only flag genuinely significant work as needing specs
2. **Skip infrastructure** - CI/CD, tooling, and infra changes rarely need specs
3. **User decides** - Present findings, let user choose what to spec
4. **Full pipeline** - Use `/speckit-flow` for complete spec packages
5. **Mark as retroactive** - Note that specs are documenting existing work
6. **Auto-fix drift** - Update all spec files immediately when drift is detected
7. **Update all files** - Check and fix drift in spec.md, quick-reference.md, plan.md, tasks.md

## Integration

This skill integrates with:
- **speckit-flow**: For creating full spec packages
- **speckit-verify**: Drift detection logic borrowed from verify (Tier 1 + Tier 2 checks)
- **speckit-retro**: Run after audit to capture deeper behavioral learnings beyond drift fixes

## Quick Reference

See `references/quick-reference.md` for matching patterns and filtering rules.
