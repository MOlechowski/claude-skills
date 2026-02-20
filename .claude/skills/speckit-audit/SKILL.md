---
name: speckit-audit
description: "Find unspecced work and fix spec drift. Use when: (1) auditing spec coverage, (2) finding features implemented without specs, (3) creating retroactive specs, (4) identifying technical debt from unspecced changes, (5) detecting and fixing spec drift. Triggers: run speckit-audit, find unspecced work, what PRs don't have specs, audit spec coverage, fix spec drift."
---

# Speckit Audit: Find Unspecced Work and Fix Drift

Audit implementation repos for work without specs and drift between specs and implementation. Identifies gaps, fixes drift, and offers retroactive specs.

## Purpose

In spec-driven development, all significant work needs a spec, and specs must stay in sync with implementation. This skill:
1. Scans repos for PRs and commits
2. Compares against existing specs
3. Reports gaps (work without specs)
4. Auto-fixes drift in matched specs
5. Offers spec creation via `/speckit-flow`

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

**Extract from each PR/git-commit:**
- Title/description
- Branch name
- Files changed (scope assessment)
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

| Spec | Short Name | Keywords |
|------|------------|----------|
| 001 | hybrid-runner | tart, podman, vm, container |
| 010 | ephemeral-pool | pool, replenish, ephemeral |

### 3. MATCH Implementation to Specs

For each implementation item, check if spec exists:

**Matching criteria (by strength):**

1. **Explicit reference** - PR/git-commit mentions spec number ("Spec 010", "(#010)")
2. **Branch name match** - `010-ephemeral-pool` matches spec `010-*`
3. **Keyword overlap** - PR about "pool replenishment" matches related spec

**Classification:**
- **Specced**: Clear match
- **Unspecced**: No match (GAP)
- **Uncertain**: Weak match, needs review

### 4. VERIFY Matched Specs (Drift Detection)

For each "Specced" match, check if spec is accurate:

```bash
# Discover all spec files
SPEC_DIR="specs/$SPEC_ID"
ls $SPEC_DIR/*.md

# Common files: spec.md, quick-reference.md, plan.md, tasks.md
```

**Extract claims from spec files:**
- `spec.md`: Core requirements, config, behavior
- `quick-reference.md`: Commands, flags, patterns
- `plan.md`: Implementation approach
- `tasks.md`: Task status

**Drift detection (Tier 1 + Tier 2):**

| Tier | Check Type | Method |
|------|------------|--------|
| T1 | Config values | `grep -E "[0-9]+(s\|ms\|m\|h)" spec.md` |
| T1 | Env vars | `grep -E '\$[A-Z_]+' spec.md` |
| T1 | Constants | `grep -E "MAX\|LIMIT\|DEFAULT" spec.md` |
| T2 | Features | `grep -i "support\|implement" spec.md` |
| T2 | Commands | `grep -E '^\s*\$\|```bash' quick-reference.md` |

**Compare spec vs implementation:**

```bash
cd $IMPL_REPO
grep -rn "timeout\|Timeout" src/        # Config values
grep -rn "os.Getenv\|process.env" src/  # Env vars
grep -rn "$FEATURE_KEYWORD" src/        # Features
```

**Drift classification:**
- **SYNCED**: Spec matches impl
- **DRIFTED**: Spec differs (auto-fix)
- **UNKNOWN**: Cannot verify (skip)

**Track per file:**

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

For each DRIFTED spec, update affected files:

```bash
SPEC_DIR="specs/$SPEC_ID"
ls $SPEC_DIR/*.md
```

**Update files:**

| File | What to Update |
|------|----------------|
| `spec.md` | Config, env vars, constants, behavior |
| `quick-reference.md` | Commands, flags, troubleshooting |
| `plan.md` | Implementation approach |
| `tasks.md` | Mark completed, add discovered tasks |

**Add changelog to spec.md:**

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
**PR Body**: Tests were failing because Podman machine state wasn't checked.
**Files Changed**: 3 files

**Generated Description**:
```
Feature: Podman Machine State Management
Check Podman machine state before starting containers.
Handle: not running, starting, already running.
```

Create spec with /speckit-flow? [Y/n]
```

### 8. INVOKE speckit-flow

When approved, invoke `/speckit-flow` to create full spec package.

**Retroactive spec handling:**
- Note that spec documents existing functionality
- Tasks reflect completed work
- Reference original implementation PRs

## Filtering

See `references/quick-reference.md` for rules and templates.

## Rules

1. **Be conservative** - Flag only significant work
2. **Skip infrastructure** - CI/CD, tooling rarely need specs
3. **User decides** - Present findings, let user choose
4. **Full pipeline** - Use `/speckit-flow` for complete packages
5. **Mark retroactive** - Note specs document existing work
6. **Auto-fix drift** - Update spec files when drift detected
7. **Update all files** - Fix drift in spec.md, quick-reference.md, plan.md, tasks.md

## Integration

- **speckit-flow**: Full spec packages
- **speckit-verify**: Drift detection (Tier 1 + Tier 2)
- **speckit-retro**: Deeper behavioral learnings

See `references/quick-reference.md` for matching patterns and rules.
