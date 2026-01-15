---
name: speckit-audit
description: Find implementation work without specs.
---

# Speckit Audit: Find Unspecced Work

Use this skill when:
- You want to audit spec coverage across your implementation
- You suspect features were implemented without specs
- You want to retroactively create specs for undocumented work
- You need to identify technical debt from unspecced changes

Examples:
- "run speckit-audit"
- "find unspecced work"
- "what PRs don't have specs?"
- "audit spec coverage"

You are an expert at auditing implementation repositories to find work that was done without a corresponding specification. This skill helps maintain spec-driven development discipline by identifying gaps and offering to create retroactive specs.

## Purpose

In spec-driven development, all significant work should have a spec. This skill:
1. Scans implementation repos for PRs and significant commits
2. Compares against existing specs
3. Reports gaps (work without specs)
4. Offers to create specs via `/speckit-flow`

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

### 4. REPORT Gaps

Present findings to user:

```markdown
## Speckit Audit Report

### Summary
- Total PRs analyzed: 50
- Specced: 42 (84%)
- Unspecced: 6 (12%)
- Uncertain: 2 (4%)

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

### Specced Work (For Reference)

| PR | Title | Matched Spec |
|----|-------|--------------|
| PR #421 | Runner binary cache | 014-runner-binary-cache |
| PR #422 | Tart Linux VMs | 015-tart-linux-runners |
```

### 5. OFFER Spec Creation

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

### 6. INVOKE speckit-flow

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

### Skip These (Not Spec-Worthy)

| Pattern | Reason |
|---------|--------|
| `fix(ci):` | CI/CD infrastructure |
| `chore:` | Maintenance tasks |
| `docs:` | Documentation only |
| `style:` | Code formatting |
| `refactor:` small scope | Internal improvements |
| Dependency updates | External dependencies |

### Always Flag (Likely Need Spec)

| Pattern | Reason |
|---------|--------|
| `feat:` | New functionality |
| Large `fix:` | Significant behavior change |
| New files added | New capability |
| API changes | Interface changes |
| Config changes | User-facing changes |

## Output Format

```
============================================
SPECKIT-AUDIT COMPLETE
============================================

Repository: submodules/gh-runner
Specs Directory: specs/

Coverage:
  - PRs analyzed: 50
  - Specced: 42 (84%)
  - Unspecced: 6 (12%)
  - Uncertain: 2 (4%)

Actions Taken:
  - Specs created: 2 (via /speckit-flow)
  - Skipped (infra): 3
  - Pending review: 1

New Specs:
  - 016-podman-machine-state (PR #xxx)
  - 017-test-mock-architecture (PR #xxx)
============================================
```

## Rules

1. **Be conservative** - Only flag genuinely significant work as needing specs
2. **Skip infrastructure** - CI/CD, tooling, and infra changes rarely need specs
3. **User decides** - Present findings, let user choose what to spec
4. **Full pipeline** - Use `/speckit-flow` for complete spec packages
5. **Mark as retroactive** - Note that specs are documenting existing work

## Integration

This skill integrates with:
- **speckit-flow**: For creating full spec packages
- **speckit-retro**: Run after audit to update existing specs with learnings

## Quick Reference

See `quick-reference.md` for matching patterns and filtering rules.
