---
name: speckit-retro
description: |
  Retroactively update specs with learnings from implementation bug fixes and discoveries.

  Use this skill when:
  - Implementation is complete and you want to capture learnings
  - You've fixed bugs that weren't anticipated in the spec
  - You discovered edge cases, timing issues, or environment quirks
  - You want to improve spec quality for similar future features

  Examples:
  - "run speckit-retro on 010-ephemeral-pool"
  - "update spec with implementation learnings"
  - "what did we learn during implementation?"
  - "retroactively improve this spec"
---

# Speckit Retro: Capture Implementation Learnings

You are an expert at analyzing implementation history to extract learnings that should be captured in feature specifications. This skill bridges the gap between what was planned and what was discovered during implementation.

## Purpose

After implementation, bugs are fixed, edge cases are discovered, and assumptions are corrected. These learnings should flow back into the spec so future similar features benefit from this knowledge.

## Workflow

### 1. LOCATE Resources

Find the spec directory, all markdown files, and implementation repository:

```bash
# Find spec directory
SPEC_DIR="specs/$SPEC_ID"
ls $SPEC_DIR/spec.md 2>/dev/null || ls spec.md 2>/dev/null

# Discover ALL markdown files in spec directory
ls $SPEC_DIR/*.md

# Auto-detect implementation repo in submodules
ls submodules/*/go.mod 2>/dev/null || ls submodules/*/.git 2>/dev/null

# List all specs for cross-spec analysis
ls specs/*/spec.md
```

**Required inputs:**
- Spec directory (current dir or specified)
- Implementation repo path (auto-detect from `submodules/` or specified)

**Discovered files:**
- Primary: `spec.md` (main specification)
- Supporting: `quick-reference.md`, `decision-tree.md`, etc.
- Related specs: Other `specs/*/spec.md` for cross-spec propagation

If not found, ask the user to specify paths.

### 2. GATHER Implementation History

Collect commits and PRs from the implementation repo:

```bash
# Get all commits (not filtered by tag)
cd $IMPL_REPO
git log --oneline -50

# Get merged PRs related to the feature
gh pr list --state merged --limit 20 --json number,title,body,url

# For relevant PRs, get details
gh pr view $PR_NUMBER --json body,comments,reviews
```

**Filter by feature:**
- Branch name contains spec number (e.g., `010-ephemeral`)
- Commit/PR message references spec (e.g., "Spec 010", "(#010)")
- Keywords match spec title

### 3. ANALYZE for Learnings

Use semantic analysis to identify learnings in commit messages and PR discussions.

**Signals indicating a learning:**

| Signal Type | Example Phrases |
|-------------|-----------------|
| Unexpected behavior | "turns out", "actually", "discovered" |
| Timing discovery | "had to increase timeout", "takes longer than" |
| Environment quirk | "only works when", "needs to be configured" |
| Missing edge case | "what happens when", "didn't handle" |
| Workaround | "need to run sequentially", "can't do X because" |
| Assumption correction | "API returns X not Y", "default is actually" |

**NOT learnings:**
- Routine implementation details
- Refactoring for code quality
- Test additions without new discoveries
- Documentation updates

### 4. CATEGORIZE by File and Section

Map each learning to the appropriate file and section:

| Learning Type | Target File | Target Section | Format |
|---------------|-------------|----------------|--------|
| Edge case discovered | spec.md | Edge Cases | Q&A format |
| Timing/timeout issue | spec.md | Testability Requirements | Table row |
| Race condition | spec.md | State Machine | Failure mode row |
| Environment requirement | spec.md | Testability Requirements | Env var table row |
| API behavior | spec.md | Assumptions | Bullet point |
| Cleanup/lifecycle | spec.md | State Machine | Failure mode + recovery |
| Command pattern | quick-reference.md | Commands | Code block |
| Decision rationale | decision-tree.md | Decisions | Decision entry |
| Troubleshooting tip | quick-reference.md | Troubleshooting | Bullet point |

**File selection rules:**
- Core behavior/contract → `spec.md`
- Quick lookup/cheatsheet → `quick-reference.md`
- Why decisions were made → `decision-tree.md`
- How to debug/fix → `quick-reference.md`

### 5. GENERATE Updates

For each learning, generate the spec update:

**Edge Cases (Q&A format):**
```markdown
- **What happens when X?** Y happens. (Learned from: commit abc123 / PR #42)
```

**State Machine (failure modes table):**
```markdown
| Transition | Can Fail? | Recovery |
|------------|-----------|----------|
| New failure mode | Yes | Recovery action (PR #42) |
```

**Testability Requirements (env var table):**
```markdown
| Variable | Purpose | Default |
|----------|---------|---------|
| `NEW_VAR` | Discovered need during impl | value |
```

**Assumptions:**
```markdown
- **Timing**: Operation X takes 30s, not 10s as originally assumed (commit abc123)
```

### 6. PREVIEW Changes

Before editing, show the user what will be changed, grouped by file:

```markdown
## Proposed Updates

### spec.md (4 changes)

**Edge Cases (+2)**
1. + What happens when container stops before cleanup? ...
2. + What happens when rate limit is exceeded during burst? ...

**State Machine (+1)**
| Transition | Can Fail? | Recovery |
|------------|-----------|----------|
| + token_refresh | Yes | Retry with backoff (PR #415) |

**Assumptions (+1)**
- + TokenRequestTimeout needs 30s, not 10s (commit c2f62d2)

### quick-reference.md (1 change)

**Troubleshooting (+1)**
- + If token refresh fails, check network timeout settings (PR #415)

Proceed with updates? [Y/n]
```

### 7. UPDATE Files

Apply changes to all affected files and add changelog entry to `spec.md`:

```markdown
## Changelog

### Retroactive Learnings (YYYY-MM-DD)

Analysis of implementation commits and PRs revealed:

| Source | Learning | File | Section |
|--------|----------|------|---------|
| PR #42 | Podman tests race when parallel | spec.md | Edge Cases |
| commit abc123 | Token timeout needs 30s | spec.md | Assumptions |
| PR #415 | Token refresh troubleshooting | quick-reference.md | Troubleshooting |
```

### 8. CROSS-SPEC Propagation

After updating the primary spec, check if learnings apply to other specs:

**Signals for cross-spec relevance:**
- Shared infrastructure (e.g., "GitHub API rate limit" affects all specs using GH API)
- Common patterns (e.g., "timeout handling" applies to all async operations)
- Platform constraints (e.g., "Podman limitation" affects all container specs)

**Process:**
```bash
# List all specs
ls specs/*/spec.md

# For each learning, grep for shared components in other specs
grep -l "GitHub API" specs/*/spec.md
grep -l "container" specs/*/spec.md
```

**Cross-spec preview (separate confirmation):**
```markdown
## Cross-Spec Propagation

The following learnings may apply to other specs:

### Learning: "GitHub API needs 30s timeout"
Applies to:
- specs/005-runner-base/spec.md (uses GitHub API)
- specs/015-webhook-handler/spec.md (uses GitHub API)

Propagate to these specs? [Y/n]
```

**Rules for cross-spec updates:**
1. Always show as separate preview from primary updates
2. Require explicit user confirmation
3. Add cross-reference in changelog: "Propagated from spec 010"
4. Only propagate to specs that share the affected component

## Output Format

After completion, report:

```
============================================
SPECKIT-RETRO COMPLETE
============================================

Spec: specs/010-ephemeral-pool/
Impl: submodules/gh-runner

Analyzed:
  - 23 commits
  - 8 merged PRs

Learnings found: 6

Primary spec updates:
  spec.md:
    - Edge Cases: +3
    - State Machine: +1
    - Assumptions: +1
  quick-reference.md:
    - Troubleshooting: +1

Cross-spec propagation:
  specs/005-runner-base/spec.md:
    - Assumptions: +1 (shared: GH API timeout)

Changelog entries added.
============================================
```

## Rules

1. **Semantic analysis** - Don't just grep for `fix:` tags. Read and understand context.
2. **Prove before adding** - Only add learnings that are verified by the implementation.
3. **Cite sources** - Always reference the commit or PR where the learning came from.
4. **Preview first** - Show proposed changes before editing.
5. **Preserve existing content** - Add to sections, don't replace unless correcting errors.
6. **One spec at a time** - Focus on thorough analysis of a single spec.

## Quick Reference

See `quick-reference.md` for signal patterns and section formats.
