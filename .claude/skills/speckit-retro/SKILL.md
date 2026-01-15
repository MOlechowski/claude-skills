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

Find the spec and implementation repository:

```bash
# Check current directory for spec.md
ls specs/*/spec.md 2>/dev/null || ls spec.md 2>/dev/null

# Auto-detect implementation repo in submodules
ls submodules/*/go.mod 2>/dev/null || ls submodules/*/.git 2>/dev/null
```

**Required inputs:**
- Spec directory (current dir or specified)
- Implementation repo path (auto-detect from `submodules/` or specified)

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

### 4. CATEGORIZE by Spec Section

Map each learning to the appropriate spec section:

| Learning Type | Target Section | Format |
|---------------|----------------|--------|
| Edge case discovered | Edge Cases | Q&A format |
| Timing/timeout issue | Testability Requirements, Assumptions | Table row or bullet |
| Race condition | State Machine, Edge Cases | Failure mode row |
| Environment requirement | Testability Requirements | Env var table row |
| API behavior | Assumptions | Bullet point |
| Cleanup/lifecycle | State Machine | Failure mode + recovery |

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

Before editing, show the user what will be changed:

```markdown
## Proposed Spec Updates

### Edge Cases (3 additions)
1. + What happens when container stops before cleanup? ...
2. + What happens when rate limit is exceeded during burst? ...
3. + What happens when GitHub API returns 502? ...

### State Machine (1 addition)
| Transition | Can Fail? | Recovery |
|------------|-----------|----------|
| + token_refresh | Yes | Retry with backoff (PR #415) |

### Assumptions (2 updates)
- + TokenRequestTimeout needs 30s, not 10s (commit c2f62d2)
- + Podman tests cannot run in parallel (PR #417)

Proceed with updates? [Y/n]
```

### 7. UPDATE Spec

Apply the changes to spec.md and add changelog entry:

```markdown
## Changelog

### Retroactive Learnings (YYYY-MM-DD)

Analysis of implementation commits and PRs revealed:

| Source | Learning | Section Updated |
|--------|----------|-----------------|
| PR #42 | Podman tests race when parallel | Edge Cases |
| commit abc123 | Token timeout needs 30s | Assumptions |
| PR #415 | Container cleanup can fail | State Machine |
```

## Output Format

After completion, report:

```
============================================
SPECKIT-RETRO COMPLETE
============================================

Spec: specs/010-ephemeral-pool/spec.md
Impl: submodules/gh-runner

Analyzed:
  - 23 commits
  - 8 merged PRs

Learnings found: 6
  - Edge Cases: 3 additions
  - State Machine: 1 addition
  - Assumptions: 2 updates
  - Testability: 0 additions

Changelog entry added.
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
