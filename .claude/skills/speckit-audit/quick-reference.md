# Speckit Audit Quick Reference

## Matching Patterns

### Explicit Spec References

```regex
Spec\s*#?\d{3}        # "Spec 010", "Spec #010"
\(#\d{3}\)            # "(#010)"
\d{3}-\w+-\w+         # "010-ephemeral-pool" (branch pattern)
spec-\d{3}            # "spec-010"
```

### Branch Name Patterns

```
010-ephemeral-pool     → matches spec 010-ephemeral-pool
feat/010-feature       → matches spec 010-*
feature/pool-mgmt      → keyword match to pool-related spec
```

## Filtering Rules

### Skip (Not Spec-Worthy)

| Commit Prefix | Reason |
|---------------|--------|
| `fix(ci):` | CI infrastructure |
| `fix(e2e):` small | Test infrastructure |
| `chore:` | Maintenance |
| `docs:` | Documentation only |
| `style:` | Formatting |
| `build:` | Build system |
| `deps:` | Dependency updates |

### Flag (Likely Need Spec)

| Commit Prefix | Reason |
|---------------|--------|
| `feat:` | New functionality |
| `feat!:` | Breaking change |
| Large `fix:` | Significant behavior change |
| `perf:` | Performance (if user-facing) |

### Scope Assessment

| Files Changed | Scope | Spec Needed? |
|---------------|-------|--------------|
| 1-2 files | Small | Probably not |
| 3-5 files | Medium | Maybe |
| 6+ files | Large | Likely yes |
| New package/module | Large | Yes |

## Command Cheatsheet

```bash
# Get merged PRs with details
gh pr list --state merged --limit 50 \
  --json number,title,body,mergedAt,headRefName

# Get PR files changed
gh pr view 123 --json files

# Get commit scope
git show --stat abc123

# List specs
ls -d specs/*/

# Get spec titles
for d in specs/*/; do
  echo "$d: $(head -1 $d/spec.md)"
done

# Find PRs referencing spec number
gh pr list --state merged --search "Spec 010"
```

## Coverage Report Template

```markdown
## Speckit Audit Report

**Repository**: {repo_path}
**Date**: {date}

### Summary

| Category | Count | Percentage |
|----------|-------|------------|
| Specced | {n} | {%} |
| Unspecced | {n} | {%} |
| Uncertain | {n} | {%} |
| **Total** | {n} | 100% |

### Gaps (Unspecced Work)

| PR | Title | Scope | Recommendation |
|----|-------|-------|----------------|
| #123 | Title | Medium | Create spec |
| #456 | Title | Small | Skip |

### Actions

- [ ] Review uncertain matches
- [ ] Create specs for gaps
- [ ] Run speckit-retro on existing specs
```

## Generated Description Template

When creating specs for unspecced work:

```markdown
Feature: {Title from PR}

{Summary from PR body}

Context:
- Originally implemented in PR #{number}
- Merged on {date}
- Files affected: {file_list}

This is a retroactive specification documenting existing functionality.
```

## Decision Tree

```
Is this a feat: commit/PR?
  YES → Flag as potential spec needed
  NO  ↓

Is this a large fix: (3+ files)?
  YES → Flag as potential spec needed
  NO  ↓

Does it add new functionality?
  YES → Flag as potential spec needed
  NO  ↓

Is it CI/CD/infra related?
  YES → Skip (not spec-worthy)
  NO  ↓

Is it a refactor with no behavior change?
  YES → Skip (not spec-worthy)
  NO  → Review manually
```

## Integration Commands

```bash
# After audit, update existing specs with learnings
/speckit-retro specs/010-ephemeral-pool

# Create full spec for unspecced work
/speckit-flow "Feature description extracted from PR"

# Check spec quality
/speckit.analyze
```
