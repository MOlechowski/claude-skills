# Speckit Audit Quick Reference

## Matching Patterns

### Explicit References

```regex
Spec\s*#?\d{3}        # "Spec 010"
\(#\d{3}\)            # "(#010)"
\d{3}-\w+-\w+         # "010-ephemeral-pool"
spec-\d{3}            # "spec-010"
```

### Branch Patterns

```
010-ephemeral-pool     -> spec 010-ephemeral-pool
feat/010-feature       -> spec 010-*
feature/pool-mgmt      -> keyword match
```

## Filtering

### Skip

| Prefix | Reason |
|--------|--------|
| `fix(ci):` | CI infrastructure |
| `chore:` | Maintenance |
| `docs:` | Documentation |
| `style:` | Formatting |
| `build:` | Build system |
| `deps:` | Dependencies |

### Flag (Needs Spec)

| Prefix | Reason |
|--------|--------|
| `feat:` | New functionality |
| `feat!:` | Breaking change |
| Large `fix:` | Significant behavior |

### Scope

| Files | Spec? |
|-------|-------|
| 1-2 | Probably no |
| 3-5 | Maybe |
| 6+ | Likely yes |
| New module | Yes |

## Commands

```bash
# Merged PRs
gh pr list --state merged --limit 50 --json number,title,body,mergedAt,headRefName

# PR files
gh pr view 123 --json files

# Commit scope
git show --stat abc123

# List specs
ls -d specs/*/

# Find PRs by spec
gh pr list --state merged --search "Spec 010"
```

## Drift Detection

### Spec Files

```bash
ls specs/$SPEC_ID/*.md
# spec.md, quick-reference.md, plan.md, tasks.md
```

### Detection Patterns

```bash
# T1: Config values
grep -E "[0-9]+(s|ms|m|h|KB|MB|GB)" specs/$SPEC_ID/*.md

# T1: Env vars
grep -E '\$[A-Z_]+|`[A-Z_]+`' specs/$SPEC_ID/*.md

# T1: Constants
grep -E "MAX|LIMIT|DEFAULT|TIMEOUT" specs/$SPEC_ID/*.md

# T2: Commands
grep -E '^\s*\$|```bash' specs/$SPEC_ID/quick-reference.md
```

### Verify vs Implementation

```bash
cd $IMPL_REPO
grep -rn "timeout|Timeout" src/
grep -rn "os.Getenv|process.env" src/
```

### Classification

| Status | Action |
|--------|--------|
| SYNCED | None |
| DRIFTED | Auto-fix |
| UNKNOWN | Skip |

## Output Format

```
SPECKIT-AUDIT COMPLETE

Coverage:
  PRs: 50 | Specced: 42 (84%) | Unspecced: 6 | Uncertain: 2

Drift Fixed:
  010-ephemeral-pool: spec.md Timeout 10s->30s
  014-runner-cache: spec.md MAX_CACHE_SIZE 1GB->5GB

Actions: 4 drift fixed, 2 specs created, 3 skipped
```

## Report Template

```markdown
## Audit Report

| Category | Count | % |
|----------|-------|---|
| Specced (synced) | {n} | |
| Specced (fixed) | {n} | |
| Unspecced | {n} | |
| Uncertain | {n} | |

### Drift Fixed
| Spec | Change | Source |
|------|--------|--------|
| 010-pool | Timeout: 10s->30s | PR #418 |

### Gaps
| PR | Title | Recommendation |
|----|-------|----------------|
| #123 | Title | Create spec |
```

## Retroactive Spec Template

```markdown
Feature: {Title from PR}
{Summary from PR body}
Originally: PR #{number}, merged {date}
(Retroactive spec documenting existing functionality)
```

## Decision Tree

```
feat: commit?           -> Flag
Large fix: (3+ files)?  -> Flag
New functionality?      -> Flag
CI/CD/infra?            -> Skip
Refactor (no behavior)? -> Skip
Otherwise               -> Review
```

## Integration

```bash
/speckit-audit                    # Run audit
/speckit-retro specs/010-*        # Deeper learnings
/speckit-flow "Feature desc"      # Create spec
/speckit-verify specs/010-*       # Full verify
```

speckit-audit auto-fixes T1+T2 drift. Use `/speckit-verify` or `/speckit-retro` for T3.
