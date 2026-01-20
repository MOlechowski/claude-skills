---
name: speckit-verify
description: Verify implementation matches spec, update spec on drift.
---

# Speckit Verify: Sync Spec to Implementation

Use this skill when:
- You want to check if spec still matches implementation
- Implementation changed and spec needs updating
- Before releasing to ensure spec accuracy
- Auditing spec drift over time

Examples:
- "verify spec matches implementation"
- "check for spec drift"
- "sync spec to current code"
- "run speckit-verify"

You are an expert at verifying that specifications accurately reflect implementation. Implementation is the source of truth - when drift is found, the spec is updated.

## Three-Tier Verification

| Tier | Type | Method | Speed |
|------|------|--------|-------|
| 1 | Static | grep/ripgrep | Fast |
| 2 | Pattern | ast-grep/semantic | Medium |
| 3 | Analysis | LLM agents | Slow |

## Workflow

### 1. LOCATE Resources

```bash
SPEC_DIR="specs/$SPEC_ID"
ls $SPEC_DIR/spec.md
ls submodules/*/.git 2>/dev/null || ls src/
```

### 2. PARSE Spec Claims by Tier

Extract claims and categorize:

**Tier 1 claims** (static values):
- Config values: "Timeout is 10s"
- Env vars: "Uses `API_KEY`"
- Constants: "Max 100 retries"
- Defaults: "Default port is 8080"
- Error codes: "Returns error code 404"

**Tier 2 claims** (patterns):
- Feature presence: "Supports retry with backoff"
- Test coverage: "Timeout handling tested"
- Log messages: "Logs 'Connection established'"
- CLI flags: "Accepts --verbose flag"
- DB schema: "Table has column `created_at`"

**Tier 3 claims** (behavior):
- Behavioral: "Retries on network failure"
- Error handling: "Gracefully handles timeout"
- Edge cases: "Handles empty input"
- Security: "Validates user input"

### 2b. IDENTIFY New Artifacts

Find new files and exports:

```bash
# New files from git
git diff --name-only origin/main | grep -E '\.(ts|js|go|py)$'

# New exports
git diff origin/main -- '*.ts' '*.js' | grep "^+.*export"
```

Track:
- New files created
- New exports added
- New routes defined
- New services registered

### 3. TIER 1 - Static Checks (grep)

```bash
# Config values
grep -rn "timeout.*=\|Timeout.*:" src/

# Env vars
grep -rn "os.Getenv\|process.env\|os.environ" src/

# Constants/limits
grep -rn "const\|MAX\|LIMIT\|DEFAULT" src/

# Error codes
grep -rn "error\|Error\|ERROR" src/
```

**Wiring checks:**
```bash
# Export exists
grep -rn "export.*NewThing" src/

# Import exists
grep -rn "import.*NewThing" src/

# Route defined
grep -rn "router\.\|app\.\|Route" src/

# Service registered
grep -rn "register\|provide\|bind" src/
```

Build results table:
| Claim | Spec | Impl | Status |
|-------|------|------|--------|
| Timeout | 10s | 30s | DRIFT |
| MaxRetries | 5 | 5 | OK |

### 4. TIER 2 - Pattern Checks (ast-grep/semantic)

**Feature presence:**
```bash
# Check if retry logic exists
sg -p 'retry($$$)' --lang go src/
sg -p 'backoff($$$)' --lang go src/
```

**Test coverage:**
```bash
# Map spec items to test files
ls *_test.go | xargs grep -l "Timeout"
ls *_test.go | xargs grep -l "Retry"
```

**Log messages:**
```bash
# Compare spec logs vs impl
grep -r "log\.\|logger\." src/ | grep -i "connection"
```

**CLI flags:**
```bash
# Find flag definitions
grep -rn "flag\.\|--\|addFlag" src/
```

**Wiring patterns:**
```bash
# Export-import match
sg -p 'export { $NAME }' src/
sg -p 'import { $NAME }' src/

# Route-handler connection
sg -p 'router.get($PATH, $HANDLER)' src/

# Usage outside tests
for f in $(git diff --name-only origin/main); do
  grep -rl "$(basename $f .ts)" src/ | grep -v test
done
```

Build results:
| Feature | Spec'd | Impl'd | Tested | Status |
|---------|--------|--------|--------|--------|
| Retry | Yes | Yes | Yes | OK |
| Rate limit | Yes | No | No | MISSING |

### 5. TIER 3 - Analysis Checks (LLM agents)

Spawn analysis agents for behavioral verification:

**Agent per check:**
```
Task(
  description="Verify retry behavior",
  prompt="Read src/client.go. Does the code retry on network failure as spec says?

  Spec claim: 'Retries up to 3 times on network failure'

  Answer: VERIFIED / NOT_VERIFIED / PARTIAL
  Evidence: [cite specific code]",
  run_in_background=true
)
```

**Checks to run:**
- Behavioral correctness
- Error handling completeness
- Edge case coverage
- Security validation

**Collect results:**
```bash
# Merge agent outputs
jq -s '.' /tmp/verify_*.json
```

### 6. REPORT - Aggregate Findings

```
============================================
SPECKIT-VERIFY COMPLETE
============================================

Spec: specs/010-feature/spec.md
Impl: owner/repo-name

Tier 1 (Static):     12/12 OK
Tier 2 (Pattern):     8/10 OK, 2 issues
Tier 3 (Analysis):    5/6 OK, 1 issue

Wiring:
  Exports:     3/3 imported
  Routes:      2/2 registered
  Services:    1/1 wired
  Usage:       4/4 called (non-test)

GitHub Issues Created:
  #142 [spec-drift] Timeout: 10s → 30s
  #143 [missing-feature] Rate limiting not implemented
  #144 [behavior-gap] Empty input handling differs

Issues found:
  [T1] Timeout: 10s → 30s (DRIFT) → #142
  [T2] Feature "rate limiting" → MISSING → #143
  [T2] Test coverage "retry" → UNTESTED
  [T3] Edge case "empty input" → NOT HANDLED → #144
```

### 6b. CREATE_ISSUES - File GitHub Issues

Automatically create GitHub issues for each drift finding.

**Detect Implementation Repo:**
```bash
# Check submodules first
IMPL_REPO=$(ls -d submodules/*/.git 2>/dev/null | head -1 | xargs dirname)

# Fallback to current directory if it has source code
[ -z "$IMPL_REPO" ] && [ -d "src" -o -f "package.json" -o -f "go.mod" ] && IMPL_REPO="."

# Get full repo path for gh CLI
cd "$IMPL_REPO"
IMPL_REPO_FULL=$(gh repo view --json nameWithOwner --jq '.nameWithOwner')
```

**Ensure Labels Exist:**
```bash
gh label create "spec-drift" -c "FBCA04" -d "Spec value differs from implementation" -f -R "$IMPL_REPO_FULL"
gh label create "missing-feature" -c "D93F0B" -d "Spec feature not found in implementation" -f -R "$IMPL_REPO_FULL"
gh label create "behavior-gap" -c "5319E7" -d "Implementation behavior differs from spec" -f -R "$IMPL_REPO_FULL"
```

**Create One Issue Per Drift:**
```bash
for finding in $FINDINGS; do
  TYPE=$(echo "$finding" | jq -r '.type')

  # Map type to label
  case "$TYPE" in
    DRIFT)       LABEL="spec-drift" ;;
    MISSING)     LABEL="missing-feature" ;;
    NOT_HANDLED) LABEL="behavior-gap" ;;
  esac

  # Check for duplicate
  EXISTING=$(gh issue list -R "$IMPL_REPO_FULL" --search "$CLAIM in:title" -s open --json number --jq '.[0].number')
  [ -n "$EXISTING" ] && continue

  # Create issue
  gh issue create \
    --title "[${LABEL}] $CLAIM" \
    --body "$BODY" \
    --label "$LABEL" \
    -R "$IMPL_REPO_FULL"
done
```

**Issue Title Format:**
| Type | Format | Example |
|------|--------|---------|
| DRIFT | `[spec-drift] {claim}: {old} → {new}` | `[spec-drift] Timeout: 10s → 30s` |
| MISSING | `[missing-feature] {feature} not implemented` | `[missing-feature] Rate limiting not implemented` |
| NOT_HANDLED | `[behavior-gap] {scenario} handling differs` | `[behavior-gap] Empty input handling differs` |

**Issue Body Template:**
```markdown
## Drift Detection

| Field | Value |
|-------|-------|
| **Type** | {type} |
| **Tier** | T{n} ({Static|Pattern|Analysis}) |

## Specification
> {verbatim quote from spec}

Source: {spec_file}:{line}

## Implementation
> {actual behavior or value}

Source: {impl_file}:{line}

## Evidence
{grep/ast-grep/analysis output}

---
*Generated by speckit-verify*
```

**Error Handling:**
- No write access: Warn and skip issue creation
- Duplicate: Skip if open issue with matching title exists
- Labels missing: Created automatically with `--force`

### 7. PREVIEW Changes

```markdown
## Spec Updates Required

### Drift corrections (Tier 1)
| Claim | Old | New | Source |
|-------|-----|-----|--------|
| Timeout | 10s | 30s | src/config.go:42 |

### Missing features (Tier 2)
- Rate limiting: Not implemented (spec overpromises)
  Action: Remove from spec OR flag as TODO

### Behavioral gaps (Tier 3)
- Empty input handling: Code throws, spec says graceful
  Action: Update spec to match actual behavior

Proceed with updates? [Y/n]
```

### 8. UPDATE Spec

Apply corrections and add changelog:

```markdown
## Changelog

### Spec Verification (YYYY-MM-DD)

3-tier verification against implementation:

| Tier | Issue | Resolution |
|------|-------|------------|
| T1 | Timeout drift | Updated 10s → 30s |
| T2 | Rate limiting missing | Removed from spec |
| T3 | Empty input behavior | Updated error handling section |
```

## Rules

1. **Implementation is truth** - Update spec to match impl
2. **Tier order** - Run T1 → T2 → T3 (fast to slow)
3. **Cite sources** - Reference file:line for each finding
4. **Preview first** - Show all tiers before updating
5. **Categorize issues** - DRIFT vs MISSING vs NOT_HANDLED

## Quick Reference

### Tier 1 patterns
```bash
# Numbers with units
grep -E "[0-9]+\s*(s|ms|m|h|KB|MB)" spec.md

# Environment variables
grep -E '\$[A-Z_]+|`[A-Z_]+`' spec.md
```

### Tier 2 patterns
```bash
# Feature keywords
grep -i "support\|implement\|provide" spec.md

# Test mapping
grep -l "TestTimeout\|test_timeout" *_test.*
```

### Tier 3 prompts
```
"Does [file] handle [edge case] as spec claims?"
"Is [security requirement] enforced in [file]?"
"Does [function] behave as spec describes?"
```

## Integration

- **speckit-audit**: Find unspecced work → verify syncs it
- **speckit-retro**: Captures learnings → verify validates
- **speckit-flow**: Implements spec → verify checks after
