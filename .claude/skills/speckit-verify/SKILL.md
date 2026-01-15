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

## Workflow

### 1. LOCATE Resources

Find spec and implementation:

```bash
# Find spec
SPEC_DIR="specs/$SPEC_ID"
ls $SPEC_DIR/spec.md

# Find implementation
ls submodules/*/.git 2>/dev/null || ls src/
```

### 2. PARSE Spec Claims

Extract verifiable claims from spec:

**Claim types:**
| Type | Example in spec | How to verify |
|------|-----------------|---------------|
| Config value | "Timeout is 10s" | grep for timeout constant |
| Default | "Default port is 8080" | find default assignment |
| Limit | "Max 100 retries" | find limit constant |
| API signature | "Takes (url, options)" | check function params |
| State | "States: idle, running, done" | find state enum/type |
| Env var | "Uses `API_KEY`" | grep for env var usage |

**Extraction patterns:**
```bash
# Find numbers with units in spec
grep -E "[0-9]+\s*(s|ms|m|h|KB|MB|GB)" spec.md

# Find defaults
grep -i "default" spec.md

# Find env vars
grep -E '\$[A-Z_]+|`[A-Z_]+`' spec.md
```

### 3. ANALYZE Implementation

For each claim, find actual value in code:

```bash
# Find timeout values
grep -r "timeout" --include="*.go" --include="*.ts" src/

# Find defaults
grep -r "default\|DEFAULT" --include="*.go" src/

# Find env vars
grep -r "os.Getenv\|process.env" src/
```

### 4. COMPARE

Build drift report:

| Claim | Spec Value | Impl Value | Status |
|-------|------------|------------|--------|
| Timeout | 10s | 30s | DRIFT |
| MaxRetries | 5 | 5 | OK |
| DefaultPort | 8080 | 9000 | DRIFT |

### 5. PREVIEW Changes

Show user what will be updated:

```markdown
## Spec Drift Report

Found 3 drifts in specs/010-feature/spec.md:

| Claim | Spec says | Impl has | Action |
|-------|-----------|----------|--------|
| Timeout | 10s | 30s | Update spec |
| DefaultPort | 8080 | 9000 | Update spec |
| MaxRetries | 3 | 5 | Update spec |

Proceed with updates? [Y/n]
```

### 6. UPDATE Spec

Apply corrections and add changelog:

```markdown
## Changelog

### Spec Verification (YYYY-MM-DD)

Synced spec to implementation:

| Claim | Old | New | Source |
|-------|-----|-----|--------|
| Timeout | 10s | 30s | src/config.go:42 |
| DefaultPort | 8080 | 9000 | src/server.go:15 |
```

## Output Format

```
============================================
SPECKIT-VERIFY COMPLETE
============================================

Spec: specs/010-feature/spec.md
Impl: src/

Claims checked: 15
  OK:     12
  Drift:   3

Updates applied:
  - Timeout: 10s → 30s (src/config.go:42)
  - DefaultPort: 8080 → 9000 (src/server.go:15)
  - MaxRetries: 3 → 5 (src/retry.go:8)

Changelog entry added.
============================================
```

## Rules

1. **Implementation is truth** - Always update spec to match impl, never reverse
2. **Cite sources** - Reference file:line for each correction
3. **Preview first** - Show drift before updating
4. **Preserve intent** - Update values, don't rewrite prose
5. **Add changelog** - Document all changes with date

## Drift Detection Patterns

### Config Values
```bash
# Timeouts
grep -rn "timeout.*=\|Timeout.*:" src/

# Limits
grep -rn "max\|limit\|MAX\|LIMIT" src/

# Defaults
grep -rn "default\|Default\|DEFAULT" src/
```

### API Signatures
```bash
# Function definitions
grep -rn "^func \|function \|def " src/

# Exported types
grep -rn "^type \|^interface \|^class " src/
```

### Environment Variables
```bash
# Go
grep -rn "os.Getenv" src/

# Node
grep -rn "process.env" src/

# Python
grep -rn "os.environ" src/
```

## Integration

Works with other speckit skills:
- **speckit-audit**: Find unspecced work → speckit-verify syncs it
- **speckit-retro**: Captures learnings → speckit-verify syncs values
- **speckit-flow**: Implements spec → speckit-verify validates after
