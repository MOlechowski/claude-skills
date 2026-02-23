---
name: dev-broken-windows
description: "Scan codebase for entropy indicators — broken windows that trigger systemic decay. Detects: skipped tests, commented-out code, TODO/FIXME without issue refs, dead exports, naming inconsistency, empty catch blocks. Produces prioritized report by severity. Use when: codebase health check, entropy scan, broken windows audit, code hygiene. Triggers: broken windows, scan for entropy, codebase health, code hygiene, audit code quality."
---

# Broken Windows Audit

Scan a codebase for entropy indicators. One broken window starts contagion — find them before they spread.

## Workflow

```
Detect Scope → Detect Language → Scan by Severity → Aggregate → Report
```

### Phase 1: Detect Scope

Default: scan entire repository from git root. Exclude:
- `vendor/`, `node_modules/`, `.git/`, `dist/`, `build/`, `__pycache__/`
- Generated files (`.pb.go`, `_generated.go`, `.min.js`, `*.bundle.js`)
- Lock files (`package-lock.json`, `go.sum`, `poetry.lock`)

If user provides specific paths, scan only those.

### Phase 2: Detect Language

Auto-detect from file extensions and config files present:

| Signal | Language |
|--------|----------|
| `go.mod` | Go |
| `package.json` | JavaScript/TypeScript |
| `pyproject.toml`, `setup.py`, `requirements.txt` | Python |
| `Cargo.toml` | Rust |
| `*.java`, `pom.xml`, `build.gradle` | Java |
| `Gemfile` | Ruby |

Adapt detection patterns per language. Multi-language repos: scan each language with its own patterns.

### Phase 3: Scan by Severity

Scan in order. Use Grep with appropriate patterns. Report every finding with `file:line`.

#### CRITICAL — Actively hiding bugs

**Skipped/disabled tests:**

| Language | Patterns |
|----------|----------|
| Go | `t.Skip(`, `t.Skipf(` |
| JS/TS | `xit(`, `xdescribe(`, `it.skip(`, `describe.skip(`, `test.skip(` |
| Python | `@pytest.mark.skip`, `@unittest.skip`, `self.skipTest(` |
| Java | `@Ignore`, `@Disabled` |
| Ruby | `skip`, `pending` in test context |
| General | `SKIP`, `DISABLED` in test filenames |

**Known vulnerable dependencies:**

```bash
# Check if audit tools are available, run if present
npm audit --json 2>/dev/null || true
pip audit --json 2>/dev/null || true
go vuln check 2>/dev/null || true
```

Only report if tool is available. Do not install tools.

#### HIGH — Dead weight confusing readers

**Commented-out code blocks:**

Grep for patterns indicating commented code, not documentation comments:
- Lines starting with `//` or `#` that contain code syntax: `=`, `(`, `)`, `{`, `}`, `return`, `if`, `for`, `import`
- Multi-line `/* */` blocks containing code syntax
- Threshold: 3+ consecutive commented lines with code syntax = one finding

Exclude: license headers, doc comments (`///`, `/**`, `#:`), build tags, linter directives.

**Dead exports — symbols exported but never imported:**

For small-to-medium repos (<500 files): Grep for exported symbols, then verify each has at least one import/usage elsewhere. For large repos: sample the top-level package exports only.

**Unreachable code:**

Grep for patterns after unconditional `return`, `break`, `continue`, `throw`, `panic`, `os.Exit`.

#### MEDIUM — Signals of neglect

**TODO/FIXME without issue references:**

```
Grep: TODO|FIXME|HACK|XXX|TEMP
```

Classify each:
- **With issue ref** (`TODO(#123)`, `FIXME: see JIRA-456`) → INFO, skip
- **Without issue ref** → MEDIUM finding
- **Aged** (in git blame > 6 months) → upgrade to HIGH

```bash
# For age checking, use git blame on the specific line
git blame -L {line},{line} -- {file} --porcelain | head -1
```

**Inconsistent naming within a module:**

Per file, check if exported/public identifiers mix conventions:
- camelCase vs snake_case vs PascalCase
- Only flag when the SAME file mixes conventions (cross-file differences may be intentional)

**Empty catch/except blocks:**

| Language | Pattern |
|----------|---------|
| JS/TS | `catch` followed by `{` then `}` with nothing between (allow comments) |
| Python | `except:` or `except Exception:` followed by `pass` |
| Go | `if err != nil {` followed by only `}` or only a comment |
| Java | `catch (` followed by `{` then `}` with nothing between |

#### LOW — Cosmetic drift

**Unused imports/variables:**

Only flag obvious patterns:
- Python: `import X` where `X` never appears again in file
- Go: compiler catches these, skip
- JS/TS: `import ... from` where imported name never appears

**Trailing whitespace, inconsistent line endings:**

Skip — leave this to formatters and linters.

### Phase 4: Aggregate

Count findings per severity:

```
CRITICAL: N findings
HIGH:     N findings
MEDIUM:   N findings
LOW:      N findings
```

Calculate entropy score (0-100, lower is better):

```
entropy = (critical * 10 + high * 5 + medium * 2 + low * 0.5) / total_files * 10
```

Cap at 100. Round to one decimal.

### Phase 5: Report

```markdown
# Broken Windows Audit: [repo-name]

## Entropy Score: [X]/100

**Scanned:** [N] files across [languages]
**Findings:** [N] critical, [N] high, [N] medium, [N] low

## Risk Assessment

[One paragraph: overall codebase health, biggest concern, recommended first action]

## Critical Findings

[All CRITICAL findings, full detail]

**Location:** `file:line`
**Category:** [Skipped Test | Known Vulnerability]
**Finding:** [What is broken]
**Fix:** [Concrete action]

## High Findings

[All HIGH findings]

## Medium Findings

[All MEDIUM findings, grouped by category]

### TODOs Without Issue References
[List with file:line and the TODO text]

### Naming Inconsistencies
[List with file and the mixed conventions found]

### Empty Catch Blocks
[List with file:line]

## Low Findings

[Summary count only, no individual listings unless <10 total]

## Top 5 Actions

1. [Most impactful fix — usually a CRITICAL]
2. [Second most impactful]
3. [Third]
4. [Fourth]
5. [Fifth]
```

## Rules

1. **Scan, don't fix.** Report findings only. Do not modify code unless explicitly asked.
2. **Every finding needs a location.** `file:line` or it didn't happen.
3. **No false positives from generated code.** Exclude generated/vendored files.
4. **Adapt to the language.** Use language-specific patterns, not one-size-fits-all regex.
5. **Be honest about coverage.** If the repo is too large to scan completely, state what was scanned and what was skipped.
6. **CRITICAL means actually critical.** Skipped tests and known vulns only. Don't inflate severity.
