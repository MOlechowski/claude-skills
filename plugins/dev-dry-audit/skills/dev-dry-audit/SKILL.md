---
name: dev-dry-audit
description: "Detect DRY violations across a codebase — knowledge duplication, not just copy-paste. Finds: code clones, repeated constants, config values in multiple places, comments paraphrasing code, API contract drift. Reports as violation pairs with suggested consolidation. Use when: DRY audit, find duplication, code duplication scan, knowledge duplication. Triggers: DRY audit, find duplicates, scan for duplication, repeated code, copy-paste detection."
---

# DRY Audit

Detect knowledge duplication across a codebase. DRY is about knowledge, not code — two identical blocks representing different concepts are fine; two different blocks encoding the same business rule are a violation.

## The Four Categories

Tag every finding with its probable category:

| Category | Cause | Fix Pattern |
|----------|-------|-------------|
| **Imposed** | Environment forces it (client/server, header/impl) | Code generators, shared schemas |
| **Inadvertent** | Design mistake (storing derived data) | Calculated fields, normalize |
| **Impatient** | Copy-paste under pressure | Extract shared utility |
| **Interdeveloper** | Teams unknowingly building the same thing | Shared library, discovery |

## Workflow

```
Detect Scope → Pass 1: Grep → Pass 2: Tools → Pass 3: Deep Read → Aggregate → Report
```

### Phase 1: Detect Scope

Default: scan entire repository from git root. Exclude:
- `vendor/`, `node_modules/`, `.git/`, `dist/`, `build/`, `__pycache__/`
- Generated files (`.pb.go`, `_generated.go`, `.min.js`, `*.bundle.js`)
- Lock files (`package-lock.json`, `go.sum`, `poetry.lock`)
- Test fixtures and snapshot files

If user provides specific paths, scan only those.

### Phase 2: Pass 1 — Grep (fast, whole-repo)

Scan the entire repo with Grep for duplication signals. This pass finds candidates; Pass 3 confirms them.

#### Repeated Constants

Find literal values (strings, numbers) that appear in 3+ files:

```bash
# Find hardcoded URLs, ports, timeouts, magic numbers
# Grep for string literals, then count occurrences across files
```

Strategy:
1. Grep for common config patterns: URLs (`http://`, `https://`), ports (`:3000`, `:8080`), timeouts, email addresses, API paths
2. For each match, count how many distinct files contain the same literal
3. Flag literals appearing in 3+ files as candidates

Exclude: test assertions comparing against known values, import paths, license text.

#### Config Duplication

Grep for values that appear in multiple config files or are hardcoded alongside config:

- Same value in `.env`, `docker-compose.yml`, `config.yaml`, and source code
- Environment variable names referenced but with hardcoded fallback values that differ
- Database connection strings, API endpoints, feature flags in multiple places

#### Explicit Duplication Markers

```bash
# Grep for developer-left markers
# Pattern: DRY|duplicat|same as|copied from|see also.*similar
```

These are developers flagging known duplication — low-hanging fruit.

### Phase 3: Pass 2 — Tools (if available)

Check for and run clone detection tools. Do not install tools — only use what's present.

```bash
# Check availability
which jscpd 2>/dev/null    # JavaScript/multi-language clone detector
which cpd 2>/dev/null       # PMD Copy/Paste Detector (Java-focused)
which dupfinder 2>/dev/null # JetBrains duplicate finder
```

If `jscpd` is available (most common):

```bash
jscpd --min-lines 5 --min-tokens 50 --reporters json --output /tmp/jscpd-report .
```

Parse the JSON output for clone pairs. Each clone becomes a finding with both locations.

If no tools are available, skip this pass — Pass 1 and Pass 3 still provide value.

### Phase 4: Pass 3 — Deep Read (targeted)

Read the top candidates from Pass 1 and 2. This pass catches what grep cannot:

#### Comment-Code Redundancy

For each file with significant comments (>10 comment lines), read the file and check:
- Do comments restate what the code already expresses?
- Are there block comments that could be replaced by better naming?
- Is the same information in a docstring AND inline comments?

Only flag comments that literally paraphrase adjacent code. Explanatory comments about *why* are valuable — do not flag those.

#### API Contract Drift

If the repo has API definitions (OpenAPI/Swagger, protobuf, GraphQL schemas):
1. Read the schema definition
2. Read the handler/resolver implementation
3. Compare: do they define the same fields/types/endpoints?
4. Flag divergences where the schema says one thing and the code does another

#### Near-Duplicate Functions

From Pass 2 clones (or from scanning if no tools), read function pairs and assess:
- Are they truly duplicate knowledge, or coincidentally similar?
- What's the minimal extraction to consolidate them?
- Tag with category: impatient (copy-paste) vs interdeveloper (different authors)

### Phase 5: Aggregate

Count findings by detection method and category:

```
Code Clones:        N pairs
Repeated Constants: N values across M files
Config Duplication: N values
Comment Redundancy: N files
API Drift:          N endpoints
```

### Phase 6: Report

```markdown
# DRY Audit: [repo-name]

**Scanned:** [N] files across [languages]
**Tool assist:** [jscpd found X clones | no clone tools available]
**Findings:** [N] violation pairs

## Summary

[One paragraph: biggest duplication risk, most duplicated knowledge, recommended first consolidation]

## Code Clones

[Grouped by similarity. Each finding as a pair:]

### Clone Group 1: [brief description of what's duplicated]

**Category:** Impatient | Interdeveloper | Imposed
**Location A:** `file-a:line-range`
**Location B:** `file-b:line-range`
**Similarity:** [high | medium]
**Consolidation:** [Concrete suggestion — extract to shared function/module, use code generator, etc.]

## Repeated Constants

### [constant value or pattern]

**Category:** Imposed | Impatient
**Appears in:**
- `file-a:line` — [context]
- `file-b:line` — [context]
- `file-c:line` — [context]
**Consolidation:** [Define once in config/constants file, import everywhere]

## Config Duplication

[Same format as Repeated Constants, focused on config values]

## Comment Redundancy

**Location:** `file:line-range`
**Finding:** Comment restates what code already expresses
**Example:** [The comment] → [The code it duplicates]
**Fix:** Delete the comment or replace with a WHY explanation

## API Contract Drift

**Schema:** `schema-file:line`
**Implementation:** `handler-file:line`
**Drift:** [What differs — missing field, type mismatch, extra endpoint]
**Fix:** [Update schema or implementation to match]

## Top 5 Consolidation Targets

1. [Highest impact — most files affected or most critical knowledge duplicated]
2. [Second]
3. [Third]
4. [Fourth]
5. [Fifth]
```

## Rules

1. **DRY is about knowledge, not characters.** Two identical utility functions in unrelated modules may be fine. The same business rule in two places is always a violation.
2. **Report as pairs.** Every finding must show both sides of the duplication — source and duplicate.
3. **Tag with category.** Every finding gets an Imposed/Inadvertent/Impatient/Interdeveloper tag. Best guess is fine.
4. **Don't flag test assertions.** Tests intentionally repeat expected values — that's verification, not duplication.
5. **Don't flag imports or type references.** Using the same type in multiple files is not duplication.
6. **Suggest consolidation, don't execute.** Report what to merge and where — don't modify code unless asked.
7. **Be honest about tool coverage.** State whether clone detection tools were available and what was scanned manually vs. by tool.
