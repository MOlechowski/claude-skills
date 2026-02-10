# Code Review Rubric

## Six Pillars Scoring

### Security (Weight: 2x)

| Score | Criteria |
|-------|----------|
| 1-2 | Active vulnerabilities: injection, auth bypass, exposed secrets, RCE |
| 3-4 | Missing input validation, weak auth patterns, no CSRF protection, hardcoded credentials |
| 5-6 | Basic validation present but incomplete, standard patterns used, some gaps |
| 7-8 | Solid validation, proper auth, defense in depth, parameterized queries throughout |
| 9-10 | Comprehensive: CSP, rate limiting, audit logging, least privilege, security headers |

### Performance (Weight: 1x)

| Score | Criteria |
|-------|----------|
| 1-2 | O(n^3)+, unbounded queries, memory leaks, blocking main thread |
| 3-4 | O(n^2) in hot paths, N+1 queries, no pagination, resource leaks |
| 5-6 | Acceptable complexity, basic optimization, some caching |
| 7-8 | Efficient algorithms, proper indexing, connection pooling, pagination |
| 9-10 | Optimal data structures, lazy loading, streaming, profiling evidence |

### Architecture (Weight: 1x)

| Score | Criteria |
|-------|----------|
| 1-2 | God objects, circular dependencies, no separation of concerns |
| 3-4 | Mixed responsibilities, tight coupling, wrong abstraction levels |
| 5-6 | Basic separation, some coupling, acceptable for small codebase |
| 7-8 | Clean boundaries, dependency injection, interface-driven design |
| 9-10 | SOLID principles, clean architecture, extensible without modification |

### Error Handling (Weight: 1.5x)

| Score | Criteria |
|-------|----------|
| 1-2 | Empty catch blocks, swallowed errors, no error types, panics |
| 3-4 | Generic catches, missing error paths, unhelpful error messages |
| 5-6 | Basic try/catch, some custom errors, errors logged |
| 7-8 | Typed errors, proper propagation, user-friendly messages, recovery logic |
| 9-10 | Error boundaries, circuit breakers, graceful degradation, full observability |

### Testing (Weight: 1x)

| Score | Criteria |
|-------|----------|
| 1-2 | No tests, or tests that never fail (tautological assertions) |
| 3-4 | Minimal happy-path tests, no edge cases, over-mocking |
| 5-6 | Happy path covered, some negative tests, basic assertions |
| 7-8 | Edge cases, integration tests, meaningful assertions, good coverage |
| 9-10 | Property-based tests, mutation testing, comprehensive coverage, test isolation |

### Maintainability (Weight: 1x)

| Score | Criteria |
|-------|----------|
| 1-2 | Unreadable, 500+ line functions, no naming convention, no structure |
| 3-4 | Inconsistent style, magic numbers, deep nesting, copy-paste duplication |
| 5-6 | Readable, some documentation where needed, acceptable complexity |
| 7-8 | Clean code, good naming, documented interfaces, low cyclomatic complexity |
| 9-10 | Self-documenting, measured complexity, exemplary readability |

## Overall Score Calculation

```
overall = (security * 2 + error_handling * 1.5 + performance + architecture + testing + maintainability) / 7.5
```

Round to one decimal place.

## Verdict Thresholds

| Range | Verdict | Action |
|-------|---------|--------|
| 1.0-3.9 | REJECT | Must not merge. Fundamental flaws. |
| 4.0-5.9 | NEEDS WORK | Requires significant revision. |
| 6.0-7.4 | ACCEPTABLE | Merge permitted. Create follow-up tasks for improvements. |
| 7.5-10.0 | SHIP IT | Approved. Minor nits addressable later. |

## Severity Levels

| Severity | Meaning | Action Required |
|----------|---------|-----------------|
| CRITICAL | Security vulnerability, data loss risk, crash | Must fix before merge |
| HIGH | Significant bug, performance regression, missing validation | Should fix before merge |
| MEDIUM | Code smell, minor bug risk, suboptimal pattern | Fix recommended |
| LOW | Style issue, minor improvement opportunity | Nice to have |
| INFO | Observation, pre-existing issue, suggestion | No action required |

## Finding Format

Each finding MUST include all five fields:

```
**Location:** `file:line` or `file:line-range`
**Severity:** CRITICAL | HIGH | MEDIUM | LOW | INFO
**Pillar:** Security | Performance | Architecture | Error Handling | Testing | Maintainability
**Finding:** [Direct statement of what is wrong]
**Fix:** [Concrete suggestion, with code snippet if helpful]
```

## Structured Report Template

ALWAYS use this exact structure:

```markdown
# Code Review: [scope]

## Verdict: [VERDICT] ([score]/10)

**Scope:** [description of what was reviewed]
**Files reviewed:** [count]
**Findings:** [N critical, N high, N medium, N low]

## Scores

| Pillar | Score | Weight | Weighted | Summary |
|--------|-------|--------|----------|---------|
| Security | X | 2.0x | X.X | [one-line summary] |
| Performance | X | 1.0x | X.X | [one-line summary] |
| Architecture | X | 1.0x | X.X | [one-line summary] |
| Error Handling | X | 1.5x | X.X | [one-line summary] |
| Testing | X | 1.0x | X.X | [one-line summary] |
| Maintainability | X | 1.0x | X.X | [one-line summary] |
| **Overall** | | | **X.X** | |

## Critical Findings

[Only CRITICAL and HIGH severity. Full finding format for each.]

## Detailed Findings

### Security
[All security findings sorted by severity]

### Performance
[All performance findings]

### Architecture
[All architecture findings]

### Error Handling
[All error handling findings]

### Testing
[All testing findings]

### Maintainability
[All maintainability findings]

## Summary

[2-3 sentences. Start with verdict justification. Highlight the single most important thing to fix. End with one genuine positive if it exists.]
```

## Inline Comment Format

When inline mode is requested:

```markdown
## [filename]

`line N` **[SEVERITY/Pillar]** Finding description.
Fix: Concrete fix suggestion.

`line N-M` **[SEVERITY/Pillar]** Finding description.
Fix: Concrete fix suggestion.
```

After all file annotations, append:

```markdown
---

## Scores

[Full scores table from structured format]

## Verdict: [VERDICT] ([score]/10)

[2-3 sentence summary]
```
