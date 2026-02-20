---
name: sec-semgrep
description: "Multi-language static analysis tool with security-focused rules. Pattern-based code scanning for vulnerabilities, bugs, and code standards. Use for: (1) security vulnerability detection, (2) custom rule enforcement, (3) multi-language SAST, (4) code review automation. Triggers: semgrep, static analysis, sast, security scan, code patterns, vulnerability scan, code review."
---

# Semgrep

Fast, lightweight static analysis tool for finding bugs and security issues.

## Quick Start

```bash
# Scan with security rules
semgrep --config auto .

# Scan with specific ruleset
semgrep --config p/security-audit .

# Scan single file
semgrep --config auto path/to/file.py

# Scan with custom rule
semgrep --config my-rules.yaml .
```

## Rule Sources

### Registry Rulesets

```bash
# Auto-detect language and use default rules
semgrep --config auto .

# Security audit rules
semgrep --config p/security-audit .

# OWASP Top 10
semgrep --config p/owasp-top-ten .

# Language-specific
semgrep --config p/python .
semgrep --config p/javascript .
semgrep --config p/go .
semgrep --config p/java .

# Framework-specific
semgrep --config p/django .
semgrep --config p/flask .
semgrep --config p/react .
semgrep --config p/nodejs .

# CI defaults
semgrep --config p/ci .

# Multiple rulesets
semgrep --config p/security-audit --config p/python .
```

### Local Rules

```bash
# Single rule file
semgrep --config rules.yaml .

# Rule directory
semgrep --config ./rules/ .

# Multiple sources
semgrep --config p/security-audit --config ./custom-rules/ .
```

## Output Formats

```bash
# Text (default)
semgrep --config auto .

# JSON
semgrep --config auto --json .

# SARIF (GitHub Security)
semgrep --config auto --sarif -o results.sarif .

# JUnit XML
semgrep --config auto --junit-xml -o results.xml .

# GitLab SAST
semgrep --config auto --gitlab-sast -o gl-sast-report.json .

# Emacs format
semgrep --config auto --emacs .

# Vim format
semgrep --config auto --vim .

# Output to file
semgrep --config auto --json -o results.json .
```

## Filtering Results

### By Severity

```bash
# Error and warning only
semgrep --config auto --severity ERROR --severity WARNING .

# Exclude info
semgrep --config auto --exclude-rule-severity INFO .
```

### By Path

```bash
# Exclude paths
semgrep --config auto --exclude tests --exclude vendor .

# Exclude patterns
semgrep --config auto --exclude '*.test.js' --exclude '*_test.py' .

# Include only specific paths
semgrep --config auto --include 'src/**/*.py' .
```

### By Rule

```bash
# Exclude specific rules
semgrep --config auto --exclude-rule python.lang.security.audit.exec-detected .

# Include only specific rules
semgrep --config auto --include-rule python.lang.security .
```

## Writing Custom Rules

### Basic Rule Structure

```yaml
# rules.yaml
rules:
  - id: hardcoded-password
    pattern: password = "..."
    message: Hardcoded password detected
    severity: ERROR
    languages:
      - python
```

### Pattern Syntax

```yaml
rules:
  # Exact match
  - id: exact-match
    pattern: eval($X)
    message: eval() is dangerous
    severity: ERROR
    languages: [python]

  # Metavariable matching
  - id: sql-injection
    pattern: cursor.execute($QUERY % $INPUT)
    message: Potential SQL injection
    severity: ERROR
    languages: [python]

  # Multiple patterns (any)
  - id: dangerous-functions
    patterns:
      - pattern-either:
          - pattern: eval(...)
          - pattern: exec(...)
          - pattern: compile(...)
    message: Dangerous function call
    severity: WARNING
    languages: [python]

  # Pattern with condition
  - id: insecure-request
    patterns:
      - pattern: requests.$METHOD(..., verify=False, ...)
    message: SSL verification disabled
    severity: ERROR
    languages: [python]
```

### Advanced Patterns

```yaml
rules:
  # Not pattern (exclude)
  - id: print-without-f-string
    patterns:
      - pattern: print($X)
      - pattern-not: print(f"...")
    message: Consider using f-string
    severity: INFO
    languages: [python]

  # Inside pattern (context)
  - id: return-in-finally
    patterns:
      - pattern-inside: |
          try:
            ...
          finally:
            ...
      - pattern: return ...
    message: Return in finally block
    severity: WARNING
    languages: [python]

  # Metavariable conditions
  - id: weak-random
    patterns:
      - pattern: random.$FUNC(...)
      - metavariable-regex:
          metavariable: $FUNC
          regex: (random|randint|choice)
    message: Use secrets module for security
    severity: WARNING
    languages: [python]
```

### Taint Tracking

```yaml
rules:
  - id: sql-injection-taint
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sinks:
      - pattern: cursor.execute($QUERY)
    pattern-sanitizers:
      - pattern: escape(...)
    message: User input flows to SQL query
    severity: ERROR
    languages: [python]
```

## Configuration File

### .semgrep.yaml

```yaml
# Project configuration
rules: []

# Paths to scan
paths:
  include:
    - src/
    - lib/

  exclude:
    - tests/
    - vendor/
    - "*.test.js"

# Rule sources
config:
  - p/security-audit
  - ./custom-rules/
```

### semgrep.yaml (Rule Library)

```yaml
rules:
  - id: project-specific-rule
    pattern: DEPRECATED_FUNCTION(...)
    message: Use NEW_FUNCTION instead
    severity: WARNING
    languages: [python]
    metadata:
      category: migration
      cwe: "CWE-477: Use of Obsolete Function"
```

## CI Integration

### GitHub Actions

```yaml
- name: Semgrep Scan
  uses: returntocorp/semgrep-action@v1
  with:
    config: p/security-audit

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: semgrep.sarif
```

### GitLab CI

```yaml
semgrep:
  image: returntocorp/sec-semgrep
  script:
    - semgrep --config auto --gitlab-sast -o gl-sast-report.json .
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/sec-semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/python', '--error']
```

## Common Patterns

### Full Security Scan

```bash
semgrep \
  --config p/security-audit \
  --config p/owasp-top-ten \
  --json \
  --output results.json \
  --exclude tests \
  --severity ERROR \
  --severity WARNING \
  .
```

### Quick Check (Pre-commit)

```bash
semgrep --config auto --error --quiet .
```

### Scan Specific Languages

```bash
# Python only
semgrep --config p/python --config p/flask .

# JavaScript/TypeScript
semgrep --config p/javascript --config p/typescript --config p/react .

# Go
semgrep --config p/go --config p/golang .
```

### Generate Baseline

```bash
# Create baseline
semgrep --config auto --json > baseline.json

# Scan with baseline (ignore known issues)
semgrep --config auto --baseline baseline.json .
```

### Test Custom Rules

```bash
# Test rule against specific file
semgrep --config my-rule.yaml test-file.py

# Validate rule syntax
semgrep --validate --config my-rules/
```

## Debugging Rules

```bash
# Verbose output
semgrep --config auto --verbose .

# Debug mode
semgrep --config auto --debug .

# Show matched patterns
semgrep --config auto --show-patterns .

# Test pattern interactively
semgrep --pattern 'eval($X)' --lang python .
```

## Integration

For Python-specific security, use `/bandit`.
For Python dependency vulnerabilities, use `/pip-audit`.
For container scanning, use `/trivy` or `/grype`.
