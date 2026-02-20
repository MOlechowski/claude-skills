---
name: sec-pip-audit
description: "Python dependency vulnerability scanner. Audit installed packages and requirements files for known vulnerabilities. Use for: (1) scanning Python dependencies, (2) CI security checks, (3) SBOM generation, (4) finding vulnerable packages. Triggers: pip-audit, python vulnerabilities, dependency audit, pip security, requirements audit, pypi vulnerabilities."
---

# pip-audit

Scan Python environments for packages with known vulnerabilities.

## Quick Start

```bash
# Audit current environment
pip-audit

# Audit requirements file
pip-audit -r requirements.txt

# Audit with fix suggestions
pip-audit --fix

# JSON output
pip-audit -f json
```

## Scan Sources

### Virtual Environment

```bash
# Current environment
pip-audit

# Specific virtual environment
pip-audit --path /path/to/venv

# Specific Python
pip-audit --python-path /usr/bin/python3.11
```

### Requirements Files

```bash
# Single file
pip-audit -r requirements.txt

# Multiple files
pip-audit -r requirements.txt -r requirements-dev.txt

# With constraints
pip-audit -r requirements.txt -c constraints.txt
```

### Lock Files

```bash
# Poetry lock
pip-audit -r poetry.lock

# Pipenv lock
pip-audit -r Pipfile.lock

# pip-tools compiled
pip-audit -r requirements.txt
```

### Direct Input

```bash
# Audit specific package
pip-audit --require "requests==2.28.0"

# Multiple packages
pip-audit --require "requests>=2.20.0" --require "flask>=1.0"
```

## Output Formats

```bash
# Table (default)
pip-audit

# JSON
pip-audit -f json

# CycloneDX SBOM
pip-audit -f cyclonedx-json

# Markdown
pip-audit -f markdown

# Columns (parseable)
pip-audit -f columns

# To file
pip-audit -f json -o audit-results.json
```

## Vulnerability Sources

```bash
# PyPI (default)
pip-audit

# OSV (Google Open Source Vulnerabilities)
pip-audit --vulnerability-service osv

# Both sources
pip-audit --vulnerability-service pypi --vulnerability-service osv

# Local database
pip-audit --local
```

## Filtering and Ignoring

### Ignore Vulnerabilities

```bash
# Ignore specific CVE
pip-audit --ignore-vuln GHSA-xxxx-yyyy-zzzz

# Ignore multiple
pip-audit --ignore-vuln PYSEC-2023-123 --ignore-vuln GHSA-xxxx-yyyy-zzzz

# Ignore from file
pip-audit --ignore-vuln-from ignore-vulns.txt
```

### ignore-vulns.txt

```
# Comments start with #
GHSA-xxxx-yyyy-zzzz  # Reason for ignoring
PYSEC-2023-123       # Another reason
```

### Skip Packages

```bash
# Skip editable installs
pip-audit --skip-editable

# Skip packages
pip-audit --ignore-package my-local-package
```

## Fix Vulnerabilities

```bash
# Suggest fixes
pip-audit --fix

# Dry run (show what would be fixed)
pip-audit --fix --dry-run

# Auto-upgrade (careful!)
pip-audit --fix --require "package>=version"
```

## Strict Mode

```bash
# Fail on any vulnerability
pip-audit --strict

# Fail on unpinned packages
pip-audit --strict --require-hashes

# Fail on dependency resolution issues
pip-audit --strict --no-deps
```

## CI Integration

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found |
| 2 | Invalid input |
| 3 | Dependency resolution error |

```bash
# In CI script
pip-audit -r requirements.txt
if [ $? -ne 0 ]; then
  echo "Vulnerabilities found!"
  exit 1
fi
```

### GitHub Actions

```yaml
- name: Audit Python dependencies
  run: |
    pip install pip-audit
    pip-audit -r requirements.txt --strict

# Or using action
- uses: pypa/gh-action-pip-audit@v1.0.8
  with:
    inputs: requirements.txt
```

### GitLab CI

```yaml
pip-audit:
  script:
    - pip install pip-audit
    - pip-audit -r requirements.txt -f json -o audit.json
  artifacts:
    paths:
      - audit.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pypa/sec-pip-audit
    rev: v2.6.1
    hooks:
      - id: pip-audit
        args: ["-r", "requirements.txt"]
```

## Configuration

### pyproject.toml

```toml
[tool.pip-audit]
require-hashes = true
vulnerability-service = "osv"
ignore-vulns = ["GHSA-xxxx-yyyy-zzzz"]
```

## Common Patterns

### Full Audit Report

```bash
pip-audit \
  -r requirements.txt \
  -r requirements-dev.txt \
  --vulnerability-service osv \
  --vulnerability-service pypi \
  -f json \
  -o audit-report.json
```

### Quick Check

```bash
pip-audit --strict -r requirements.txt
```

### Generate SBOM with Vulnerabilities

```bash
# CycloneDX format
pip-audit -r requirements.txt -f cyclonedx-json -o sbom.json

# Include all packages (not just vulnerable)
pip-audit -f cyclonedx-json --desc > sbom-full.json
```

### Compare Audits

```bash
# Baseline audit
pip-audit -r requirements.txt -f json > baseline.json

# Current audit
pip-audit -r requirements.txt -f json > current.json

# Compare
diff <(jq '.dependencies[].vulns[].id' baseline.json | sort) \
     <(jq '.dependencies[].vulns[].id' current.json | sort)
```

### Audit Multiple Projects

```bash
#!/bin/bash
for req in */requirements.txt; do
  project=$(dirname "$req")
  echo "Auditing $project..."
  pip-audit -r "$req" -f json -o "$project/audit.json"
done
```

### Find Upgrade Path

```bash
# Show fix versions
pip-audit --fix --dry-run -r requirements.txt 2>&1 | \
  grep "would be upgraded"
```

## Troubleshooting

### Dependency Resolution

```bash
# Skip dependency resolution (use installed versions)
pip-audit --no-deps

# Use pip for resolution
pip-audit --require "package==1.0.0" --no-deps
```

### Cache Issues

```bash
# Clear cache
pip-audit --cache-dir /tmp/pip-audit-cache --clear-cache

# Skip cache
pip-audit --no-cache
```

### Verbose Output

```bash
# Debug output
pip-audit -v

# Very verbose
pip-audit -vv
```

## Integration

For Python code security analysis, use `/bandit`.
For multi-language SAST, use `/semgrep`.
For container vulnerability scanning, use `/trivy` or `/grype`.
For general SBOM generation, use `/syft`.
