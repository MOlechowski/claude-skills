---
name: bandit
description: "Python security linter for finding common security issues. Static analysis for vulnerabilities, hardcoded secrets, and dangerous functions. Use for: (1) Python security auditing, (2) CI security gates, (3) finding hardcoded credentials, (4) detecting dangerous function calls. Triggers: bandit, python security, python linter, security audit python, find vulnerabilities python, hardcoded secrets."
---

# Bandit

Security-focused static analysis tool for Python code.

## Quick Start

```bash
# Scan directory
bandit -r ./src

# Scan single file
bandit myfile.py

# Scan with severity filter
bandit -r ./src -ll  # Medium and above

# JSON output
bandit -r ./src -f json -o results.json
```

## Scan Options

### Basic Scanning

```bash
# Recursive scan
bandit -r ./project

# Single file
bandit script.py

# Multiple files
bandit file1.py file2.py

# From stdin
cat script.py | bandit -
```

### Severity Filtering

```bash
# Show all severities (default)
bandit -r ./src

# Low and above
bandit -r ./src -l

# Medium and above
bandit -r ./src -ll

# High only
bandit -r ./src -lll
```

### Confidence Filtering

```bash
# High confidence only
bandit -r ./src -iii

# Medium confidence and above
bandit -r ./src -ii

# All confidence levels (default)
bandit -r ./src -i
```

### Combined Filters

```bash
# High severity, high confidence
bandit -r ./src -lll -iii

# Medium+ severity, medium+ confidence
bandit -r ./src -ll -ii
```

## Output Formats

```bash
# Text (default)
bandit -r ./src

# JSON
bandit -r ./src -f json

# CSV
bandit -r ./src -f csv

# HTML
bandit -r ./src -f html -o report.html

# YAML
bandit -r ./src -f yaml

# XML
bandit -r ./src -f xml

# Screen (colored)
bandit -r ./src -f screen

# Custom template
bandit -r ./src -f custom --msg-template "{abspath}:{line}: {test_id} - {msg}"
```

### Save to File

```bash
# JSON to file
bandit -r ./src -f json -o results.json

# HTML report
bandit -r ./src -f html -o report.html
```

## Test Selection

### List Available Tests

```bash
bandit --help
# Look for -s/--skip and -t/--tests options
```

### Include/Exclude Tests

```bash
# Run specific tests only
bandit -r ./src -t B101,B102,B103

# Skip specific tests
bandit -r ./src -s B101,B601

# Run specific plugin
bandit -r ./src -t B404  # import_subprocess
```

### Common Test IDs

| ID | Description |
|----|-------------|
| B101 | assert_used |
| B102 | exec_used |
| B103 | set_bad_file_permissions |
| B104 | hardcoded_bind_all_interfaces |
| B105 | hardcoded_password_string |
| B106 | hardcoded_password_funcarg |
| B107 | hardcoded_password_default |
| B108 | hardcoded_tmp_directory |
| B110 | try_except_pass |
| B112 | try_except_continue |
| B201 | flask_debug_true |
| B301 | pickle |
| B302 | marshal |
| B303 | md5/sha1 weak hash |
| B304 | des/rc4 weak cipher |
| B305 | cipher mode without authentication |
| B306 | mktemp_q |
| B307 | eval |
| B308 | mark_safe (Django) |
| B310 | urllib_urlopen |
| B311 | random |
| B312 | telnetlib |
| B313-B320 | XML vulnerabilities |
| B321 | FTP |
| B323 | unverified SSL context |
| B324 | hashlib weak hash |
| B401 | import_telnetlib |
| B402 | import_ftplib |
| B403 | import_pickle |
| B404 | import_subprocess |
| B405 | import_xml |
| B501 | request_with_no_cert_validation |
| B502 | ssl_with_bad_version |
| B503 | ssl_with_bad_defaults |
| B504 | ssl_with_no_version |
| B505 | weak_cryptographic_key |
| B506 | yaml_load |
| B507 | ssh_no_host_key_verification |
| B601 | paramiko_calls |
| B602 | subprocess_popen_with_shell_equals_true |
| B603 | subprocess_without_shell_equals_true |
| B604 | any_other_function_with_shell_equals_true |
| B605 | start_process_with_a_shell |
| B606 | start_process_with_no_shell |
| B607 | start_process_with_partial_path |
| B608 | hardcoded_sql_expressions |
| B609 | linux_commands_wildcard_injection |
| B610 | django_extra_used |
| B611 | django_rawsql_used |
| B701 | jinja2_autoescape_false |
| B702 | use_of_mako_templates |
| B703 | django_mark_safe |

## Configuration

### bandit.yaml

```yaml
# .bandit or bandit.yaml
skips:
  - B101  # Skip assert_used
  - B601  # Skip paramiko_calls

tests:
  - B102  # exec_used
  - B307  # eval

exclude_dirs:
  - tests
  - venv
  - .venv

# Profile-based configuration
profiles:
  high_severity:
    include:
      - B101
      - B102
    exclude:
      - B301
```

### Use Config File

```bash
# Default locations: .bandit, bandit.yaml, pyproject.toml
bandit -r ./src

# Explicit config
bandit -r ./src -c bandit.yaml

# Use profile from config
bandit -r ./src -p high_severity
```

### pyproject.toml

```toml
[tool.bandit]
exclude_dirs = ["tests", "venv"]
skips = ["B101", "B601"]

[tool.bandit.assert_used]
skips = ["*_test.py", "*test*.py"]
```

## Exclusions

### Exclude Paths

```bash
# Exclude directories
bandit -r ./src --exclude ./src/tests,./src/migrations

# Exclude patterns
bandit -r . -x "./.venv,./tests,./docs"
```

### Inline Exclusions

```python
# Skip single line
password = "secret123"  # nosec B105

# Skip block (context manager style comment)
# nosec
subprocess.call(cmd, shell=True)

# Skip with specific test
eval(user_input)  # nosec B307
```

## CI Integration

### Exit Codes

```bash
# Exit 0 only if no issues
bandit -r ./src

# Exit code based on severity
bandit -r ./src -ll  # Exit 1 if medium+ found

# Explicit exit codes
bandit -r ./src --exit-zero  # Always exit 0
```

### GitHub Actions

```yaml
- name: Run Bandit
  run: |
    pip install bandit
    bandit -r ./src -ll -f json -o bandit-results.json

- name: Upload Bandit results
  uses: actions/upload-artifact@v3
  with:
    name: bandit-results
    path: bandit-results.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ["-ll", "-r"]
```

## Common Patterns

### Full Security Audit

```bash
bandit -r ./src \
  -f json \
  -o security-audit.json \
  --exclude "./.venv,./tests" \
  -ll -ii
```

### Quick Check

```bash
# High severity, high confidence only
bandit -r ./src -lll -iii -q
```

### Compare Runs

```bash
# Baseline
bandit -r ./src -f json -o baseline.json

# Later scan
bandit -r ./src -f json -o current.json

# Compare with jq
diff <(jq '.results[].test_id' baseline.json | sort) \
     <(jq '.results[].test_id' current.json | sort)
```

### Generate Baseline

```bash
# Create baseline file
bandit -r ./src -f json -o .bandit-baseline.json

# Scan against baseline (only new issues)
bandit -r ./src -b .bandit-baseline.json
```

## Integration

For multi-language static analysis, use `/semgrep`.
For Python dependency vulnerabilities, use `/pip-audit`.
For general vulnerability scanning, use `/trivy`.
