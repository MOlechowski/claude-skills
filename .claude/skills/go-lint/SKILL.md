---
name: go-lint
description: "[Go] Linter aggregator: 100+ linters (staticcheck, gosec, errcheck, govet, revive, etc.), .golangci.yml configuration, CI integration. Use for: linting Go code, static analysis, code quality, security scanning. Triggers: golangci-lint, go lint, staticcheck, gosec, errcheck."
---

# golangci-lint

Fast Go linter aggregator running 100+ linters in parallel.

## Installation

```bash
# macOS
brew install golangci-lint

# Go install
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Binary download
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin
```

## Quick Start

```bash
# Run all enabled linters
golangci-lint run

# Run on specific paths
golangci-lint run ./pkg/...

# Run specific linters
golangci-lint run --enable=gosec,errcheck

# Auto-fix issues
golangci-lint run --fix

# Show available linters
golangci-lint linters
```

## Common Linter Presets

### Fast (Default)

```yaml
# .golangci.yml
linters:
  enable:
    - errcheck      # Unchecked errors
    - gosimple      # Simplifications
    - govet         # Go vet checks
    - ineffassign   # Unused assignments
    - staticcheck   # Static analysis
    - unused        # Unused code
```

### Thorough

```yaml
linters:
  enable:
    - errcheck
    - gosimple
    - govet
    - ineffassign
    - staticcheck
    - unused
    - gocritic      # Code review comments
    - gocyclo       # Cyclomatic complexity
    - gofmt         # Format check
    - goimports     # Import format
    - misspell      # Spelling
    - unconvert     # Unnecessary conversions
    - unparam       # Unused parameters
```

### Security

```yaml
linters:
  enable:
    - gosec         # Security issues
    - govet
    - staticcheck
    - bodyclose     # HTTP body close
    - sqlclosecheck # SQL rows close
    - exportloopref # Loop variable capture
```

## Configuration

### Minimal .golangci.yml

```yaml
run:
  timeout: 5m

linters:
  enable:
    - errcheck
    - gosimple
    - govet
    - staticcheck
    - unused

issues:
  exclude-use-default: false
```

### Full Configuration

```yaml
run:
  timeout: 5m
  issues-exit-code: 1
  tests: true
  skip-dirs:
    - vendor
    - testdata

linters:
  disable-all: true
  enable:
    - errcheck
    - gosimple
    - govet
    - ineffassign
    - staticcheck
    - unused
    - gocritic
    - gofmt
    - gosec

linters-settings:
  errcheck:
    check-type-assertions: true
    check-blank: true

  govet:
    enable-all: true

  gocyclo:
    min-complexity: 15

  gocritic:
    enabled-tags:
      - diagnostic
      - style
      - performance

  gosec:
    excludes:
      - G104  # Audit errors not checked

issues:
  exclude-rules:
    # Exclude test files from some linters
    - path: _test\.go
      linters:
        - errcheck
        - gosec

  max-issues-per-linter: 50
  max-same-issues: 10
```

## Linter Selection Guide

| Linter | Purpose | Recommended |
|--------|---------|-------------|
| errcheck | Unchecked errors | Yes |
| staticcheck | Static analysis (SA*) | Yes |
| govet | Go vet checks | Yes |
| gosimple | Code simplification (S*) | Yes |
| unused | Unused code | Yes |
| gosec | Security issues | Yes |
| gocritic | Code review | Medium projects |
| gofmt | Formatting | CI only |
| goimports | Import formatting | CI only |
| revive | Lint rules | Alternative to golint |
| misspell | Spelling | Optional |
| dupl | Code duplication | Large projects |
| gocyclo | Complexity | Set threshold |

## CI/CD Integration

### GitHub Actions

```yaml
name: Lint
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: golangci-lint
        uses: golangci/golangci-lint-action@v4
        with:
          version: latest
          args: --timeout=5m
```

### GitLab CI

```yaml
lint:
  image: golangci/golangci-lint:latest
  script:
    - golangci-lint run --timeout=5m
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/golangci/golangci-lint
    rev: v1.55.2
    hooks:
      - id: golangci-lint
```

## Common Issues and Fixes

### Suppress False Positives

```go
// Inline suppression
//nolint:errcheck
_ = f.Close()

// Suppress specific linter
//nolint:gosec
password := os.Getenv("PASSWORD")

// Suppress with reason
//nolint:errcheck // error is logged by Close()
defer f.Close()
```

### Config-Level Exclusions

```yaml
issues:
  exclude-rules:
    # Ignore errcheck in tests
    - path: _test\.go
      linters:
        - errcheck

    # Ignore specific message
    - text: "G104: Errors unhandled"
      linters:
        - gosec
```

## Performance

```bash
# Run with limited CPU
golangci-lint run --concurrency=2

# Disable expensive linters
golangci-lint run --disable=dupl,gocyclo

# Use cache
golangci-lint run  # Automatic caching

# Clear cache
golangci-lint cache clean
```

## Full Linter List

See: [references/linters.md](references/linters.md) for complete linter reference with configurations.
