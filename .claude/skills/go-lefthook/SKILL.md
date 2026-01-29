---
name: go-lefthook
description: "[Go] Git hooks manager for Go projects. Use for: pre-commit hooks, pre-push checks, CI quality gates. Triggers: lefthook, git hooks, pre-commit, pre-push."
---

# lefthook

Fast Git hooks manager - run linters, tests, and formatters on git events.

## Installation

```bash
# macOS
brew install lefthook

# Go install
go install github.com/evilmartians/lefthook@latest

# npm
npm install lefthook --save-dev

# Verify
lefthook version
```

## Quick Start

```bash
# Initialize in repo
lefthook install

# This creates lefthook.yml
```

## Basic Configuration

```yaml
# lefthook.yml
pre-commit:
  parallel: true
  commands:
    lint:
      glob: "*.go"
      run: golangci-lint run --fix {staged_files}
    fmt:
      glob: "*.go"
      run: gofmt -w {staged_files}

pre-push:
  commands:
    test:
      run: go test ./...
```

## Commands vs Scripts

### Commands (Inline)

```yaml
pre-commit:
  commands:
    lint:
      run: golangci-lint run
```

### Scripts (External)

```yaml
pre-commit:
  scripts:
    "check-branch.sh":
      runner: bash
```

```bash
# .lefthook/pre-commit/check-branch.sh
#!/bin/bash
branch=$(git branch --show-current)
if [ "$branch" = "main" ]; then
  echo "Direct commits to main not allowed"
  exit 1
fi
```

## File Filtering

### Glob Patterns

```yaml
pre-commit:
  commands:
    go-lint:
      glob: "*.go"
      run: golangci-lint run {staged_files}

    js-lint:
      glob: "*.{js,ts}"
      run: eslint {staged_files}
```

### Exclude Patterns

```yaml
pre-commit:
  commands:
    lint:
      glob: "*.go"
      exclude: "*_test.go"
      run: golangci-lint run {staged_files}
```

### Root Directory

```yaml
pre-commit:
  commands:
    lint:
      root: "backend/"
      glob: "*.go"
      run: golangci-lint run {staged_files}
```

## Placeholders

| Placeholder | Description |
|-------------|-------------|
| `{staged_files}` | Files staged for commit |
| `{push_files}` | Files being pushed |
| `{all_files}` | All tracked files |
| `{files}` | Auto-selected based on hook |

```yaml
pre-commit:
  commands:
    lint:
      run: golangci-lint run {staged_files}

pre-push:
  commands:
    test:
      run: go test {push_files}
```

## Parallel Execution

```yaml
pre-commit:
  parallel: true  # Run all commands in parallel
  commands:
    lint:
      run: golangci-lint run
    fmt:
      run: gofmt -l .
    vet:
      run: go vet ./...
```

### Piped Execution

```yaml
pre-commit:
  piped: true  # Run sequentially, stop on failure
  commands:
    1-fmt:
      run: gofmt -w {staged_files}
    2-lint:
      run: golangci-lint run {staged_files}
    3-test:
      run: go test ./...
```

## Skip Conditions

### Environment Variable

```yaml
pre-commit:
  commands:
    lint:
      run: golangci-lint run
      skip:
        - merge
        - rebase
```

Skip with env:

```bash
LEFTHOOK=0 git commit -m "skip hooks"
```

### Only/Skip Branches

```yaml
pre-push:
  commands:
    deploy:
      run: ./deploy.sh
      only:
        - main
        - release/*
```

## Go Project Example

```yaml
# lefthook.yml
pre-commit:
  parallel: true
  commands:
    fmt:
      glob: "*.go"
      run: gofumpt -w {staged_files} && git add {staged_files}
      stage_fixed: true

    imports:
      glob: "*.go"
      run: goimports -w {staged_files} && git add {staged_files}
      stage_fixed: true

    lint:
      glob: "*.go"
      run: golangci-lint run --new-from-rev=HEAD~1

    generate:
      glob: "*.go"
      run: |
        go generate ./...
        if ! git diff --quiet; then
          echo "go generate produced changes"
          exit 1
        fi

pre-push:
  commands:
    test:
      run: go test -race ./...

    coverage:
      run: |
        go test -coverprofile=coverage.out ./...
        coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
        echo "Coverage: $coverage"

commit-msg:
  commands:
    conventional:
      run: |
        msg=$(cat $1)
        pattern="^(feat|fix|docs|style|refactor|test|chore)(\(.+\))?: .+"
        if ! echo "$msg" | grep -qE "$pattern"; then
          echo "Commit message must follow Conventional Commits"
          exit 1
        fi
```

## CLI Commands

```bash
lefthook install           # Install hooks
lefthook uninstall         # Remove hooks
lefthook run pre-commit    # Run hook manually
lefthook run --all         # Run on all files
lefthook add pre-commit    # Add hook type
lefthook version           # Show version
```

## Integration with CI

```yaml
# lefthook.yml
pre-commit:
  commands:
    lint:
      run: golangci-lint run
      skip:
        - ref: CI  # Skip in CI (use CI=true env)
```

```yaml
# .github/workflows/ci.yml
- name: Lint
  run: golangci-lint run  # Run linter directly in CI
```

## Directory Structure

```
myproject/
├── .lefthook/
│   ├── pre-commit/
│   │   └── check-branch.sh
│   └── commit-msg/
│       └── validate.sh
├── lefthook.yml
└── ...
```

## Tips

1. **Use parallel: true** - Faster hook execution
2. **Stage fixed files** - Auto-stage formatting fixes
3. **Skip in CI** - Run tools directly in CI, not via hooks
4. **Use glob** - Only process relevant files
5. **Commit lefthook.yml** - Share hooks with team
