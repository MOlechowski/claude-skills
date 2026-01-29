---
name: go-task
description: "[Go] Task runner (taskfile.dev) for Go projects. YAML-based alternative to Make. Use for: build automation, development tasks, CI/CD scripts. Triggers: task, taskfile, go-task, task runner."
---

# Task

Modern task runner - simpler alternative to Make with YAML configuration.

## Installation

```bash
# macOS
brew install go-task

# Go install
go install github.com/go-task/task/v3/cmd/task@latest

# Linux
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b ~/.local/bin

# Verify
task --version
```

## Quick Start

Create `Taskfile.yml`:

```yaml
version: '3'

tasks:
  build:
    cmds:
      - go build -o bin/app ./cmd/app

  test:
    cmds:
      - go test ./...

  lint:
    cmds:
      - golangci-lint run
```

Run tasks:

```bash
task build
task test
task lint
```

## Taskfile Structure

```yaml
version: '3'

vars:
  BINARY: myapp
  BUILD_DIR: bin

env:
  CGO_ENABLED: '0'

tasks:
  default:
    cmds:
      - task: build

  build:
    desc: Build the application
    cmds:
      - go build -o {{.BUILD_DIR}}/{{.BINARY}} ./cmd/app
    sources:
      - '**/*.go'
    generates:
      - '{{.BUILD_DIR}}/{{.BINARY}}'

  test:
    desc: Run tests
    cmds:
      - go test -race -cover ./...

  clean:
    desc: Clean build artifacts
    cmds:
      - rm -rf {{.BUILD_DIR}}
```

## Variables

### Static Variables

```yaml
vars:
  NAME: myapp
  VERSION: 1.0.0

tasks:
  build:
    cmds:
      - go build -ldflags "-X main.version={{.VERSION}}" -o {{.NAME}}
```

### Dynamic Variables

```yaml
vars:
  GIT_COMMIT:
    sh: git rev-parse --short HEAD
  DATE:
    sh: date +%Y-%m-%d

tasks:
  build:
    cmds:
      - echo "Building commit {{.GIT_COMMIT}} on {{.DATE}}"
```

### Task-Level Variables

```yaml
tasks:
  greet:
    vars:
      NAME: '{{default "World" .NAME}}'
    cmds:
      - echo "Hello, {{.NAME}}!"
```

## Dependencies

### Basic Dependencies

```yaml
tasks:
  build:
    deps: [generate, lint]
    cmds:
      - go build ./...

  generate:
    cmds:
      - go generate ./...

  lint:
    cmds:
      - golangci-lint run
```

### Parallel Dependencies

```yaml
tasks:
  all:
    deps:
      - task: test
      - task: lint
      - task: build
    # Dependencies run in parallel by default
```

### Sequential Execution

```yaml
tasks:
  deploy:
    cmds:
      - task: test
      - task: build
      - task: push
    # cmds run sequentially
```

## Sources and Generates

Skip task if sources haven't changed:

```yaml
tasks:
  build:
    sources:
      - '**/*.go'
      - go.mod
      - go.sum
    generates:
      - bin/app
    cmds:
      - go build -o bin/app ./cmd/app
```

## Environment

```yaml
env:
  GOOS: linux
  GOARCH: amd64

tasks:
  build-linux:
    env:
      CGO_ENABLED: '0'
    cmds:
      - go build -o bin/app-linux ./cmd/app
```

### dotenv Support

```yaml
dotenv: ['.env', '.env.local']

tasks:
  run:
    cmds:
      - ./bin/app  # Uses vars from .env
```

## Includes

Split large Taskfiles:

```yaml
# Taskfile.yml
version: '3'

includes:
  docker: ./taskfiles/Docker.yml
  test: ./taskfiles/Test.yml
```

```yaml
# taskfiles/Docker.yml
version: '3'

tasks:
  build:
    cmds:
      - docker build -t myapp .
```

```bash
task docker:build
```

## Preconditions

```yaml
tasks:
  deploy:
    preconditions:
      - sh: test -f bin/app
        msg: "Binary not found. Run 'task build' first."
      - sh: '[ -n "$DEPLOY_TOKEN" ]'
        msg: "DEPLOY_TOKEN not set"
    cmds:
      - ./deploy.sh
```

## CLI Commands

```bash
task              # Run default task
task build        # Run specific task
task -l           # List tasks
task -a           # List all tasks (including internal)
task --dry        # Dry run (show commands)
task -f           # Force run (ignore up-to-date)
task -w           # Watch mode
task -p           # Run in parallel
task VAR=value    # Pass variables
```

## Watch Mode

```yaml
tasks:
  dev:
    watch: true
    sources:
      - '**/*.go'
    cmds:
      - go run ./cmd/app
```

```bash
task dev  # Reruns on file changes
```

## Go Project Example

```yaml
version: '3'

vars:
  BINARY: myapp
  VERSION:
    sh: git describe --tags --always --dirty
  COMMIT:
    sh: git rev-parse --short HEAD
  LDFLAGS: -s -w -X main.version={{.VERSION}} -X main.commit={{.COMMIT}}

env:
  CGO_ENABLED: '0'

tasks:
  default:
    cmds:
      - task: build

  generate:
    desc: Run go generate
    cmds:
      - go generate ./...
    sources:
      - '**/*.go'

  build:
    desc: Build binary
    deps: [generate]
    cmds:
      - go build -ldflags "{{.LDFLAGS}}" -o bin/{{.BINARY}} ./cmd/app
    sources:
      - '**/*.go'
      - go.mod
    generates:
      - bin/{{.BINARY}}

  test:
    desc: Run tests
    cmds:
      - go test -race -cover ./...

  lint:
    desc: Run linters
    cmds:
      - golangci-lint run

  fmt:
    desc: Format code
    cmds:
      - gofumpt -w .
      - goimports -w .

  ci:
    desc: Run CI checks
    cmds:
      - task: fmt
      - task: lint
      - task: test
      - task: build

  clean:
    desc: Clean build artifacts
    cmds:
      - rm -rf bin/
      - go clean -cache

  release:
    desc: Create release
    deps: [ci]
    cmds:
      - goreleaser release --clean
```

## Task vs Make

| Feature | Task | Make |
|---------|------|------|
| Config | YAML | Makefile |
| Cross-platform | Yes | Needs compatibility |
| Variables | Native YAML | Make syntax |
| Dependencies | Simple | Tab-sensitive |
| Watch mode | Built-in | External |
| Parallel | Native | -j flag |
