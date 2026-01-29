# Go Modules

## Table of Contents
- [go.mod Management](#gomod-management)
- [Workspace Mode](#workspace-mode)
- [Replace Directives](#replace-directives)
- [Vendoring](#vendoring)
- [Private Modules](#private-modules)
- [Multi-Module Repositories](#multi-module-repositories)
- [Version Selection (MVS)](#version-selection-mvs)
- [Retract Directives](#retract-directives)

## go.mod Management

### Initialize Module

```bash
# New project
go mod init github.com/user/project

# Existing project without modules
cd myproject
go mod init github.com/user/myproject
```

### go.mod Structure

```go
module github.com/user/myproject

go 1.22

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
)

require (
    // indirect dependencies
    golang.org/x/sys v0.15.0 // indirect
)
```

### Common Commands

```bash
# Add dependency
go get github.com/pkg/errors

# Add specific version
go get github.com/pkg/errors@v0.9.1

# Update dependency
go get -u github.com/pkg/errors

# Update all dependencies
go get -u ./...

# Update to latest minor/patch
go get -u=patch ./...

# Remove unused dependencies
go mod tidy

# Download dependencies
go mod download

# Verify checksums
go mod verify

# Show dependency graph
go mod graph

# Explain why dependency is needed
go mod why github.com/pkg/errors
```

### Version Queries

```bash
go get pkg@v1.2.3      # Specific version
go get pkg@latest      # Latest release
go get pkg@upgrade     # Latest allowed by go.mod
go get pkg@patch       # Latest patch version
go get pkg@master      # Branch name
go get pkg@abc123      # Commit hash
go get pkg@none        # Remove dependency
```

## Workspace Mode

### Creating Workspace

```bash
# Initialize workspace with modules
go work init ./module1 ./module2

# Add module to existing workspace
go work use ./module3

# Edit go.work manually
go work edit -use=./module4
```

### go.work File

```go
go 1.22

use (
    ./api
    ./backend
    ./shared
)

// Optional: replace for all modules in workspace
replace github.com/user/shared => ./shared
```

### Workspace Commands

```bash
# Sync workspace modules
go work sync

# Build all workspace modules
go build ./...

# Run tests across workspace
go test ./...
```

### When to Use Workspaces

- Local development with multiple modules
- Testing changes across modules before publishing
- Monorepo development
- Avoiding replace directives in go.mod

### Workspace vs Replace

```go
// go.work - for development only (not committed)
// Replace affects all modules in workspace
// Doesn't modify individual go.mod files

// go.mod replace - committed to repo
// Only affects that specific module
// Published modules should NOT have replace
```

## Replace Directives

### Local Development

```go
// go.mod
module github.com/user/myapp

replace github.com/user/mylib => ../mylib

require github.com/user/mylib v1.0.0
```

### Fork Replace

```go
// Use fork instead of original
replace github.com/original/pkg => github.com/myfork/pkg v1.0.0
```

### Version Override

```go
// Force specific version
replace github.com/pkg/errors v0.8.0 => github.com/pkg/errors v0.9.1
```

### Remove Before Publishing

```bash
# Check for replace directives
grep -n "replace" go.mod

# Remove all replace directives
# Manual edit or:
go mod edit -dropreplace=github.com/user/mylib
```

## Vendoring

### Creating Vendor Directory

```bash
# Copy dependencies to vendor/
go mod vendor

# Verify vendor matches go.mod
go mod verify
```

### Using Vendor

```bash
# Build using vendor (default if vendor/ exists)
go build ./...

# Explicitly use vendor
go build -mod=vendor ./...

# Ignore vendor
go build -mod=readonly ./...
go build -mod=mod ./...
```

### vendor/modules.txt

```
# github.com/gin-gonic/gin v1.9.1
## explicit; go 1.20
github.com/gin-gonic/gin
github.com/gin-gonic/gin/binding
```

### When to Vendor

- Reproducible builds without network
- Air-gapped environments
- CI/CD optimization (pre-downloaded deps)
- Dependency auditing

## Private Modules

### GOPRIVATE

```bash
# Single domain
export GOPRIVATE=github.com/mycompany

# Multiple domains
export GOPRIVATE=github.com/mycompany,gitlab.com/mycompany

# Wildcard
export GOPRIVATE=*.mycompany.com

# In .bashrc or .zshrc
export GOPRIVATE=github.com/mycompany/*
```

### Git Configuration

```bash
# Use SSH instead of HTTPS
git config --global url."git@github.com:".insteadOf "https://github.com/"

# For specific org
git config --global url."git@github.com:mycompany/".insteadOf "https://github.com/mycompany/"
```

### GOPROXY Configuration

```bash
# Default (public proxy)
export GOPROXY=https://proxy.golang.org,direct

# Skip proxy for private
export GOPROXY=https://proxy.golang.org,direct
export GOPRIVATE=github.com/mycompany

# Private proxy
export GOPROXY=https://goproxy.mycompany.com,https://proxy.golang.org,direct

# Direct only (no proxy)
export GOPROXY=direct
```

### GONOSUMDB

```bash
# Skip checksum database for private modules
export GONOSUMDB=github.com/mycompany/*

# Usually set together with GOPRIVATE
export GOPRIVATE=github.com/mycompany
export GONOSUMDB=$GOPRIVATE
```

### CI/CD Configuration

```yaml
# GitHub Actions
env:
  GOPRIVATE: github.com/mycompany/*

steps:
  - uses: actions/checkout@v4
  - name: Configure Git
    run: |
      git config --global url."https://${{ secrets.GH_TOKEN }}@github.com/".insteadOf "https://github.com/"
```

## Multi-Module Repositories

### Shared Version

```
repo/
├── go.mod            # v1.0.0
├── submodule/
│   └── go.mod       # v1.0.0 (independent)
└── pkg/
    └── shared.go    # Part of root module
```

### Independent Versions

```
repo/
├── api/
│   ├── go.mod       # github.com/user/repo/api v2.0.0
│   └── api.go
├── client/
│   ├── go.mod       # github.com/user/repo/client v1.5.0
│   └── client.go
└── shared/
    ├── go.mod       # github.com/user/repo/shared v1.2.0
    └── shared.go
```

### Tagging Submodules

```bash
# Root module
git tag v1.0.0

# Submodule (prefix with path)
git tag api/v2.0.0
git tag client/v1.5.0

# Push tags
git push origin --tags
```

### Internal Dependencies

```go
// client/go.mod
module github.com/user/repo/client

require github.com/user/repo/shared v1.2.0
```

## Version Selection (MVS)

### How MVS Works

```
Your module requires:
- pkg A v1.2.0
- pkg B v1.0.0

pkg A requires:
- pkg C v1.5.0

pkg B requires:
- pkg C v1.3.0

MVS selects: pkg C v1.5.0 (highest minimum version)
```

### Version Constraints

```go
// go.mod - minimum version constraints
require github.com/pkg/errors v0.9.0  // At least v0.9.0
```

### Upgrade vs Downgrade

```bash
# Upgrade to latest
go get -u github.com/pkg/errors

# Upgrade to specific
go get github.com/pkg/errors@v0.9.1

# Downgrade (may fail if others need higher)
go get github.com/pkg/errors@v0.8.0
```

### Understanding Version Selection

```bash
# See why version was selected
go mod why github.com/pkg/errors

# See full graph
go mod graph | grep errors

# See all versions
go list -m -versions github.com/pkg/errors
```

## Retract Directives

### Retract Versions

```go
// go.mod
module github.com/user/mylib

go 1.22

// Retract broken versions
retract (
    v1.0.0 // Critical bug in parsing
    v1.0.1 // Incomplete fix
)

retract [v1.1.0, v1.1.5] // Range of versions
```

### Retract Current Version

```go
// go.mod
module github.com/user/mylib

go 1.22

// This version retracts itself
retract v1.2.0 // Accidental release with debug code
```

### Publishing Retraction

```bash
# Edit go.mod with retract directive
# Tag and push new version (e.g., v1.2.1)
git tag v1.2.1
git push origin v1.2.1

# Users will see warning when using retracted version
# go get will prefer non-retracted versions
```

### Checking Retractions

```bash
# See if using retracted versions
go list -m -u all

# Shows:
# github.com/user/mylib v1.0.0 (retracted)
```
