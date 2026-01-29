# golangci-lint Linters Reference

Complete reference for all major linters.

## Default Enabled

### errcheck
Checks for unchecked errors.

```yaml
linters-settings:
  errcheck:
    check-type-assertions: true
    check-blank: true
    exclude-functions:
      - io/ioutil.ReadFile
      - io.Copy
```

### gosimple
Simplification suggestions (S* rules from staticcheck).

```yaml
linters-settings:
  gosimple:
    checks: ["all"]
```

### govet
Reports suspicious constructs.

```yaml
linters-settings:
  govet:
    enable-all: true
    disable:
      - shadow
```

### ineffassign
Detects ineffectual assignments.

### staticcheck
Static analysis (SA* rules).

```yaml
linters-settings:
  staticcheck:
    checks: ["all", "-SA1019"]  # Disable deprecation warnings
```

### unused
Finds unused code.

## Code Quality

### gocritic
Code review comments.

```yaml
linters-settings:
  gocritic:
    enabled-tags:
      - diagnostic
      - style
      - performance
    disabled-checks:
      - whyNoLint
```

### gocyclo
Cyclomatic complexity.

```yaml
linters-settings:
  gocyclo:
    min-complexity: 15
```

### gocognit
Cognitive complexity.

```yaml
linters-settings:
  gocognit:
    min-complexity: 20
```

### maintidx
Maintainability index.

```yaml
linters-settings:
  maintidx:
    under: 20
```

### dupl
Code duplication.

```yaml
linters-settings:
  dupl:
    threshold: 100  # Tokens
```

### funlen
Function length.

```yaml
linters-settings:
  funlen:
    lines: 60
    statements: 40
```

### lll
Line length.

```yaml
linters-settings:
  lll:
    line-length: 120
    tab-width: 4
```

## Formatting

### gofmt
Checks formatting.

```yaml
linters-settings:
  gofmt:
    simplify: true
```

### goimports
Checks import formatting.

```yaml
linters-settings:
  goimports:
    local-prefixes: github.com/myorg
```

### gofumpt
Stricter gofmt.

```yaml
linters-settings:
  gofumpt:
    extra-rules: true
```

### whitespace
Whitespace issues.

```yaml
linters-settings:
  whitespace:
    multi-if: true
    multi-func: true
```

## Security

### gosec
Security issues (G* rules).

```yaml
linters-settings:
  gosec:
    excludes:
      - G104  # Errors unhandled
      - G304  # File path injection
    config:
      G301: "0750"  # File permissions
```

Common rules:
- G101: Hardcoded credentials
- G102: Bind to all interfaces
- G104: Unhandled errors
- G201: SQL string formatting
- G301: Poor file permissions
- G304: File path from tainted input
- G401: Weak cryptographic primitive
- G501: Crypto/md5 import

### bodyclose
HTTP response body close.

### sqlclosecheck
SQL rows close.

### exportloopref
Loop variable capture in goroutines.

### noctx
HTTP requests without context.

## Style

### revive
Configurable linter (golint replacement).

```yaml
linters-settings:
  revive:
    rules:
      - name: blank-imports
      - name: context-as-argument
      - name: context-keys-type
      - name: dot-imports
      - name: error-return
      - name: error-strings
      - name: error-naming
      - name: exported
      - name: if-return
      - name: increment-decrement
      - name: var-naming
      - name: package-comments
      - name: range
      - name: receiver-naming
      - name: time-naming
      - name: unexported-return
      - name: indent-error-flow
      - name: errorf
```

### stylecheck
Style checks (ST* rules from staticcheck).

```yaml
linters-settings:
  stylecheck:
    checks: ["all", "-ST1000"]
```

### misspell
Spelling errors.

```yaml
linters-settings:
  misspell:
    locale: US
```

### godot
Comment period.

```yaml
linters-settings:
  godot:
    scope: declarations
```

### wsl
Whitespace linter.

### nlreturn
Newline before return.

## Bugs

### nilnil
nil return with nil error.

### nilerr
Return nil on error.

### unparam
Unused parameters.

### unconvert
Unnecessary conversions.

### wastedassign
Wasted assignments.

### predeclared
Shadowing predeclared identifiers.

## Performance

### prealloc
Slice preallocation.

```yaml
linters-settings:
  prealloc:
    simple: true
    range-loops: true
    for-loops: false
```

### maligned (deprecated)
Use fieldalignment instead.

### bodyclose
HTTP body close (also security).

## Testing

### testpackage
Separate test package.

```yaml
linters-settings:
  testpackage:
    skip-regexp: (export|internal)_test\.go
```

### paralleltest
Missing t.Parallel().

### tparallel
Improper t.Parallel() usage - detects missing calls and incorrect patterns.

### thelper
Missing t.Helper().

### testifylint
Testify best practices and common mistakes.

```yaml
linters-settings:
  testifylint:
    enable-all: true
```

## Additional Linters

### exhaustruct
Enforce exhaustive struct initialization.

```yaml
linters-settings:
  exhaustruct:
    include:
      - '.*Config$'
      - '.*Options$'
```

### containedctx
Flags structs containing context.Context fields.

```go
// Bad: context in struct
type Service struct {
    ctx context.Context  // Will be flagged
}

// Good: pass context to methods
func (s *Service) Do(ctx context.Context) error { ... }
```

### contextcheck
Ensures context is passed as first parameter.

```go
// Bad: context not first
func Process(data []byte, ctx context.Context) {}

// Good
func Process(ctx context.Context, data []byte) {}
```

### gochecknoglobals
Flags global variables (with exceptions for errors and compiled regexps).

```yaml
linters-settings:
  gochecknoglobals:
    allow-exceptions: true
```

### gochecknoinits
Flags init() functions.

### nonamedreturns
Forbids named return values.

```go
// Flagged
func foo() (result int, err error) { ... }

// Allowed
func foo() (int, error) { ... }
```

### cyclop
Package complexity (alternative to gocyclo).

```yaml
linters-settings:
  cyclop:
    max-complexity: 15
    package-average: 5.0
```

## Configuration Examples

### Minimal (Fast)

```yaml
linters:
  enable:
    - errcheck
    - gosimple
    - govet
    - staticcheck
    - unused
```

### Standard

```yaml
linters:
  enable:
    - errcheck
    - gosimple
    - govet
    - staticcheck
    - unused
    - gosec
    - gocritic
    - gofmt
```

### Thorough

```yaml
linters:
  disable-all: true
  enable:
    - errcheck
    - gosimple
    - govet
    - staticcheck
    - unused
    - gosec
    - gocritic
    - gofmt
    - goimports
    - misspell
    - unconvert
    - unparam
    - dupl
    - funlen
    - gocyclo
    - revive
```

### Security Focus

```yaml
linters:
  enable:
    - gosec
    - govet
    - staticcheck
    - bodyclose
    - noctx
    - sqlclosecheck
    - exportloopref
```

## Suppressing Issues

### Inline

```go
//nolint:errcheck
_ = f.Close()

//nolint:gosec
password := os.Getenv("PASSWORD")

//nolint:all
riskyCode()
```

### File Level

```go
//nolint:dupl
package mypackage
```

### Config Level

```yaml
issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - errcheck
        - gosec

    - path: mock_
      linters:
        - dupl

    - text: "G104"
      linters:
        - gosec
```
