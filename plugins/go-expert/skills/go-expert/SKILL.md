---
name: go-expert
description: "[Go] Language expertise: idiomatic patterns, project structure, concurrency (goroutines, channels, sync), error handling, testing strategies, generics, modules. Use for: Go architecture decisions, code review, project setup, idiomatic patterns. Delegates to: go-golangci-lint, go-delve, go-pprof, go-goreleaser. Triggers: golang, go code, idiomatic go, go project, go testing, go concurrency, goroutine, channel, go architecture."
---

# Go Language Expert

Domain expertise for Go architecture, idiomatic patterns, and design decisions.

**Delegate to tool-specific skills:**
- `go-lint` - Linting and static analysis
- `go-delve` - Debugging
- `go-pprof` - Profiling and performance
- `go-release` - Release automation

## Tool Selection

| Task | Tool | Notes |
|------|------|-------|
| Format code | `gofmt` / `goimports` | Built-in, use goimports for import management |
| Lint code | `golangci-lint` | See go-lint skill |
| Debug | `delve` | See go-delve skill |
| Profile | `pprof` | See go-pprof skill |
| Release | `goreleaser` | See go-release skill |
| Vulnerability scan | `govulncheck` | Built-in since Go 1.20 |
| Race detection | `go test -race` | Built-in |

## Philosophy

**Start with the standard library, add dependencies only when they block you.** Unlike ecosystems where reaching for a framework is step one, Go's stdlib and compiler-enforced conventions (`internal/` visibility) mean most production backends are built with minimal external dependencies.

## HTTP Framework Decision Guide

| Scenario | Use | Why |
|----------|-----|-----|
| New project, learning Go | `net/http` (stdlib) | Full control, no deps |
| Need routing + middleware | Chi | stdlib-compatible, composable |
| Rapid prototyping, REST API | Gin | Batteries-included, 48% market share |
| Express.js-like DX | Fiber | Familiar syntax, fast |
| Already have stdlib code | Chi | Drop-in compatible with `net/http` |

## Database Layer Decision Guide

| Scenario | Use | Why |
|----------|-----|-----|
| Know SQL, want type safety | sqlc | Code-gen from SQL, near-native perf |
| PostgreSQL-specific | pgx | Fastest Postgres driver |
| Quick prototyping | GORM | Full ORM, migrations, relations |
| Existing `database/sql` code | sqlx | Thin wrapper, struct scanning |

For detailed library examples see: [references/ecosystem.md](references/ecosystem.md)

## Idiomatic Go Principles

### Accept Interfaces, Return Structs

```go
// Good: Accept interface
func Process(r io.Reader) error { ... }

// Good: Return concrete type
func NewServer(addr string) *Server { ... }

// Bad: Return interface (hides implementation)
func NewServer(addr string) ServerInterface { ... }
```

### Make Zero Values Useful

```go
// Good: Zero value is ready to use
type Counter struct {
    mu    sync.Mutex
    count int  // zero value is 0, ready to use
}

// bytes.Buffer works with zero value
var buf bytes.Buffer
buf.WriteString("hello")
```

### Small Interfaces

```go
// Good: Single-method interface
type Reader interface {
    Read(p []byte) (n int, err error)
}

// Good: Compose small interfaces
type ReadWriter interface {
    Reader
    Writer
}

// Bad: Large interfaces reduce flexibility
type DoEverything interface {
    Read() error
    Write() error
    Close() error
    Flush() error
    // ... many more methods
}
```

### Error Handling Philosophy

```go
// Handle errors explicitly
if err != nil {
    return fmt.Errorf("operation failed: %w", err)
}

// Don't panic for recoverable errors
// Use panic only for programmer errors (impossible states)

// Errors are values - can be inspected, compared, wrapped
if errors.Is(err, sql.ErrNoRows) {
    return nil, ErrNotFound
}
```

## Core Toolchain

### Build and Run

```bash
go build ./...              # Build all packages
go build -o myapp ./cmd/app # Build specific binary
go run ./cmd/app            # Build and run
go install ./...            # Install binaries to $GOPATH/bin
```

### Testing

```bash
go test ./...               # Run all tests
go test -v ./pkg/...        # Verbose output
go test -race ./...         # Race detector
go test -cover ./...        # Coverage
go test -count=1 ./...      # Disable test caching
go test -run TestFoo ./...  # Run specific test
```

### Modules

```bash
go mod init example.com/myproject  # Initialize module
go mod tidy                        # Add/remove dependencies
go mod download                    # Download dependencies
go mod verify                      # Verify checksums
go mod graph                       # Show dependency graph
go get package@version             # Add/update dependency
```

### Code Quality

```bash
go fmt ./...                # Format code
go vet ./...                # Static analysis
go doc package              # View documentation
go generate ./...           # Run go:generate directives
```

### Workspaces (Go 1.18+)

```bash
go work init ./module1 ./module2  # Create workspace
go work use ./module3             # Add module to workspace
go work sync                      # Sync workspace
```

## Concurrency Decision Guide

| Scenario | Use | Why |
|----------|-----|-----|
| Coordinate goroutines | `sync.WaitGroup` | Simple completion signaling |
| Share data with single writer | `sync.Mutex` | Protect critical section |
| Share data with many readers | `sync.RWMutex` | Better read concurrency |
| One-time initialization | `sync.Once` | Thread-safe lazy init |
| Pass data between goroutines | Channels | Communicate by sharing |
| Cancel long operations | `context.Context` | Propagate cancellation |
| Limit concurrent operations | Semaphore channel | `make(chan struct{}, n)` |
| Pool expensive resources | `sync.Pool` | Reduce allocations |

### Context Patterns

```go
// Always pass context as first parameter
func DoWork(ctx context.Context, arg string) error {
    // Check for cancellation
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }
    // ... work
}

// Create contexts with timeout/deadline
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

// Never store context in structs (usually)
```

## Interface Design

### Define Interfaces Where Used

```go
// package consumer
type Storage interface {
    Get(key string) ([]byte, error)
    Put(key string, value []byte) error
}

func NewService(s Storage) *Service { ... }

// package producer - no interface needed
type RedisStorage struct { ... }
func (r *RedisStorage) Get(key string) ([]byte, error) { ... }
func (r *RedisStorage) Put(key string, value []byte) error { ... }
```

### Interface Segregation

```go
// Good: Client defines minimal interface needed
type Getter interface {
    Get(key string) ([]byte, error)
}

// Function only needs Get, accepts Getter
func FetchData(g Getter, key string) ([]byte, error) {
    return g.Get(key)
}
```

## Functional Options Pattern

Configure complex types with optional parameters cleanly.

```go
type Server struct {
    addr    string
    timeout time.Duration
    logger  *slog.Logger
}

// Option is a functional option
type Option func(*Server)

// WithTimeout sets the server timeout
func WithTimeout(d time.Duration) Option {
    return func(s *Server) {
        s.timeout = d
    }
}

// WithLogger sets the logger
func WithLogger(l *slog.Logger) Option {
    return func(s *Server) {
        s.logger = l
    }
}

// NewServer creates server with options
func NewServer(addr string, opts ...Option) *Server {
    s := &Server{
        addr:    addr,
        timeout: 30 * time.Second,  // Default
        logger:  slog.Default(),    // Default
    }
    for _, opt := range opts {
        opt(s)
    }
    return s
}

// Usage
srv := NewServer(":8080",
    WithTimeout(60*time.Second),
    WithLogger(customLogger),
)
```

**When to use:**
- Constructor with many optional parameters
- Configuration that may grow over time
- Avoiding boolean/config struct proliferation

## Dependency Injection

Manual constructor injection dominates production Go. Start manual, add a framework only when wiring becomes painful.

| Approach | When | Example |
|----------|------|---------|
| Manual constructors | Default for all projects | `NewService(repo, logger)` |
| [Wire](https://github.com/google/wire) | Large codebases, compile-time | Code generation, no runtime cost |
| [uber-go/fx](https://github.com/uber-go/fx) | Large codebases, runtime | Reflection-based, less boilerplate |

## Package Design

### Naming

```go
// Good: Short, lowercase, no underscores
package user
package httputil
package testdata

// Bad
package user_service  // no underscores
package HTTPUtil      // no mixed case
package utils         // too generic
```

### Structure

```
myproject/
├── cmd/
│   └── myapp/
│       └── main.go       # Entry point
├── internal/             # Private packages
│   ├── config/
│   └── handler/
├── pkg/                  # Public packages (optional)
│   └── client/
├── go.mod
└── go.sum
```

### Avoid Package-Level State

```go
// Bad: Global state
var db *sql.DB

func Query() { db.Query(...) }

// Good: Dependency injection
type Service struct {
    db *sql.DB
}

func (s *Service) Query() { s.db.Query(...) }
```

## Error Patterns

### Wrapping Errors

```go
// Add context when wrapping
if err != nil {
    return fmt.Errorf("failed to connect to %s: %w", addr, err)
}

// Check wrapped errors
if errors.Is(err, os.ErrNotExist) { ... }

// Extract wrapped error
var pathErr *os.PathError
if errors.As(err, &pathErr) {
    fmt.Println(pathErr.Path)
}
```

### Sentinel Errors

```go
// Define at package level
var ErrNotFound = errors.New("not found")

// Use for expected conditions callers handle
func Get(id string) (*Item, error) {
    if !exists(id) {
        return nil, ErrNotFound
    }
    return item, nil
}
```

### Custom Error Types

```go
type ValidationError struct {
    Field   string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Check with errors.As
var valErr *ValidationError
if errors.As(err, &valErr) {
    fmt.Printf("invalid field: %s\n", valErr.Field)
}
```

## Common Gotchas

| Gotcha | Issue | Solution |
|--------|-------|----------|
| Loop variable capture | Closure captures variable address | Go 1.22+ fixes this; otherwise copy var |
| nil interface vs nil concrete | `interface{}((*T)(nil)) != nil` | Check both interface and concrete |
| Slice append | May allocate new backing array | Pre-allocate if size known |
| defer in loop | Deferred calls accumulate | Extract to function |
| Map concurrent access | Race condition | Use sync.Map or mutex |
| String iteration | Iterates runes, not bytes | Use `[]byte(s)` for bytes |

For detailed coverage see: [references/gotchas.md](references/gotchas.md)

## Resources

- [references/concurrency.md](references/concurrency.md) - Goroutines, channels, sync patterns
- [references/error-handling.md](references/error-handling.md) - Error wrapping, sentinels, custom types
- [references/testing.md](references/testing.md) - Table-driven tests, mocks, fuzzing, benchmarks
- [references/project-structure.md](references/project-structure.md) - Package layout, interfaces, DI
- [references/modules.md](references/modules.md) - Workspaces, vendoring, private modules
- [references/generics.md](references/generics.md) - Type parameters, constraints, patterns
- [references/gotchas.md](references/gotchas.md) - Common pitfalls and solutions
- [references/ecosystem.md](references/ecosystem.md) - Popular libraries by domain
