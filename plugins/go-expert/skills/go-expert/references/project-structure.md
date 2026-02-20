# Go Project Structure

## Table of Contents
- [Standard Layouts](#standard-layouts)
- [Package Naming](#package-naming)
- [Interface Placement](#interface-placement)
- [Dependency Injection](#dependency-injection)
- [internal vs pkg](#internal-vs-pkg)
- [Module Organization](#module-organization)

## Standard Layouts

### Minimal Project

```
myproject/
├── main.go           # Entry point
├── go.mod
└── go.sum
```

### Small Library

```
mylib/
├── mylib.go          # Main library code
├── mylib_test.go     # Tests
├── go.mod
└── go.sum
```

### Application with cmd

```
myapp/
├── cmd/
│   └── myapp/
│       └── main.go   # Application entry point
├── internal/         # Private application code
│   ├── config/
│   │   └── config.go
│   └── server/
│       └── server.go
├── go.mod
└── go.sum
```

### Full Project Layout

```
myproject/
├── cmd/                    # Main applications
│   ├── api/
│   │   └── main.go
│   └── worker/
│       └── main.go
├── internal/               # Private code (not importable)
│   ├── config/
│   ├── database/
│   ├── handler/
│   └── service/
├── pkg/                    # Public libraries (optional)
│   └── client/
├── api/                    # API definitions
│   └── openapi.yaml
├── web/                    # Web assets
│   ├── static/
│   └── templates/
├── scripts/                # Build/deploy scripts
├── deployments/            # Deployment configs
│   ├── docker/
│   └── kubernetes/
├── testdata/               # Test fixtures
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

### When to Use What

| Project Type | Structure |
|--------------|-----------|
| Simple script | Single main.go |
| Small library | Flat structure |
| CLI tool | cmd/ + internal/ |
| Web service | cmd/ + internal/ + api/ |
| Monorepo | Multiple go.mod or go.work |

## Package Naming

### Good Names

```go
package user       // Domain entity
package http       // Protocol
package json       // Format
package config     // Configuration
package testutil   // Testing utilities (suffix -util ok for test helpers)
```

### Bad Names

```go
package utils      // Too generic
package common     // Too generic
package helpers    // Too generic
package misc       // Meaningless
package user_service  // No underscores
package userService   // No mixed case
package UserService   // No exported package names
```

### Package vs Directory

```
// Directory name = package name (usually)
internal/user/user.go     → package user
internal/http/server.go   → package http (shadows stdlib - be careful)
internal/httputil/util.go → package httputil
```

### Import Path Naming

```go
// Full import path
import "github.com/user/project/internal/config"

// Aliasing when names conflict
import (
    "net/http"
    myhttp "github.com/user/project/internal/http"
)
```

## Interface Placement

### Define Where Used (Consumer)

```go
// package handler (consumer)
type UserGetter interface {
    GetUser(id string) (*User, error)
}

func NewHandler(ug UserGetter) *Handler {
    return &Handler{users: ug}
}

// package storage (producer) - no interface needed
type PostgresStore struct { ... }
func (p *PostgresStore) GetUser(id string) (*User, error) { ... }
```

### Benefits

```go
// Multiple consumers can define their own interfaces
// package auth
type UserVerifier interface {
    GetUser(id string) (*User, error)
}

// package notification
type UserEmailer interface {
    GetUser(id string) (*User, error)
    GetEmail(id string) (string, error)
}

// Same implementation satisfies both
```

### Standard Library Pattern

```go
// io.Reader defined in io package
// Used by many packages: json.Decoder, bufio.Reader, etc.
// Implementations: os.File, bytes.Buffer, net.Conn, etc.

type Reader interface {
    Read(p []byte) (n int, err error)
}
```

### Exceptions

```go
// Define at producer when:
// 1. Interface is the primary API
// 2. Multiple implementations expected
// 3. Plugin/driver pattern

// Example: database/sql
type Driver interface {
    Open(name string) (Conn, error)
}
```

## Dependency Injection

### Constructor Injection

```go
type Service struct {
    db     *sql.DB
    cache  Cache
    logger *slog.Logger
}

func NewService(db *sql.DB, cache Cache, logger *slog.Logger) *Service {
    return &Service{
        db:     db,
        cache:  cache,
        logger: logger,
    }
}
```

### Functional Options

```go
type Server struct {
    addr    string
    timeout time.Duration
    logger  *slog.Logger
}

type Option func(*Server)

func WithTimeout(d time.Duration) Option {
    return func(s *Server) {
        s.timeout = d
    }
}

func WithLogger(l *slog.Logger) Option {
    return func(s *Server) {
        s.logger = l
    }
}

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
    WithTimeout(5*time.Second),
    WithLogger(myLogger),
)
```

### Wire Main

```go
// cmd/myapp/main.go
func main() {
    // Create dependencies
    db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    cache := redis.NewClient(&redis.Options{
        Addr: os.Getenv("REDIS_URL"),
    })
    defer cache.Close()

    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

    // Wire dependencies
    userStore := storage.NewPostgresUserStore(db)
    userCache := cache.NewUserCache(cache)
    userService := service.NewUserService(userStore, userCache, logger)
    userHandler := handler.NewUserHandler(userService, logger)

    // Start server
    router := http.NewServeMux()
    router.Handle("/users/", userHandler)

    log.Fatal(http.ListenAndServe(":8080", router))
}
```

## internal vs pkg

### internal/

```go
// Code in internal/ cannot be imported outside the module
// Enforced by Go compiler

myproject/
├── internal/
│   └── secret/        # Only myproject can import
│       └── secret.go
└── cmd/
    └── myapp/
        └── main.go    # Can import internal/secret

// Another project CANNOT import:
// import "github.com/user/myproject/internal/secret"  // Error!
```

### pkg/

```go
// pkg/ is conventional, not enforced
// Signals "this is meant to be imported"

myproject/
├── pkg/
│   └── client/        # Public API for other projects
│       └── client.go
└── internal/
    └── server/        # Private implementation

// Other projects CAN import:
// import "github.com/user/myproject/pkg/client"  // OK
```

### When to Use

| Use Case | Location |
|----------|----------|
| Application logic | internal/ |
| Private helpers | internal/ |
| Domain models (private) | internal/ |
| Public client library | pkg/ or root |
| Shared utilities (public) | pkg/ |

### Many Projects Skip pkg/

```go
// Flat structure is fine for libraries
mylib/
├── client.go    # Public
├── internal/    # Private
└── go.mod
```

## Module Organization

### Single Module (Most Common)

```
myproject/
├── go.mod         # module github.com/user/myproject
├── cmd/
├── internal/
└── pkg/
```

### Multi-Module (Monorepo)

```
monorepo/
├── go.work           # Go workspace
├── service-a/
│   ├── go.mod       # module github.com/user/monorepo/service-a
│   └── ...
├── service-b/
│   ├── go.mod       # module github.com/user/monorepo/service-b
│   └── ...
└── shared/
    ├── go.mod       # module github.com/user/monorepo/shared
    └── ...
```

### go.work Example

```go
// go.work
go 1.21

use (
    ./service-a
    ./service-b
    ./shared
)
```

### When Multi-Module

- Independent versioning needed
- Different release cycles
- Large teams with separate ownership
- Shared libraries with stable APIs

### When Single Module

- Small to medium projects
- Tightly coupled components
- Same release cycle
- Single team ownership
