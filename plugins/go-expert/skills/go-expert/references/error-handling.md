# Go Error Handling

## Table of Contents
- [Error Basics](#error-basics)
- [Error Wrapping](#error-wrapping)
- [Sentinel Errors](#sentinel-errors)
- [Custom Error Types](#custom-error-types)
- [Panic and Recover](#panic-and-recover)
- [Errors in Goroutines](#errors-in-goroutines)

## Error Basics

### The error Interface

```go
type error interface {
    Error() string
}

// Creating simple errors
err := errors.New("something went wrong")
err := fmt.Errorf("failed to process %s", name)
```

### Error Handling Pattern

```go
result, err := doSomething()
if err != nil {
    return fmt.Errorf("doSomething failed: %w", err)
}
// Use result
```

### Don't Ignore Errors

```go
// Bad: Ignoring error
data, _ := ioutil.ReadFile("config.json")

// Good: Handle or propagate
data, err := ioutil.ReadFile("config.json")
if err != nil {
    return nil, fmt.Errorf("reading config: %w", err)
}
```

## Error Wrapping

### Using %w for Wrapping

```go
func loadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("reading config file %s: %w", path, err)
    }

    var cfg Config
    if err := json.Unmarshal(data, &cfg); err != nil {
        return nil, fmt.Errorf("parsing config: %w", err)
    }

    return &cfg, nil
}
```

### errors.Is - Check Error Chain

```go
if err != nil {
    // Check if error (or any wrapped error) is os.ErrNotExist
    if errors.Is(err, os.ErrNotExist) {
        return nil, ErrConfigNotFound
    }
    return nil, err
}

// Works through multiple wrapping levels
err := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", os.ErrNotExist))
errors.Is(err, os.ErrNotExist)  // true
```

### errors.As - Extract Error Type

```go
var pathErr *os.PathError
if errors.As(err, &pathErr) {
    fmt.Printf("failed path: %s\n", pathErr.Path)
    fmt.Printf("operation: %s\n", pathErr.Op)
}

// Works through wrapping
err := fmt.Errorf("wrapper: %w", &os.PathError{Path: "/tmp/foo"})
errors.As(err, &pathErr)  // true, pathErr is populated
```

### errors.Unwrap

```go
// Unwrap one level
inner := errors.Unwrap(err)

// Usually prefer errors.Is/As over manual unwrapping
```

## Sentinel Errors

### Defining Sentinel Errors

```go
package mypackage

import "errors"

var (
    ErrNotFound     = errors.New("not found")
    ErrUnauthorized = errors.New("unauthorized")
    ErrInvalidInput = errors.New("invalid input")
)
```

### Using Sentinel Errors

```go
func GetUser(id string) (*User, error) {
    user, exists := users[id]
    if !exists {
        return nil, ErrNotFound
    }
    return user, nil
}

// Caller checks
user, err := GetUser("123")
if errors.Is(err, ErrNotFound) {
    // Handle missing user
}
```

### When to Use Sentinel Errors

Use when:
- Callers need to distinguish specific error conditions
- Error is part of API contract
- No additional context needed

Avoid when:
- Error contains dynamic data
- Error is implementation detail
- Custom error type provides more value

## Custom Error Types

### Basic Custom Error

```go
type ValidationError struct {
    Field   string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation failed on %s: %s", e.Field, e.Message)
}
```

### Error with Cause

```go
type QueryError struct {
    Query string
    Err   error
}

func (e *QueryError) Error() string {
    return fmt.Sprintf("query %q failed: %v", e.Query, e.Err)
}

func (e *QueryError) Unwrap() error {
    return e.Err
}
```

### Error with Multiple Causes

```go
type MultiError struct {
    Errors []error
}

func (e *MultiError) Error() string {
    var msgs []string
    for _, err := range e.Errors {
        msgs = append(msgs, err.Error())
    }
    return strings.Join(msgs, "; ")
}

// Go 1.20+: Implement Unwrap() []error for errors.Is/As support
func (e *MultiError) Unwrap() []error {
    return e.Errors
}
```

### Checking Custom Errors

```go
result, err := validate(input)
if err != nil {
    var valErr *ValidationError
    if errors.As(err, &valErr) {
        return fmt.Errorf("field %s is invalid: %s", valErr.Field, valErr.Message)
    }
    return err
}
```

## Panic and Recover

### When to Panic

```go
// Panic for programmer errors (impossible states)
func mustParseTemplate(s string) *template.Template {
    t, err := template.Parse(s)
    if err != nil {
        panic(fmt.Sprintf("template parse error: %v", err))
    }
    return t
}

// Panic for invariant violations
func (s *Stack) Pop() interface{} {
    if len(s.items) == 0 {
        panic("pop from empty stack")  // Programmer error
    }
    // ...
}
```

### When NOT to Panic

```go
// Don't panic for recoverable errors
// Bad:
func ReadConfig(path string) *Config {
    data, err := os.ReadFile(path)
    if err != nil {
        panic(err)  // Bad! File not found is recoverable
    }
}

// Good:
func ReadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("reading config: %w", err)
    }
    // ...
}
```

### Recover from Panics

```go
func safeOperation() (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic recovered: %v", r)
        }
    }()

    riskyOperation()
    return nil
}

// HTTP middleware example
func recoveryMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                log.Printf("panic: %v\n%s", err, debug.Stack())
                http.Error(w, "Internal Server Error", 500)
            }
        }()
        next.ServeHTTP(w, r)
    })
}
```

## Errors in Goroutines

### Channel-Based Error Handling

```go
func processItems(items []Item) error {
    errs := make(chan error, len(items))
    var wg sync.WaitGroup

    for _, item := range items {
        wg.Add(1)
        go func(it Item) {
            defer wg.Done()
            if err := process(it); err != nil {
                errs <- err
            }
        }(item)
    }

    wg.Wait()
    close(errs)

    // Collect errors
    var allErrs []error
    for err := range errs {
        allErrs = append(allErrs, err)
    }

    if len(allErrs) > 0 {
        return &MultiError{Errors: allErrs}
    }
    return nil
}
```

### errgroup Package

```go
import "golang.org/x/sync/errgroup"

func processWithErrgroup(ctx context.Context, items []Item) error {
    g, ctx := errgroup.WithContext(ctx)

    for _, item := range items {
        item := item  // Capture for goroutine (pre-Go 1.22)
        g.Go(func() error {
            return processItem(ctx, item)
        })
    }

    // Wait for all and return first error
    return g.Wait()
}

// With concurrency limit
func processWithLimit(items []Item) error {
    g := new(errgroup.Group)
    g.SetLimit(10)  // Max 10 concurrent

    for _, item := range items {
        item := item
        g.Go(func() error {
            return processItem(item)
        })
    }

    return g.Wait()
}
```

### Result Type Pattern

```go
type Result struct {
    Value string
    Err   error
}

func fetchAll(urls []string) []Result {
    results := make([]Result, len(urls))
    var wg sync.WaitGroup

    for i, url := range urls {
        wg.Add(1)
        go func(idx int, u string) {
            defer wg.Done()
            val, err := fetch(u)
            results[idx] = Result{Value: val, Err: err}
        }(i, url)
    }

    wg.Wait()
    return results
}
```
