# Go Gotchas

Common pitfalls and their solutions.

## Table of Contents
- [Loop Variable Capture](#loop-variable-capture)
- [nil Interface vs nil Concrete](#nil-interface-vs-nil-concrete)
- [Slice Gotchas](#slice-gotchas)
- [defer Behavior](#defer-behavior)
- [Map Concurrent Access](#map-concurrent-access)
- [String and Byte Conversion](#string-and-byte-conversion)
- [Pointer vs Value Receivers](#pointer-vs-value-receivers)
- [Named Return Values](#named-return-values)
- [Interface Satisfaction](#interface-satisfaction)

## Loop Variable Capture

### The Problem (pre-Go 1.22)

```go
// BUG: All goroutines see same value
funcs := []func(){}
for _, v := range []int{1, 2, 3} {
    funcs = append(funcs, func() {
        fmt.Println(v)  // All print 3!
    })
}
```

### Solution (pre-Go 1.22)

```go
// Fix 1: Copy variable
for _, v := range []int{1, 2, 3} {
    v := v  // Shadow with local copy
    funcs = append(funcs, func() {
        fmt.Println(v)  // Correct: 1, 2, 3
    })
}

// Fix 2: Pass as parameter
for _, v := range []int{1, 2, 3} {
    funcs = append(funcs, func(n int) func() {
        return func() { fmt.Println(n) }
    }(v))
}
```

### Go 1.22+ Fix

```go
// Go 1.22+ automatically creates new variable each iteration
for _, v := range []int{1, 2, 3} {
    funcs = append(funcs, func() {
        fmt.Println(v)  // Correct: 1, 2, 3
    })
}
```

## nil Interface vs nil Concrete

### The Problem

```go
type MyError struct{ msg string }
func (e *MyError) Error() string { return e.msg }

func returnsError() error {
    var err *MyError = nil
    return err  // Returns non-nil interface!
}

func main() {
    err := returnsError()
    if err != nil {
        fmt.Println("not nil!")  // This prints!
    }
}
```

### Why It Happens

```go
// Interface has two components: (type, value)
// nil interface: (nil, nil)
// interface with nil concrete: (*MyError, nil) - NOT nil!

var e error = nil           // (nil, nil) - is nil
var e error = (*MyError)(nil)  // (*MyError, nil) - NOT nil!
```

### Solution

```go
// Return nil explicitly
func returnsError() error {
    var err *MyError = nil
    if err == nil {
        return nil  // Return nil explicitly
    }
    return err
}

// Or check concrete type
func checkError(err error) bool {
    if err == nil {
        return false
    }
    // Also check if concrete value is nil
    v := reflect.ValueOf(err)
    return !v.IsNil()
}
```

## Slice Gotchas

### Append May Allocate

```go
// Original slice has capacity 3
s := make([]int, 3, 3)
s[0], s[1], s[2] = 1, 2, 3

s2 := s[:2]              // Shares backing array
s2 = append(s2, 4)       // Modifies s[2]!
fmt.Println(s)           // [1 2 4] - modified!

// With larger append
s2 = append(s2, 5, 6, 7) // New allocation
// s is unchanged, s2 has new backing array
```

### Solution: Pre-allocate or Copy

```go
// Pre-allocate with known size
s := make([]int, 0, expectedSize)

// Copy to avoid sharing
s2 := make([]int, len(s))
copy(s2, s)

// Or use slices.Clone (Go 1.21+)
s2 := slices.Clone(s)
```

### Slice Header Gotcha

```go
func modify(s []int) {
    s[0] = 100  // Modifies original!
    s = append(s, 200)  // Doesn't affect original
}

// Slice is a header (ptr, len, cap)
// Passed by value - modifications to elements visible
// But reassignment (from append) is local
```

### Memory Leak with Subslice

```go
// Large slice
data := make([]byte, 1<<20)  // 1MB

// Small subslice still references 1MB
small := data[:10]

// Fix: Copy to new slice
small := make([]byte, 10)
copy(small, data[:10])
```

## defer Behavior

### Arguments Evaluated Immediately

```go
func example() {
    x := 1
    defer fmt.Println(x)  // Prints 1, not 2
    x = 2
}
```

### Fix: Use Closure

```go
func example() {
    x := 1
    defer func() {
        fmt.Println(x)  // Prints 2
    }()
    x = 2
}
```

### defer in Loop

```go
// BUG: All defers accumulate until function returns
func processFiles(paths []string) error {
    for _, path := range paths {
        f, err := os.Open(path)
        if err != nil {
            return err
        }
        defer f.Close()  // Won't close until function returns!
    }
    return nil
}

// FIX: Extract to function
func processFiles(paths []string) error {
    for _, path := range paths {
        if err := processFile(path); err != nil {
            return err
        }
    }
    return nil
}

func processFile(path string) error {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    defer f.Close()
    // ...
    return nil
}
```

### defer Order

```go
func example() {
    defer fmt.Println("first")
    defer fmt.Println("second")
    defer fmt.Println("third")
}
// Output: third, second, first (LIFO)
```

## Map Concurrent Access

### The Problem

```go
// RACE CONDITION
m := make(map[string]int)

go func() { m["a"] = 1 }()
go func() { _ = m["a"] }()

// Will panic or produce undefined behavior
```

### Solution 1: sync.Mutex

```go
type SafeMap struct {
    mu sync.RWMutex
    m  map[string]int
}

func (s *SafeMap) Get(key string) int {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return s.m[key]
}

func (s *SafeMap) Set(key string, value int) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.m[key] = value
}
```

### Solution 2: sync.Map

```go
var m sync.Map

m.Store("key", "value")
v, ok := m.Load("key")
m.Delete("key")

// Good for: many reads, few writes, disjoint key access
```

## String and Byte Conversion

### String Iteration

```go
s := "hello世界"

// Iterates RUNES (Unicode code points), not bytes
for i, r := range s {
    fmt.Printf("%d: %c\n", i, r)
}
// 0: h, 1: e, 2: l, 3: l, 4: o, 5: 世, 8: 界
// Note: indices 5 and 8 - runes can be multi-byte!

// For bytes
for i := 0; i < len(s); i++ {
    fmt.Printf("%d: %x\n", i, s[i])
}
```

### Conversion Copies Data

```go
s := "hello"
b := []byte(s)  // Allocates and copies

b[0] = 'H'      // Doesn't modify s
fmt.Println(s)  // "hello" (unchanged)
```

### Efficient String Building

```go
// Bad: O(n²) - creates new string each iteration
var s string
for i := 0; i < 1000; i++ {
    s += "x"
}

// Good: O(n) - uses builder
var sb strings.Builder
for i := 0; i < 1000; i++ {
    sb.WriteString("x")
}
s := sb.String()
```

## Pointer vs Value Receivers

### Inconsistent Receivers

```go
type Counter struct {
    value int
}

// Value receiver - doesn't modify original
func (c Counter) IncrementWrong() {
    c.value++  // Modifies copy!
}

// Pointer receiver - modifies original
func (c *Counter) Increment() {
    c.value++  // Modifies actual Counter
}
```

### Interface Satisfaction

```go
type Incrementer interface {
    Increment()
}

// Only *Counter satisfies Incrementer
var _ Incrementer = &Counter{}  // OK
var _ Incrementer = Counter{}   // Error!
```

### Rule of Thumb

```go
// Use pointer receiver when:
// - Method modifies receiver
// - Receiver is large struct
// - Consistency (if any method needs pointer, use pointer for all)

// Use value receiver when:
// - Receiver is small, immutable type (time.Time, etc.)
// - Method doesn't modify receiver
// - Receiver is map, chan, func (already reference types)
```

## Named Return Values

### Shadowing Bug

```go
func example() (err error) {
    if condition {
        err := doSomething()  // Shadows named return!
        if err != nil {
            return  // Returns nil, not err!
        }
    }
    return
}

// Fix: Use assignment, not declaration
func example() (err error) {
    if condition {
        err = doSomething()  // Assigns to named return
        if err != nil {
            return
        }
    }
    return
}
```

### defer with Named Returns

```go
func example() (result int, err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic: %v", r)
        }
    }()

    result = riskyOperation()
    return
}
// Named returns allow defer to modify return values
```

## Interface Satisfaction

### Implicit Satisfaction

```go
// No "implements" keyword needed
type Reader interface {
    Read(p []byte) (n int, err error)
}

type MyReader struct{}

func (r *MyReader) Read(p []byte) (n int, err error) {
    // Implementation
}

// *MyReader automatically satisfies Reader
```

### Compile-Time Check

```go
// Verify type satisfies interface at compile time
var _ io.Reader = (*MyReader)(nil)
var _ io.Writer = (*MyWriter)(nil)

// If interface not satisfied, compilation fails
```

### Empty Interface Gotcha

```go
// any/interface{} matches everything
func process(v any) {
    // Must type assert to use
    s, ok := v.(string)
    if !ok {
        // Handle non-string
    }
}

// Prefer specific interfaces when possible
func process(r io.Reader) {
    // Can use r.Read() directly
}
```
