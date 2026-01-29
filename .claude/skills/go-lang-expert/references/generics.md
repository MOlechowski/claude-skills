# Go Generics

## Table of Contents
- [Type Parameter Syntax](#type-parameter-syntax)
- [Constraints](#constraints)
- [When to Use Generics](#when-to-use-generics)
- [Common Patterns](#common-patterns)
- [Type Inference](#type-inference)
- [Limitations and Gotchas](#limitations-and-gotchas)
- [Real-World Examples](#real-world-examples)

## Type Parameter Syntax

### Generic Functions

```go
// Single type parameter
func Print[T any](v T) {
    fmt.Println(v)
}

// Multiple type parameters
func Pair[K, V any](key K, val V) (K, V) {
    return key, val
}

// Usage
Print[int](42)        // Explicit type
Print("hello")        // Type inferred
```

### Generic Types

```go
// Generic struct
type Stack[T any] struct {
    items []T
}

func (s *Stack[T]) Push(v T) {
    s.items = append(s.items, v)
}

func (s *Stack[T]) Pop() (T, bool) {
    if len(s.items) == 0 {
        var zero T
        return zero, false
    }
    v := s.items[len(s.items)-1]
    s.items = s.items[:len(s.items)-1]
    return v, true
}

// Usage
stack := Stack[int]{}
stack.Push(1)
```

### Generic Interfaces

```go
type Container[T any] interface {
    Add(T)
    Get() T
}
```

## Constraints

### Built-in Constraints

```go
import "constraints"  // golang.org/x/exp/constraints

// any - accepts any type (alias for interface{})
func Print[T any](v T) { ... }

// comparable - supports == and !=
func Equal[T comparable](a, b T) bool {
    return a == b
}

// constraints.Ordered - supports < > <= >=
func Max[T constraints.Ordered](a, b T) T {
    if a > b {
        return a
    }
    return b
}

// constraints.Integer, constraints.Float, constraints.Signed, etc.
```

### Custom Constraints

```go
// Interface constraint
type Stringer interface {
    String() string
}

func PrintString[T Stringer](v T) {
    fmt.Println(v.String())
}

// Type set constraint
type Number interface {
    int | int8 | int16 | int32 | int64 |
    uint | uint8 | uint16 | uint32 | uint64 |
    float32 | float64
}

func Sum[T Number](nums []T) T {
    var sum T
    for _, n := range nums {
        sum += n
    }
    return sum
}

// Approximation constraint (~)
type Integer interface {
    ~int | ~int8 | ~int16 | ~int32 | ~int64
}

type MyInt int  // Satisfies ~int

func Double[T Integer](v T) T {
    return v * 2
}

Double(MyInt(5))  // Works!
```

### Combining Constraints

```go
// Intersection: must satisfy both
type PrintableNumber interface {
    Number
    fmt.Stringer
}

// Multiple methods
type ReadWriter interface {
    Read([]byte) (int, error)
    Write([]byte) (int, error)
}
```

## When to Use Generics

### Good Use Cases

```go
// 1. Container types
type Set[T comparable] struct {
    m map[T]struct{}
}

// 2. Algorithms operating on collections
func Filter[T any](s []T, f func(T) bool) []T

// 3. Type-safe APIs
type Result[T any] struct {
    Value T
    Err   error
}

// 4. Utility functions
func Keys[K comparable, V any](m map[K]V) []K
func Values[K comparable, V any](m map[K]V) []V
```

### When NOT to Use

```go
// 1. When interface{} or any is sufficient
func PrintAny(v any) { fmt.Println(v) }  // Fine without generics

// 2. When io.Reader/Writer pattern works
func Process(r io.Reader) error  // Interface is better

// 3. Single concrete type
func ProcessUsers(users []User) error  // No need for generics

// 4. When it complicates without benefit
// Bad: Over-generic
func Get[T any](m map[string]T, key string) (T, bool)
// Often just use map[string]YourType directly
```

### Decision Guide

| Situation | Use |
|-----------|-----|
| Same logic for int, float, string | Generics |
| Container/collection types | Generics |
| Different types need different methods | Interface |
| Single type | Concrete type |
| I/O operations | io.Reader/Writer |

## Common Patterns

### Generic Slice Operations

```go
func Map[T, U any](s []T, f func(T) U) []U {
    result := make([]U, len(s))
    for i, v := range s {
        result[i] = f(v)
    }
    return result
}

func Filter[T any](s []T, f func(T) bool) []T {
    var result []T
    for _, v := range s {
        if f(v) {
            result = append(result, v)
        }
    }
    return result
}

func Reduce[T, U any](s []T, init U, f func(U, T) U) U {
    result := init
    for _, v := range s {
        result = f(result, v)
    }
    return result
}

// Usage
nums := []int{1, 2, 3, 4, 5}
doubled := Map(nums, func(n int) int { return n * 2 })
evens := Filter(nums, func(n int) bool { return n%2 == 0 })
sum := Reduce(nums, 0, func(a, b int) int { return a + b })
```

### Generic Map Operations

```go
func Keys[K comparable, V any](m map[K]V) []K {
    keys := make([]K, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    return keys
}

func Values[K comparable, V any](m map[K]V) []V {
    vals := make([]V, 0, len(m))
    for _, v := range m {
        vals = append(vals, v)
    }
    return vals
}

func MapKeys[K comparable, V any, K2 comparable](m map[K]V, f func(K) K2) map[K2]V {
    result := make(map[K2]V, len(m))
    for k, v := range m {
        result[f(k)] = v
    }
    return result
}
```

### Generic Channel Operations

```go
func Merge[T any](chs ...<-chan T) <-chan T {
    out := make(chan T)
    var wg sync.WaitGroup

    for _, ch := range chs {
        wg.Add(1)
        go func(c <-chan T) {
            defer wg.Done()
            for v := range c {
                out <- v
            }
        }(ch)
    }

    go func() {
        wg.Wait()
        close(out)
    }()

    return out
}

func SendAll[T any](ch chan<- T, items []T) {
    for _, item := range items {
        ch <- item
    }
}
```

### Optional/Result Pattern

```go
type Optional[T any] struct {
    value T
    valid bool
}

func Some[T any](v T) Optional[T] {
    return Optional[T]{value: v, valid: true}
}

func None[T any]() Optional[T] {
    return Optional[T]{}
}

func (o Optional[T]) Get() (T, bool) {
    return o.value, o.valid
}

func (o Optional[T]) OrElse(def T) T {
    if o.valid {
        return o.value
    }
    return def
}
```

## Type Inference

### When Inference Works

```go
// Inferred from arguments
func First[T any](s []T) T { return s[0] }
First([]int{1, 2, 3})  // T inferred as int

// Inferred from return type assignment
func Zero[T any]() T { var z T; return z }
var x int = Zero[int]()  // Must specify - can't infer from assignment
```

### When Explicit Types Needed

```go
// No arguments to infer from
Zero[int]()

// Ambiguous inference
func Convert[T, U any](v T) U { ... }
Convert[int, string](42)  // Must specify both

// Struct literal
Stack[int]{}  // Must specify type parameter
```

## Limitations and Gotchas

### No Method Type Parameters

```go
// INVALID: Methods cannot have their own type parameters
type Container struct{}

func (c Container) Map[T, U any](f func(T) U) {}  // Error!

// VALID: Type parameters on the type
type Container[T any] struct{}

func (c Container[T]) Values() []T {}  // OK
```

### No Operator Overloading

```go
// Cannot use + with type parameter unless constrained
func Add[T any](a, b T) T {
    return a + b  // Error: operator + not defined on T
}

// Must use constraint
func Add[T constraints.Ordered](a, b T) T {
    return a + b  // OK for numeric types
}
```

### No Type Assertions on Type Parameters

```go
func Convert[T any](v T) {
    // Cannot do type assertion on T
    s := v.(string)  // Error!

    // Must use any first (loses type safety)
    s := any(v).(string)  // Works but risky
}
```

### Zero Value Gotcha

```go
func GetOrDefault[T any](m map[string]T, key string, def T) T {
    if v, ok := m[key]; ok {
        return v
    }
    return def
}

// Must pass explicit default - no way to get "zero of T" easily
result := GetOrDefault(m, "key", "")  // Must pass "" for string

// Getting zero value
func Zero[T any]() T {
    var zero T
    return zero
}
```

### Pointer Constraints

```go
// Want to call method that requires pointer receiver
type Setter interface {
    Set(int)
}

// This won't work as expected
func CallSet[T Setter](v T) {
    v.Set(42)
}

// Solution: Constrain to pointer type
func CallSet[T any, PT interface{ *T; Setter }](v *T) {
    PT(v).Set(42)
}
```

## Real-World Examples

### Thread-Safe Cache

```go
type Cache[K comparable, V any] struct {
    mu    sync.RWMutex
    items map[K]V
}

func NewCache[K comparable, V any]() *Cache[K, V] {
    return &Cache[K, V]{
        items: make(map[K]V),
    }
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    v, ok := c.items[key]
    return v, ok
}

func (c *Cache[K, V]) Set(key K, value V) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.items[key] = value
}
```

### Generic Repository

```go
type Entity interface {
    GetID() string
}

type Repository[T Entity] struct {
    items map[string]T
}

func NewRepository[T Entity]() *Repository[T] {
    return &Repository[T]{
        items: make(map[string]T),
    }
}

func (r *Repository[T]) Save(entity T) {
    r.items[entity.GetID()] = entity
}

func (r *Repository[T]) FindByID(id string) (T, bool) {
    entity, ok := r.items[id]
    return entity, ok
}

func (r *Repository[T]) FindAll() []T {
    result := make([]T, 0, len(r.items))
    for _, e := range r.items {
        result = append(result, e)
    }
    return result
}
```

### Pagination

```go
type Page[T any] struct {
    Items      []T
    TotalCount int
    PageSize   int
    PageNum    int
}

func (p Page[T]) HasNext() bool {
    return p.PageNum*p.PageSize < p.TotalCount
}

func (p Page[T]) TotalPages() int {
    return (p.TotalCount + p.PageSize - 1) / p.PageSize
}

func Paginate[T any](items []T, pageSize, pageNum int) Page[T] {
    start := (pageNum - 1) * pageSize
    end := start + pageSize
    if end > len(items) {
        end = len(items)
    }
    if start > len(items) {
        start = len(items)
    }

    return Page[T]{
        Items:      items[start:end],
        TotalCount: len(items),
        PageSize:   pageSize,
        PageNum:    pageNum,
    }
}
```
