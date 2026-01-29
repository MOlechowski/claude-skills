---
name: go-pprof
description: "[Go] Profiler: CPU profiling, memory allocation, goroutine analysis, block profiling, mutex contention. Use for: performance optimization, memory leaks, goroutine leaks. Triggers: pprof, go profile, cpu profile, memory profile, heap profile."
---

# pprof

Go's built-in profiling tool for CPU, memory, goroutine, and contention analysis.

## Enabling Profiling

### HTTP Server (net/http/pprof)

```go
import _ "net/http/pprof"

func main() {
    // Add pprof endpoints to default mux
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()

    // Your application code
}
```

Available endpoints:
- `/debug/pprof/` - Index page
- `/debug/pprof/profile` - CPU profile
- `/debug/pprof/heap` - Heap profile
- `/debug/pprof/goroutine` - Goroutine profile
- `/debug/pprof/block` - Block profile
- `/debug/pprof/mutex` - Mutex profile
- `/debug/pprof/trace` - Execution trace

### Programmatic (runtime/pprof)

```go
import "runtime/pprof"

// CPU Profile
f, _ := os.Create("cpu.prof")
pprof.StartCPUProfile(f)
defer pprof.StopCPUProfile()

// Memory Profile
f, _ := os.Create("mem.prof")
defer f.Close()
runtime.GC()  // Get accurate stats
pprof.WriteHeapProfile(f)
```

### Test Profiling

```bash
# CPU profile
go test -cpuprofile=cpu.prof -bench=.

# Memory profile
go test -memprofile=mem.prof -bench=.

# Both
go test -cpuprofile=cpu.prof -memprofile=mem.prof -bench=.
```

## CPU Profiling

### Collect Profile

```bash
# From HTTP endpoint (30 seconds)
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# From file
go tool pprof cpu.prof

# From binary + profile
go tool pprof ./myapp cpu.prof
```

### Analyze

```
# Top functions by CPU
(pprof) top
(pprof) top10
(pprof) top -cum    # Cumulative time

# Show function source
(pprof) list main.handleRequest

# Show disassembly
(pprof) disasm main.handleRequest

# Web visualization (opens browser)
(pprof) web

# Generate SVG
(pprof) svg > cpu.svg

# Generate flame graph
(pprof) web flamegraph
```

### One-Liner

```bash
# Interactive mode
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=10

# Direct output
go tool pprof -top http://localhost:6060/debug/pprof/profile?seconds=10
go tool pprof -svg http://localhost:6060/debug/pprof/profile?seconds=10 > cpu.svg
```

## Memory Profiling

### Heap Profile

```bash
# Collect heap profile
go tool pprof http://localhost:6060/debug/pprof/heap

# With allocation space (bytes)
go tool pprof -alloc_space http://localhost:6060/debug/pprof/heap

# With allocation objects (count)
go tool pprof -alloc_objects http://localhost:6060/debug/pprof/heap

# In-use space (current)
go tool pprof -inuse_space http://localhost:6060/debug/pprof/heap
```

### Sample Types

| Type | Description |
|------|-------------|
| inuse_space | Current memory in use (bytes) |
| inuse_objects | Current objects in use (count) |
| alloc_space | Total allocated (bytes) since start |
| alloc_objects | Total allocated (count) since start |

### Find Memory Leaks

```bash
# Compare two heap profiles
go tool pprof -base heap1.prof heap2.prof

# In interactive mode
(pprof) top -diff_base=heap1.prof
```

## Goroutine Profiling

### Collect Profile

```bash
# Current goroutines
go tool pprof http://localhost:6060/debug/pprof/goroutine

# Full stack dump
curl http://localhost:6060/debug/pprof/goroutine?debug=2
```

### Analyze

```
(pprof) top
(pprof) traces    # Show all stacks
(pprof) web
```

### Find Goroutine Leaks

```go
// In code: track goroutine count
import "runtime"

func logGoroutines() {
    log.Printf("goroutines: %d", runtime.NumGoroutine())
}
```

## Block Profiling

Block profiling shows where goroutines block waiting on synchronization.

### Enable

```go
import "runtime"

// Enable block profiling (rate in nanoseconds)
runtime.SetBlockProfileRate(1)  // All events
runtime.SetBlockProfileRate(1000000)  // 1ms+ events
```

### Collect

```bash
go tool pprof http://localhost:6060/debug/pprof/block
```

## Mutex Profiling

Shows mutex contention.

### Enable

```go
import "runtime"

runtime.SetMutexProfileFraction(1)  // All events
runtime.SetMutexProfileFraction(5)  // 1/5 events
```

### Collect

```bash
go tool pprof http://localhost:6060/debug/pprof/mutex
```

## Execution Trace

More detailed than profiling - shows exact event timing.

### Collect

```bash
# Collect trace
curl -o trace.out http://localhost:6060/debug/pprof/trace?seconds=5

# View
go tool trace trace.out
```

### In Tests

```bash
go test -trace=trace.out .
go tool trace trace.out
```

## pprof Commands

| Command | Description |
|---------|-------------|
| top [n] | Top n functions |
| top -cum | Sort by cumulative |
| list func | Source for function |
| disasm func | Disassembly |
| web | Open in browser |
| svg | Generate SVG |
| png | Generate PNG |
| text | Text report |
| traces | Show all traces |
| peek func | Show callers/callees |

## Output Formats

```bash
# In interactive mode
(pprof) svg > output.svg
(pprof) png > output.png
(pprof) text > output.txt

# Command line
go tool pprof -svg cpu.prof > cpu.svg
go tool pprof -png cpu.prof > cpu.png
go tool pprof -text cpu.prof
go tool pprof -top cpu.prof
```

## Continuous Profiling

### Simple Approach

```go
import (
    "os"
    "os/signal"
    "runtime/pprof"
)

func enableProfilingOnSignal() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGUSR1)

    go func() {
        for range c {
            f, _ := os.Create("cpu.prof")
            pprof.StartCPUProfile(f)
            time.Sleep(30 * time.Second)
            pprof.StopCPUProfile()
            f.Close()
        }
    }()
}
```

### Production Services

- **Pyroscope**: Continuous profiling platform
- **Parca**: Open source continuous profiling
- **Google Cloud Profiler**: For GCP workloads
- **Datadog Continuous Profiler**: With Datadog APM

## Best Practices

1. **CPU Profile**: Run under realistic load
2. **Memory Profile**: Call `runtime.GC()` before heap profile for accuracy
3. **Block/Mutex**: Set reasonable rates to avoid overhead
4. **Production**: Use low sample rates or triggered profiling
5. **Comparison**: Always compare before/after profiles

## Common Patterns

### Profile in Tests

```go
func BenchmarkFoo(b *testing.B) {
    for i := 0; i < b.N; i++ {
        foo()
    }
}
```

```bash
go test -bench=BenchmarkFoo -cpuprofile=cpu.prof
go tool pprof -http=:8080 cpu.prof
```

### HTTP Handler Wrapper

```go
func profileHandler(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Query().Get("profile") == "cpu" {
            f, _ := os.CreateTemp("", "cpu*.prof")
            pprof.StartCPUProfile(f)
            defer func() {
                pprof.StopCPUProfile()
                f.Close()
            }()
        }
        h.ServeHTTP(w, r)
    })
}
```
