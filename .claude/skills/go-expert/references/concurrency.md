# Go Concurrency Patterns

## Table of Contents
- [Goroutine Lifecycle](#goroutine-lifecycle)
- [Channel Patterns](#channel-patterns)
- [sync Package](#sync-package)
- [Context Usage](#context-usage)
- [Worker Pools](#worker-pools)
- [Race Condition Debugging](#race-condition-debugging)

## Goroutine Lifecycle

### Creating Goroutines

```go
// Simple goroutine
go func() {
    doWork()
}()

// Goroutine with parameters (avoid closure capture issues)
go func(data string) {
    process(data)
}(myData)
```

### Goroutine Leaks

Common causes and solutions:

```go
// LEAK: Blocked channel send with no receiver
go func() {
    ch <- result  // Blocks forever if nothing reads
}()

// FIX: Use buffered channel or select with timeout
go func() {
    select {
    case ch <- result:
    case <-time.After(5 * time.Second):
        log.Println("timeout sending result")
    }
}()

// LEAK: Infinite loop without exit condition
go func() {
    for {
        doWork()  // Never exits
    }
}()

// FIX: Use context for cancellation
go func(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
            doWork()
        }
    }
}(ctx)
```

### Detecting Goroutine Leaks

```go
// In tests
import "runtime"

func TestNoLeak(t *testing.T) {
    before := runtime.NumGoroutine()

    // Run test code

    // Allow time for cleanup
    time.Sleep(100 * time.Millisecond)

    after := runtime.NumGoroutine()
    if after > before {
        t.Errorf("goroutine leak: %d -> %d", before, after)
    }
}
```

## Channel Patterns

### Fan-Out (1 sender, N receivers)

```go
func fanOut(input <-chan int, workers int) []<-chan int {
    outputs := make([]<-chan int, workers)
    for i := 0; i < workers; i++ {
        out := make(chan int)
        outputs[i] = out
        go func(in <-chan int, out chan<- int) {
            defer close(out)
            for v := range in {
                out <- process(v)
            }
        }(input, out)
    }
    return outputs
}
```

### Fan-In (N senders, 1 receiver)

```go
func fanIn(inputs ...<-chan int) <-chan int {
    out := make(chan int)
    var wg sync.WaitGroup

    for _, ch := range inputs {
        wg.Add(1)
        go func(c <-chan int) {
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
```

### Pipeline

```go
func pipeline() {
    // Stage 1: Generate
    gen := func(nums ...int) <-chan int {
        out := make(chan int)
        go func() {
            defer close(out)
            for _, n := range nums {
                out <- n
            }
        }()
        return out
    }

    // Stage 2: Square
    sq := func(in <-chan int) <-chan int {
        out := make(chan int)
        go func() {
            defer close(out)
            for n := range in {
                out <- n * n
            }
        }()
        return out
    }

    // Use pipeline
    for n := range sq(sq(gen(2, 3))) {
        fmt.Println(n)  // 16, 81
    }
}
```

### Semaphore (Limit Concurrency)

```go
func processWithLimit(items []Item, maxConcurrent int) {
    sem := make(chan struct{}, maxConcurrent)
    var wg sync.WaitGroup

    for _, item := range items {
        wg.Add(1)
        sem <- struct{}{}  // Acquire

        go func(it Item) {
            defer wg.Done()
            defer func() { <-sem }()  // Release

            process(it)
        }(item)
    }

    wg.Wait()
}
```

### Or-Done Channel

```go
func orDone(done <-chan struct{}, c <-chan int) <-chan int {
    out := make(chan int)
    go func() {
        defer close(out)
        for {
            select {
            case <-done:
                return
            case v, ok := <-c:
                if !ok {
                    return
                }
                select {
                case out <- v:
                case <-done:
                    return
                }
            }
        }
    }()
    return out
}
```

### First-Response Pattern

```go
func queryFirst(ctx context.Context, urls []string) (string, error) {
    ctx, cancel := context.WithCancel(ctx)
    defer cancel()

    results := make(chan string, len(urls))

    for _, url := range urls {
        go func(u string) {
            if resp, err := fetch(ctx, u); err == nil {
                results <- resp
            }
        }(url)
    }

    select {
    case result := <-results:
        return result, nil
    case <-ctx.Done():
        return "", ctx.Err()
    }
}
```

## sync Package

### Mutex

```go
type SafeCounter struct {
    mu    sync.Mutex
    count int
}

func (c *SafeCounter) Inc() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.count++
}

func (c *SafeCounter) Value() int {
    c.mu.Lock()
    defer c.mu.Unlock()
    return c.count
}
```

### RWMutex

```go
type Cache struct {
    mu    sync.RWMutex
    items map[string]string
}

func (c *Cache) Get(key string) (string, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    v, ok := c.items[key]
    return v, ok
}

func (c *Cache) Set(key, value string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.items[key] = value
}
```

### WaitGroup

```go
func processAll(items []Item) {
    var wg sync.WaitGroup

    for _, item := range items {
        wg.Add(1)
        go func(it Item) {
            defer wg.Done()
            process(it)
        }(item)
    }

    wg.Wait()
}
```

### Once

```go
var (
    instance *Config
    once     sync.Once
)

func GetConfig() *Config {
    once.Do(func() {
        instance = loadConfig()
    })
    return instance
}
```

### Pool

```go
var bufPool = sync.Pool{
    New: func() interface{} {
        return new(bytes.Buffer)
    },
}

func process(data []byte) {
    buf := bufPool.Get().(*bytes.Buffer)
    defer func() {
        buf.Reset()
        bufPool.Put(buf)
    }()

    buf.Write(data)
    // Use buffer
}
```

### Map

```go
var cache sync.Map

func Get(key string) (interface{}, bool) {
    return cache.Load(key)
}

func Set(key string, value interface{}) {
    cache.Store(key, value)
}

func GetOrCreate(key string, create func() interface{}) interface{} {
    val, loaded := cache.LoadOrStore(key, create())
    if !loaded {
        // Value was created
    }
    return val
}
```

### Cond

```go
type Queue struct {
    mu    sync.Mutex
    cond  *sync.Cond
    items []int
}

func NewQueue() *Queue {
    q := &Queue{}
    q.cond = sync.NewCond(&q.mu)
    return q
}

func (q *Queue) Push(item int) {
    q.mu.Lock()
    defer q.mu.Unlock()
    q.items = append(q.items, item)
    q.cond.Signal()  // Wake one waiter
}

func (q *Queue) Pop() int {
    q.mu.Lock()
    defer q.mu.Unlock()
    for len(q.items) == 0 {
        q.cond.Wait()  // Release lock and wait
    }
    item := q.items[0]
    q.items = q.items[1:]
    return item
}
```

## Context Usage

### Creating Contexts

```go
// Root context
ctx := context.Background()

// With cancellation
ctx, cancel := context.WithCancel(ctx)
defer cancel()

// With timeout
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

// With deadline
deadline := time.Now().Add(30 * time.Second)
ctx, cancel := context.WithDeadline(ctx, deadline)
defer cancel()

// With value (use sparingly)
ctx = context.WithValue(ctx, requestIDKey, "12345")
```

### Checking Cancellation

```go
func doWork(ctx context.Context) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()  // context.Canceled or context.DeadlineExceeded
        default:
            // Do one unit of work
            if err := processItem(); err != nil {
                return err
            }
        }
    }
}
```

### Propagating Context

```go
func handler(ctx context.Context) error {
    // Add timeout for this operation
    ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()

    // Pass to downstream calls
    result, err := fetchData(ctx)
    if err != nil {
        return err
    }

    return processResult(ctx, result)
}
```

## Worker Pools

### Fixed Worker Pool

```go
func workerPool(jobs <-chan Job, results chan<- Result, numWorkers int) {
    var wg sync.WaitGroup

    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            for job := range jobs {
                result := process(job)
                results <- result
            }
        }(i)
    }

    wg.Wait()
    close(results)
}
```

### Worker Pool with Context

```go
func workerPoolWithContext(ctx context.Context, jobs <-chan Job, numWorkers int) <-chan Result {
    results := make(chan Result)
    var wg sync.WaitGroup

    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for {
                select {
                case <-ctx.Done():
                    return
                case job, ok := <-jobs:
                    if !ok {
                        return
                    }
                    select {
                    case results <- process(job):
                    case <-ctx.Done():
                        return
                    }
                }
            }
        }()
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    return results
}
```

## Race Condition Debugging

### Race Detector

```bash
# Run tests with race detector
go test -race ./...

# Build with race detector
go build -race

# Run with race detector
go run -race main.go
```

### Common Race Patterns

```go
// RACE: Shared variable without synchronization
var counter int
go func() { counter++ }()
go func() { counter++ }()

// FIX: Use atomic
var counter int64
go func() { atomic.AddInt64(&counter, 1) }()
go func() { atomic.AddInt64(&counter, 1) }()

// RACE: Map concurrent access
m := make(map[string]int)
go func() { m["a"] = 1 }()
go func() { _ = m["a"] }()

// FIX: Use sync.Map or mutex
var mu sync.Mutex
go func() {
    mu.Lock()
    m["a"] = 1
    mu.Unlock()
}()
```

### Atomic Operations

```go
import "sync/atomic"

var (
    counter int64
    flag    int32
)

// Increment
atomic.AddInt64(&counter, 1)

// Load/Store
val := atomic.LoadInt64(&counter)
atomic.StoreInt64(&counter, 100)

// Compare and Swap
if atomic.CompareAndSwapInt32(&flag, 0, 1) {
    // Successfully changed from 0 to 1
}
```
