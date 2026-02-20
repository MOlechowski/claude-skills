# Go Testing

## Table of Contents
- [Table-Driven Tests](#table-driven-tests)
- [Test Fixtures and Helpers](#test-fixtures-and-helpers)
- [Mocking Strategies](#mocking-strategies)
- [Subtests and Parallel](#subtests-and-parallel)
- [Fuzzing](#fuzzing)
- [Benchmarking](#benchmarking)
- [Coverage and Race Detection](#coverage-and-race-detection)

## Table-Driven Tests

### Basic Pattern

```go
func TestAdd(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"positive numbers", 2, 3, 5},
        {"negative numbers", -2, -3, -5},
        {"mixed", -2, 3, 1},
        {"zeros", 0, 0, 0},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("Add(%d, %d) = %d; want %d", tt.a, tt.b, result, tt.expected)
            }
        })
    }
}
```

### With Error Cases

```go
func TestParse(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    int
        wantErr bool
    }{
        {"valid", "123", 123, false},
        {"negative", "-456", -456, false},
        {"invalid", "abc", 0, true},
        {"empty", "", 0, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Parse(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("Parse(%q) = %v, want %v", tt.input, got, tt.want)
            }
        })
    }
}
```

### Map-Based Tests

```go
func TestValidate(t *testing.T) {
    tests := map[string]struct {
        input   string
        wantErr error
    }{
        "valid email":   {"user@example.com", nil},
        "missing @":     {"userexample.com", ErrInvalidEmail},
        "empty":         {"", ErrEmptyInput},
    }

    for name, tt := range tests {
        t.Run(name, func(t *testing.T) {
            err := Validate(tt.input)
            if !errors.Is(err, tt.wantErr) {
                t.Errorf("got error %v, want %v", err, tt.wantErr)
            }
        })
    }
}
```

## Test Fixtures and Helpers

### Test Helpers

```go
func TestHandler(t *testing.T) {
    // Helper marks function as test helper
    // Line numbers in errors point to caller
    assertEqual := func(t *testing.T, got, want string) {
        t.Helper()
        if got != want {
            t.Errorf("got %q, want %q", got, want)
        }
    }

    result := process("input")
    assertEqual(t, result, "expected")
}
```

### Setup and Teardown

```go
func TestDatabase(t *testing.T) {
    // Setup
    db := setupTestDB(t)

    // Teardown using t.Cleanup
    t.Cleanup(func() {
        db.Close()
    })

    // Tests run here
    t.Run("insert", func(t *testing.T) {
        // ...
    })
}

// Reusable setup helper
func setupTestDB(t *testing.T) *sql.DB {
    t.Helper()

    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        t.Fatalf("failed to open db: %v", err)
    }

    t.Cleanup(func() {
        db.Close()
    })

    return db
}
```

### testdata Directory

```go
// Files in testdata/ are ignored by go build
func TestParseFile(t *testing.T) {
    data, err := os.ReadFile("testdata/sample.json")
    if err != nil {
        t.Fatal(err)
    }

    result, err := Parse(data)
    // ...
}

// Golden files pattern
func TestRender(t *testing.T) {
    result := Render(input)

    golden := filepath.Join("testdata", t.Name()+".golden")

    if *update {
        os.WriteFile(golden, result, 0644)
    }

    expected, _ := os.ReadFile(golden)
    if !bytes.Equal(result, expected) {
        t.Errorf("output mismatch")
    }
}
```

### TestMain

```go
func TestMain(m *testing.M) {
    // Setup before all tests
    setup()

    // Run tests
    code := m.Run()

    // Teardown after all tests
    teardown()

    os.Exit(code)
}
```

## Mocking Strategies

### Interface-Based Mocking

```go
// Define interface where used
type UserStore interface {
    GetUser(id string) (*User, error)
    SaveUser(user *User) error
}

// Production implementation
type PostgresUserStore struct { /* ... */ }

// Test mock
type MockUserStore struct {
    GetUserFunc  func(id string) (*User, error)
    SaveUserFunc func(user *User) error
}

func (m *MockUserStore) GetUser(id string) (*User, error) {
    return m.GetUserFunc(id)
}

func (m *MockUserStore) SaveUser(user *User) error {
    return m.SaveUserFunc(user)
}

// In tests
func TestService(t *testing.T) {
    mock := &MockUserStore{
        GetUserFunc: func(id string) (*User, error) {
            return &User{ID: id, Name: "Test"}, nil
        },
    }

    svc := NewService(mock)
    // ...
}
```

### Using mockgen

```bash
# Install
go install go.uber.org/mock/mockgen@latest

# Generate from interface
mockgen -source=store.go -destination=mock_store.go -package=mypackage
```

```go
// Using generated mock
func TestWithMockgen(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()

    mock := NewMockUserStore(ctrl)
    mock.EXPECT().GetUser("123").Return(&User{ID: "123"}, nil)

    svc := NewService(mock)
    user, err := svc.GetUser("123")
    // ...
}
```

### Using mockery

mockery generates testify-compatible mocks with less boilerplate.

```bash
# Install
go install github.com/vektra/mockery/v2@latest

# Generate mock for specific interface
mockery --name=UserStore

# Generate mocks for all interfaces in package
mockery --all
```

#### .mockery.yaml Configuration

```yaml
# .mockery.yaml
with-expecter: true
packages:
  github.com/myorg/myproject/internal/store:
    interfaces:
      UserStore:
        config:
          dir: mocks
      OrderStore:
        config:
          dir: mocks
```

```bash
# Run mockery with config
mockery
```

#### Using Generated Mocks

```go
import "github.com/myorg/myproject/mocks"

func TestService(t *testing.T) {
    mock := mocks.NewMockUserStore(t)  // Auto cleanup

    // Using On/Return (testify style)
    mock.On("GetUser", "123").Return(&User{ID: "123"}, nil)

    // Or using EXPECT (mockery v2 with expecter)
    mock.EXPECT().GetUser("123").Return(&User{ID: "123"}, nil)

    svc := NewService(mock)
    user, _ := svc.GetUser("123")
    assert.Equal(t, "123", user.ID)
}
```

**mockery vs mockgen:**
- mockery: testify integration, simpler API, YAML config
- mockgen: gomock expectations, more verbose, stricter

### httptest Package

```go
func TestHTTPClient(t *testing.T) {
    // Mock server
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/api/users" {
            t.Errorf("unexpected path: %s", r.URL.Path)
        }
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"id": "123"}`))
    }))
    defer server.Close()

    // Test client
    client := NewClient(server.URL)
    user, err := client.GetUser("123")
    // ...
}

// Testing handlers
func TestHandler(t *testing.T) {
    req := httptest.NewRequest("GET", "/users/123", nil)
    w := httptest.NewRecorder()

    handler := NewUserHandler()
    handler.ServeHTTP(w, req)

    if w.Code != http.StatusOK {
        t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
    }
}
```

## Subtests and Parallel

### Subtests

```go
func TestMath(t *testing.T) {
    t.Run("Add", func(t *testing.T) {
        if Add(2, 3) != 5 {
            t.Error("failed")
        }
    })

    t.Run("Multiply", func(t *testing.T) {
        if Multiply(2, 3) != 6 {
            t.Error("failed")
        }
    })
}
```

### Parallel Tests

```go
func TestParallel(t *testing.T) {
    tests := []struct {
        name  string
        input int
    }{
        {"case1", 1},
        {"case2", 2},
        {"case3", 3},
    }

    for _, tt := range tests {
        tt := tt  // Capture range variable (pre-Go 1.22)
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()  // Run in parallel with other parallel tests
            result := slowFunction(tt.input)
            // ...
        })
    }
}
```

## Fuzzing

### Basic Fuzz Test

```go
func FuzzReverse(f *testing.F) {
    // Seed corpus
    f.Add("hello")
    f.Add("世界")
    f.Add("")

    // Fuzz target
    f.Fuzz(func(t *testing.T, s string) {
        rev := Reverse(s)
        doubleRev := Reverse(rev)
        if s != doubleRev {
            t.Errorf("reverse twice: got %q, want %q", doubleRev, s)
        }
    })
}
```

### Running Fuzz Tests

```bash
# Run fuzzing for 30 seconds
go test -fuzz=FuzzReverse -fuzztime=30s

# Run with specific seed
go test -run=FuzzReverse/seed_corpus_entry
```

### Multiple Parameters

```go
func FuzzParse(f *testing.F) {
    f.Add([]byte(`{"key": "value"}`))
    f.Add([]byte(`[]`))

    f.Fuzz(func(t *testing.T, data []byte) {
        var v interface{}
        if err := json.Unmarshal(data, &v); err != nil {
            return  // Invalid JSON is expected
        }

        // Re-marshal should work
        _, err := json.Marshal(v)
        if err != nil {
            t.Errorf("marshal failed: %v", err)
        }
    })
}
```

## Benchmarking

### Basic Benchmark

```go
func BenchmarkFib(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Fib(20)
    }
}
```

### With Setup

```go
func BenchmarkParse(b *testing.B) {
    data := loadTestData()

    b.ResetTimer()  // Exclude setup from timing

    for i := 0; i < b.N; i++ {
        Parse(data)
    }
}
```

### Memory Allocation

```go
func BenchmarkAlloc(b *testing.B) {
    b.ReportAllocs()

    for i := 0; i < b.N; i++ {
        _ = make([]byte, 1024)
    }
}
```

### Sub-Benchmarks

```go
func BenchmarkSort(b *testing.B) {
    sizes := []int{100, 1000, 10000}

    for _, size := range sizes {
        b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
            data := generateData(size)
            b.ResetTimer()

            for i := 0; i < b.N; i++ {
                sort.Ints(data)
            }
        })
    }
}
```

### Running Benchmarks

```bash
# Run all benchmarks
go test -bench=.

# Run specific benchmark
go test -bench=BenchmarkFib

# With memory stats
go test -bench=. -benchmem

# Compare benchmarks
go test -bench=. -count=5 > old.txt
# Make changes
go test -bench=. -count=5 > new.txt
benchstat old.txt new.txt
```

## Coverage and Race Detection

### Coverage

```bash
# Run with coverage
go test -cover ./...

# Generate coverage profile
go test -coverprofile=coverage.out ./...

# View in browser
go tool cover -html=coverage.out

# View by function
go tool cover -func=coverage.out

# Coverage mode (set, count, atomic)
go test -covermode=atomic -coverprofile=coverage.out ./...
```

### Race Detection

```bash
# Run tests with race detector
go test -race ./...

# Build with race detector
go build -race -o myapp

# Run with race detector
go run -race main.go
```

### Integration Testing Example

```go
//go:build integration

package mypackage

func TestIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test in short mode")
    }

    // Integration test code
}
```

```bash
# Run including integration tests
go test -tags=integration ./...

# Skip long tests
go test -short ./...
```

## Build Tags for Test Organization

### Common Patterns

```go
//go:build integration
// +build integration

package mypackage

// Only compiled when: go test -tags=integration
```

### Multiple Tags

```go
//go:build integration && !windows
// Tests run on integration builds except Windows
```

### Separate Test Files

```
mypackage/
├── service.go
├── service_test.go          # Unit tests (always run)
├── service_integration_test.go  # go:build integration
└── service_e2e_test.go          # go:build e2e
```

### Running Tagged Tests

```bash
# Unit tests only (default)
go test ./...

# Include integration tests
go test -tags=integration ./...

# Multiple tags
go test -tags="integration e2e" ./...

# Exclude short tests (honors testing.Short())
go test -short ./...
```

### Environment-Based Skipping

```go
func TestRequiresDB(t *testing.T) {
    if os.Getenv("TEST_DB_URL") == "" {
        t.Skip("TEST_DB_URL not set")
    }
    // ...
}
```

## testifylint Patterns

When using testify, follow these patterns for cleaner tests.

```go
// Good: Use require for setup that must succeed
func TestUser(t *testing.T) {
    user, err := CreateUser("test")
    require.NoError(t, err)  // Stops test if fails
    require.NotNil(t, user)

    // Use assert for actual test assertions
    assert.Equal(t, "test", user.Name)
    assert.True(t, user.Active)
}

// Good: Use ErrorIs/ErrorAs for error checking
assert.ErrorIs(t, err, ErrNotFound)

var pathErr *os.PathError
assert.ErrorAs(t, err, &pathErr)

// Good: Specific assertions over generic
assert.Empty(t, slice)        // Not: assert.Len(t, slice, 0)
assert.Contains(t, s, "foo")  // Not: assert.True(t, strings.Contains(s, "foo"))
assert.Zero(t, value)         // Not: assert.Equal(t, 0, value)

// Good: Consistent argument order (expected, actual)
assert.Equal(t, expected, actual)  // Not: assert.Equal(t, actual, expected)
```
