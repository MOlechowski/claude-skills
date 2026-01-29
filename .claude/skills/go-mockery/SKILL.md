---
name: go-mockery
description: "[Go] Mock generation for interfaces using testify. Use for: generating mocks, test setup, interface mocking. Triggers: mockery, go mock, testify mock, mock generation."
---

# mockery

Mock generator for Go interfaces, producing testify-compatible mocks.

## Installation

```bash
# Go install
go install github.com/vektra/mockery/v2@latest

# macOS
brew install mockery

# Verify
mockery --version
```

## Quick Start

```bash
# Generate mock for specific interface
mockery --name=UserStore

# Generate for all interfaces in package
mockery --all

# With output directory
mockery --name=UserStore --output=mocks

# Recursive (all packages)
mockery --all --recursive
```

## Configuration (.mockery.yaml)

```yaml
# .mockery.yaml
with-expecter: true
dir: mocks
packages:
  github.com/myorg/myproject/internal/store:
    interfaces:
      UserStore:
      OrderStore:
  github.com/myorg/myproject/internal/client:
    interfaces:
      HTTPClient:
        config:
          mockname: MockHTTPClient
```

Run with config:

```bash
mockery  # Reads .mockery.yaml automatically
```

## Interface Example

```go
// store/user.go
package store

type User struct {
    ID   string
    Name string
}

type UserStore interface {
    GetUser(id string) (*User, error)
    SaveUser(user *User) error
    DeleteUser(id string) error
}
```

## Using Generated Mocks

### Basic Usage

```go
import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/myorg/myproject/mocks"
)

func TestGetUser(t *testing.T) {
    // Create mock (auto-cleanup with t)
    mock := mocks.NewMockUserStore(t)

    // Set expectation
    mock.On("GetUser", "123").Return(&User{ID: "123", Name: "John"}, nil)

    // Use mock
    svc := NewService(mock)
    user, err := svc.GetUser("123")

    assert.NoError(t, err)
    assert.Equal(t, "John", user.Name)
}
```

### With Expecter (Recommended)

When `with-expecter: true` is set:

```go
func TestGetUserExpect(t *testing.T) {
    mock := mocks.NewMockUserStore(t)

    // Type-safe expectations
    mock.EXPECT().GetUser("123").Return(&User{ID: "123"}, nil)

    svc := NewService(mock)
    user, _ := svc.GetUser("123")
    assert.Equal(t, "123", user.ID)
}
```

### Argument Matching

```go
// Any argument
mock.On("GetUser", mock.Anything).Return(&User{}, nil)

// Custom matcher
mock.On("SaveUser", mock.MatchedBy(func(u *User) bool {
    return u.Name != ""
})).Return(nil)

// Typed any (with expecter)
mock.EXPECT().GetUser(mock.AnythingOfType("string")).Return(&User{}, nil)
```

### Return Behavior

```go
// Return error
mock.On("GetUser", "404").Return(nil, errors.New("not found"))

// Dynamic return
mock.On("GetUser", mock.Anything).Return(func(id string) (*User, error) {
    return &User{ID: id}, nil
})

// Return once then different
mock.On("GetUser", "123").Return(&User{}, nil).Once()
mock.On("GetUser", "123").Return(nil, errors.New("deleted"))
```

### Verifying Calls

```go
func TestSaveUser(t *testing.T) {
    mock := mocks.NewMockUserStore(t)

    mock.On("SaveUser", mock.Anything).Return(nil)

    svc := NewService(mock)
    svc.CreateUser("John")

    // Verify call was made
    mock.AssertCalled(t, "SaveUser", mock.Anything)

    // Verify call count
    mock.AssertNumberOfCalls(t, "SaveUser", 1)

    // Verify all expectations met
    mock.AssertExpectations(t)
}
```

## CLI Options

```bash
mockery --name=Interface      # Specific interface
mockery --all                 # All interfaces
mockery --recursive           # Include subpackages
mockery --output=./mocks      # Output directory
mockery --outpkg=mocks        # Package name
mockery --filename=mock_x.go  # Output filename
mockery --with-expecter       # Generate EXPECT() methods
mockery --inpackage           # Generate in same package
mockery --testonly            # Generate _test.go file
mockery --dry-run             # Show what would be generated
```

## go:generate Integration

```go
//go:generate mockery --name=UserStore
type UserStore interface {
    GetUser(id string) (*User, error)
}
```

```bash
go generate ./...
```

## Project Structure

```
myproject/
├── internal/
│   └── store/
│       ├── user.go      # Interface definition
│       └── postgres.go  # Implementation
├── mocks/               # Generated mocks
│   └── mock_user_store.go
├── .mockery.yaml
└── go.mod
```

## Best Practices

1. **Use .mockery.yaml** - Centralized config, reproducible generation
2. **Enable expecter** - Type-safe expectations with EXPECT()
3. **Use go:generate** - Keep mocks in sync with interfaces
4. **Separate mocks dir** - Keep generated code separate
5. **Pass `t` to constructor** - Automatic cleanup and failure reporting

## mockery vs mockgen

| Feature | mockery | mockgen |
|---------|---------|---------|
| Style | testify (On/Return) | gomock (EXPECT) |
| Config | YAML file | CLI flags |
| API | Simpler | More verbose |
| Assertions | testify integration | gomock matchers |
| Type safety | With expecter | Always |
