---
name: go-delve
description: "[Go] Debugger: breakpoints, stepping, variable inspection, goroutine debugging, remote debugging, core dumps. Use for: debugging Go programs, inspecting state, tracing execution. Triggers: dlv, delve, go debug, breakpoint, stepping."
---

# Delve

Source-level debugger for Go programs.

## Installation

```bash
# Go install
go install github.com/go-delve/delve/cmd/dlv@latest

# macOS
brew install delve

# Verify
dlv version
```

## Quick Start

```bash
# Debug current package
dlv debug

# Debug specific main
dlv debug ./cmd/myapp

# Debug with arguments
dlv debug ./cmd/myapp -- --config=config.yaml

# Debug test
dlv test ./pkg/mypackage

# Debug specific test
dlv test ./pkg/mypackage -- -test.run TestMyFunc

# Attach to running process
dlv attach <pid>

# Core dump analysis
dlv core ./myapp core.dump
```

## Breakpoints

### Setting Breakpoints

```
# By function name
(dlv) break main.main
(dlv) b main.handleRequest

# By file:line
(dlv) break main.go:42

# By package.function
(dlv) break github.com/user/pkg.Function

# Conditional breakpoint
(dlv) break main.go:42 if x > 10
(dlv) condition 1 x > 10  # Set condition on existing BP

# List breakpoints
(dlv) breakpoints
(dlv) bp

# Clear breakpoint
(dlv) clear 1
(dlv) clearall
```

### Tracepoints

```
# Trace without stopping
(dlv) trace main.handleRequest

# Trace with output
(dlv) on 1 print x  # Print x when BP 1 is hit
```

## Stepping

```
# Continue until next breakpoint
(dlv) continue
(dlv) c

# Step over (next line)
(dlv) next
(dlv) n

# Step into function
(dlv) step
(dlv) s

# Step out of function
(dlv) stepout
(dlv) so

# Step single instruction
(dlv) si
```

## Variable Inspection

```
# Print variable
(dlv) print x
(dlv) p x

# Print with format
(dlv) p/x myint     # Hex
(dlv) p/b myint     # Binary

# Print struct fields
(dlv) p myStruct
(dlv) p myStruct.Field

# Print slice/array
(dlv) p mySlice
(dlv) p mySlice[0:5]

# Print map
(dlv) p myMap
(dlv) p myMap["key"]

# Print pointer dereference
(dlv) p *ptr

# Local variables
(dlv) locals

# Function arguments
(dlv) args

# Set variable
(dlv) set x = 10
```

## Goroutines

```
# List all goroutines
(dlv) goroutines
(dlv) grs

# Filter goroutines
(dlv) goroutines -with-loc main.go  # At location
(dlv) goroutines -group state       # By state

# Switch goroutine
(dlv) goroutine 5
(dlv) gr 5

# Show goroutine stack
(dlv) goroutine 5 stack

# Current goroutine
(dlv) goroutine
```

## Stack Inspection

```
# Show stack trace
(dlv) stack
(dlv) bt          # Backtrace (alias)

# Full stack with locals
(dlv) stack -full

# Move up/down frames
(dlv) up
(dlv) down
(dlv) frame 3     # Jump to frame

# Show frame info
(dlv) frame
```

## Remote Debugging

### Start Debug Server

```bash
# Headless mode
dlv debug --headless --listen=:2345 --api-version=2

# Accept connections from any host
dlv debug --headless --listen=0.0.0.0:2345 --api-version=2 --accept-multiclient
```

### Connect Client

```bash
dlv connect localhost:2345
```

### Docker Debugging

```dockerfile
# Dockerfile
FROM golang:1.22
RUN go install github.com/go-delve/delve/cmd/dlv@latest
COPY . /app
WORKDIR /app
EXPOSE 2345
CMD ["dlv", "debug", "--headless", "--listen=:2345", "--api-version=2"]
```

```bash
# Run container
docker run -p 2345:2345 myapp-debug

# Connect
dlv connect localhost:2345
```

## IDE Integration

### VS Code (launch.json)

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch Package",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/myapp"
    },
    {
      "name": "Attach",
      "type": "go",
      "request": "attach",
      "mode": "local",
      "processId": 0
    },
    {
      "name": "Remote",
      "type": "go",
      "request": "attach",
      "mode": "remote",
      "remotePath": "/app",
      "port": 2345,
      "host": "localhost"
    }
  ]
}
```

### GoLand

```
Run → Edit Configurations → + → Go Remote
Host: localhost
Port: 2345
```

## Command Reference

| Command | Short | Description |
|---------|-------|-------------|
| break | b | Set breakpoint |
| breakpoints | bp | List breakpoints |
| clear | | Clear breakpoint |
| continue | c | Continue execution |
| next | n | Step over |
| step | s | Step into |
| stepout | so | Step out |
| print | p | Print variable |
| locals | | Show local vars |
| args | | Show arguments |
| stack | bt | Stack trace |
| goroutines | grs | List goroutines |
| goroutine | gr | Switch goroutine |
| frame | | Switch frame |
| restart | r | Restart program |
| exit | q | Exit debugger |

## Tips

### Debug Build

```bash
# Disable optimizations for better debugging
go build -gcflags="all=-N -l" ./cmd/myapp
dlv exec ./myapp
```

### Expressions

```
# Call functions (pure functions only)
(dlv) call myFunc(arg)

# Evaluate expressions
(dlv) p len(mySlice)
(dlv) p myStruct.Field + 10
```

### Configuration

```yaml
# ~/.config/dlv/config.yml
substitute-path:
  - from: /go/src
    to: /home/user/project

source-list-line-color: 34
```
