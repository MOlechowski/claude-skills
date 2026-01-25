---
name: re-strace
description: "System call tracing with strace/ltrace/dtrace: trace syscalls, library calls, filter by type, follow processes. Use for: dynamic analysis, understanding binary behavior, debugging, identifying file/network access. Triggers: strace, ltrace, dtrace, trace syscalls, trace library calls, what syscalls, what files accessed."
---

# strace / ltrace

System call and library call tracing for dynamic analysis.

## Quick Start

```bash
# Trace all syscalls
strace ./binary

# Trace specific syscalls
strace -e open,read,write ./binary

# Trace library calls
ltrace ./binary

# Attach to running process
strace -p PID
```

## strace - System Calls

### Basic Usage

```bash
strace ./binary                    # All syscalls
strace -o trace.log ./binary       # Save to file
strace -f ./binary                 # Follow forks
strace -ff -o out ./binary         # Separate files per child
```

### Filtering

```bash
# By syscall name
strace -e open ./binary            # Only open()
strace -e open,read,write ./binary # Multiple

# By category
strace -e trace=file ./binary      # File operations
strace -e trace=network ./binary   # Network operations
strace -e trace=process ./binary   # Process operations
strace -e trace=signal ./binary    # Signal operations
strace -e trace=memory ./binary    # Memory operations
```

### Output Options

```bash
strace -t ./binary                 # Timestamp
strace -tt ./binary                # Microsecond timestamp
strace -T ./binary                 # Syscall duration
strace -c ./binary                 # Summary statistics
strace -C ./binary                 # Stats + regular output
strace -s 1000 ./binary            # String length (default 32)
strace -x ./binary                 # Hex output
```

### Common Patterns

```bash
# What files does it open?
strace -e openat,open -f ./binary 2>&1 | grep -v ENOENT

# Network connections?
strace -e connect,socket,bind ./binary

# What does it execute?
strace -e execve -f ./binary

# File reads/writes?
strace -e read,write -e trace=desc ./binary
```

## ltrace - Library Calls

### Basic Usage

```bash
ltrace ./binary                    # All library calls
ltrace -o lib.log ./binary         # Save to file
ltrace -f ./binary                 # Follow forks
ltrace -C ./binary                 # Demangle C++ names
```

### Filtering

```bash
ltrace -e malloc ./binary          # Only malloc
ltrace -e 'malloc+free' ./binary   # malloc and free
ltrace -e '*@libc*' ./binary       # All libc functions
ltrace -e '-*' ./binary            # None (for exclusion base)
```

### Useful Patterns

```bash
# Memory allocations
ltrace -e malloc+free+realloc ./binary

# String operations
ltrace -e 'str*' ./binary

# Crypto/SSL
ltrace -e '*@libssl*' ./binary
```

## dtrace (macOS/BSD)

### Quick Start

```bash
# Requires SIP disabled or entitled binary
sudo dtrace -n 'syscall:::entry { @[execname,probefunc] = count(); }'

# Trace process syscalls
sudo dtrace -n 'syscall:::entry /pid == $target/ { trace(probefunc); }' -p PID

# One-liner: files opened
sudo dtrace -n 'syscall::open*:entry { printf("%s", copyinstr(arg0)); }'
```

### dtruss (macOS strace equivalent)

```bash
sudo dtruss ./binary               # Like strace
sudo dtruss -p PID                 # Attach to process
sudo dtruss -f ./binary            # Follow forks
```

## Quick Reference

| Tool | Purpose | Common Options |
|------|---------|----------------|
| `strace` | Syscall tracing | `-e`, `-f`, `-o`, `-c` |
| `ltrace` | Library call tracing | `-e`, `-f`, `-C` |
| `dtrace` | Dynamic tracing (macOS) | `-n`, `-p` |
| `dtruss` | macOS strace equivalent | `-f`, `-p` |

## Common Analysis Tasks

### Find accessed files
```bash
strace -e openat,open,stat 2>&1 ./binary | grep -E '^(openat|open|stat)'
```

### Find network activity
```bash
strace -e socket,connect,sendto,recvfrom ./binary
```

### Find executed commands
```bash
strace -f -e execve ./binary 2>&1 | grep execve
```

### Profile syscall time
```bash
strace -c ./binary
```

## Integration

For static analysis before tracing, use `/re-expert`.
For debugging with breakpoints, use `/re-gdb` or `/re-lldb`.
For hooking specific functions, use `/re-frida`.
