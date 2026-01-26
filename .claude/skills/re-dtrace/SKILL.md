---
name: re-dtrace
description: "DTrace dynamic tracing for macOS/BSD: D language scripts, dtruss (strace equivalent), syscall/file/network/process tracing, probe providers. Use for: macOS syscall tracing, performance analysis, debugging on macOS, understanding binary behavior. Triggers: dtrace, dtruss, macos strace, macos syscall trace, D language tracing, dynamic tracing macos."
---

# DTrace (macOS/BSD)

**Platform: macOS, FreeBSD, Solaris.** For Linux tracing, use `/re-strace`.

Dynamic tracing framework for system-wide observability and debugging.

## Prerequisites

### System Integrity Protection (SIP)

DTrace requires SIP adjustments on modern macOS:

```bash
# Check SIP status
csrutil status

# Disable DTrace restrictions (requires Recovery Mode)
# Boot to Recovery: Hold Cmd+R on Intel, Power button on Apple Silicon
csrutil enable --without dtrace

# Full disable (not recommended for production)
csrutil disable
```

Note: On Apple Silicon Macs, some restrictions remain even with SIP disabled.

## dtruss - macOS strace Equivalent

Quick syscall tracing without writing D scripts.

### Basic Usage

```bash
sudo dtruss ./binary               # Trace all syscalls
sudo dtruss -p PID                 # Attach to running process
sudo dtruss -f ./binary            # Follow forks
sudo dtruss -t open ./binary       # Specific syscall
sudo dtruss -t 'open,read,write' ./binary  # Multiple syscalls
```

### Output Options

```bash
sudo dtruss -d ./binary            # Print relative timestamps
sudo dtruss -e ./binary            # Print elapsed time
sudo dtruss -a ./binary            # Print all details
```

### Common Patterns

```bash
# What files does it open?
sudo dtruss -t open ./binary 2>&1 | grep -v ENOENT

# Network activity
sudo dtruss -t 'socket,connect,bind,send,recv' ./binary

# Process operations
sudo dtruss -t 'fork,exec,exit' ./binary
```

## DTrace D Language Basics

### Probe Format

```
provider:module:function:name { action }
```

**Common Providers:**
- `syscall` - System calls
- `proc` - Process events
- `io` - Disk I/O
- `fbt` - Kernel functions
- `pid` - User-space functions

### One-Liners

```bash
# Count syscalls by name
sudo dtrace -n 'syscall:::entry { @[probefunc] = count(); }'

# Count syscalls by process
sudo dtrace -n 'syscall:::entry { @[execname] = count(); }'

# Trace syscalls for specific PID
sudo dtrace -n 'syscall:::entry /pid == 1234/ { printf("%s", probefunc); }'

# Trace syscalls for process by name
sudo dtrace -n 'syscall:::entry /execname == "Safari"/ { printf("%s", probefunc); }'

# Trace file opens with path
sudo dtrace -n 'syscall::open*:entry { printf("%s", copyinstr(arg0)); }'

# Trace with timestamp
sudo dtrace -n 'syscall:::entry { printf("%d %s", timestamp, probefunc); }'
```

### Aggregations

```bash
# Count by syscall and process
sudo dtrace -n 'syscall:::entry { @[execname, probefunc] = count(); }'

# Sum bytes read by process
sudo dtrace -n 'syscall::read:return { @[execname] = sum(arg0); }'

# Quantize read sizes
sudo dtrace -n 'syscall::read:return /arg0 > 0/ { @[execname] = quantize(arg0); }'

# Time spent in syscalls
sudo dtrace -n 'syscall:::entry { self->ts = timestamp; }
    syscall:::return /self->ts/ { @[probefunc] = sum(timestamp - self->ts); self->ts = 0; }'
```

## File Tracing

```bash
# All file opens with path
sudo dtrace -n 'syscall::open*:entry { printf("%s %s", execname, copyinstr(arg0)); }'

# Filter by process name
sudo dtrace -n 'syscall::open*:entry /execname == "MyApp"/ {
    printf("%s", copyinstr(arg0));
}'

# Track read/write activity
sudo dtrace -n 'syscall::read:entry { @reads[execname] = count(); }
    syscall::write:entry { @writes[execname] = count(); }'
```

## Network Tracing

```bash
# Track socket creation
sudo dtrace -n 'syscall::socket:entry {
    printf("%s domain=%d type=%d", execname, arg0, arg1);
}'

# Network syscalls summary
sudo dtrace -n 'syscall::socket:entry,syscall::connect:entry,
    syscall::bind:entry,syscall::listen:entry { @[execname, probefunc] = count(); }'
```

## Process Tracing

```bash
# Track process execution
sudo dtrace -n 'proc:::exec-success { printf("%s -> %s", execname, curpsinfo->pr_psargs); }'

# Process creation/exit
sudo dtrace -n 'proc:::create { printf("create: %s", execname); }
    proc:::exit { printf("exit: %s", execname); }'

# Fork tracking
sudo dtrace -n 'syscall::fork:return /arg0 > 0/ { printf("%s forked %d", execname, arg0); }'
```

## D Script Files

### Script Structure

```d
#!/usr/sbin/dtrace -s

#pragma D option quiet

dtrace:::BEGIN {
    printf("Tracing... Ctrl+C to stop\n");
}

syscall::open*:entry
/execname == $$1/
{
    printf("%s\n", copyinstr(arg0));
}

dtrace:::END {
    printf("Done\n");
}
```

Run with: `sudo dtrace -s script.d MyApp`

### Syscall Timer Script

```d
#!/usr/sbin/dtrace -s

syscall:::entry { self->ts = timestamp; }

syscall:::return
/self->ts/
{
    @time[probefunc] = avg(timestamp - self->ts);
    self->ts = 0;
}
```

## pid Provider (User-Space)

Trace user-space functions by process ID.

```bash
# Trace function entry
sudo dtrace -n 'pid$target::function_name:entry { trace(arg0); }' -p PID

# Trace library function
sudo dtrace -n 'pid$target:libsystem_c.dylib:malloc:entry { printf("%d", arg0); }' -p PID

# Trace return value
sudo dtrace -n 'pid$target::function:return { printf("ret=%d", arg1); }' -p PID
```

## Quick Reference

| Tool/Command | Purpose |
|--------------|---------|
| `dtruss` | strace-equivalent for macOS |
| `dtrace -n 'probe { action }'` | One-liner tracing |
| `dtrace -s script.d` | Run D script |
| `dtrace -l` | List available probes |
| `dtrace -l -n 'syscall::*open*:'` | Search probes |

### Probe Providers

| Provider | Description | Common Probes |
|----------|-------------|---------------|
| `syscall` | System calls | `:::entry`, `:::return` |
| `proc` | Process events | `:::exec-success`, `:::exit` |
| `io` | Disk I/O | `:::start`, `:::done` |
| `fbt` | Kernel functions | `::func:entry/return` |
| `pid` | User functions | `$target::func:entry` |

## Troubleshooting

### Common Issues

**"dtrace: system integrity protection is on"**
```bash
# Boot to Recovery Mode and run:
csrutil enable --without dtrace
```

**"dtrace: failed to grab process"**
- Process may have hardened runtime
- Try: `codesign --remove-signature /path/to/binary` (creates unsigned copy)

**"dtrace: invalid probe specifier"**
- Check probe exists: `dtrace -l -n 'your:::probe'`
- Use wildcards: `syscall::*open*:entry`

**Apple Silicon limitations**
- Some kernel probes restricted even with SIP disabled
- Use `dtruss` as fallback for syscall tracing

## Integration

For Linux syscall tracing, use `/re-strace`.
For debugging with breakpoints, use `/re-lldb` (macOS) or `/re-gdb` (Linux).
For hooking specific functions, use `/re-frida`.
For static analysis, use `/re-ghidra` or `/re-radare2`.
