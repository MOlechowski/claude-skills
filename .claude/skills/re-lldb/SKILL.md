---
name: re-lldb
description: "LLDB debugger for macOS/iOS reverse engineering: breakpoints, memory examination, Python scripting, Xcode integration. Use for: debugging on macOS, iOS analysis, memory patching, macOS binary analysis. Triggers: lldb, macos debug, ios debug, lldb command, debug on mac, xcode debugger."
---

# LLDB

LLVM debugger for macOS, iOS, and cross-platform debugging.

## Quick Start

```bash
lldb ./binary              # Debug binary
lldb -- ./binary arg1      # With arguments
lldb -p PID                # Attach to PID
lldb -n Safari             # Attach by name
lldb -w -n MyApp           # Wait for launch
```

## Essential Commands

| Command | Purpose |
|---------|---------|
| `b func` / `b -a addr` | Set breakpoint |
| `r` | Run |
| `c` | Continue |
| `n` / `s` | Step over / into |
| `ni` / `si` | Step instruction |
| `x/Nx addr` | Examine memory |
| `register read` | Show registers |
| `bt` | Backtrace |

For comprehensive command reference, see: [references/commands.md](references/commands.md)

## GDB to LLDB Mapping

| GDB | LLDB |
|-----|------|
| `break *0x1234` | `b -a 0x1234` |
| `info registers` | `register read` |
| `set $rax=1` | `register write rax 1` |
| `info breakpoints` | `br l` |
| `info proc mappings` | `image list` |

## Memory Operations

```bash
# Read
memory read -c 64 $rsp       # 64 bytes
x/10x $rsp                   # GDB-style

# Write
memory write -s 1 0x100001234 0x90   # Write byte
memory write -s 4 0x100001234 0x90909090  # Write dword
```

## iOS/macOS Specifics

### Attach to App

```bash
lldb -n Safari              # By name
lldb -n com.apple.Safari    # By bundle ID
lldb -w -n MyApp            # Wait for launch
```

### iOS Simulator

```bash
xcrun simctl list devices
xcrun simctl launch booted com.example.app
lldb -n MyApp
```

### Objective-C / Swift

```bash
# Objective-C
expr -l objc -- (void)NSLog(@"Hello")
po object

# Swift
expr -l swift -- print("Hello")
```

## .lldbinit Setup

```bash
# ~/.lldbinit
settings set target.x86-disassembly-flavor intel
command alias bpl breakpoint list
```

## Python Scripting

```python
import lldb

def analyze(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    frame = target.GetProcess().GetSelectedThread().GetSelectedFrame()
    rax = frame.FindRegister("rax").GetValueAsUnsigned()
    print(f"rax = {hex(rax)}")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f module.analyze analyze')
```

Load with: `command script import ~/scripts/my_script.py`

## Integration

For Linux debugging, use `/re-gdb`.
For memory patching, see `/re-xxd`.
For binary analysis, use `/re-ghidra` or `/re-radare2`.
