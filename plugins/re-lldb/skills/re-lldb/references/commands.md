# LLDB Command Reference

Complete command reference with GDB equivalents.

## Command Structure

LLDB uses a structured command format:
```
<noun> <verb> [-options] [argument]
```

Example: `breakpoint set -n main`

## Running and Stopping

| LLDB Command | Short | GDB Equivalent |
|--------------|-------|----------------|
| `process launch` | `r` | `run` |
| `process launch -- args` | `r args` | `run args` |
| `process continue` | `c` | `continue` |
| `process kill` | `kill` | `kill` |
| `quit` | `q` | `quit` |
| `process attach -p PID` | | `attach PID` |
| `process attach -n name` | | `attach name` |
| `process detach` | | `detach` |

## Breakpoints

| LLDB Command | Short | Description |
|--------------|-------|-------------|
| `breakpoint set -n func` | `b func` | Break at function |
| `breakpoint set -a 0x1234` | `b -a 0x1234` | Break at address |
| `breakpoint set -f file -l N` | | Break at file:line |
| `breakpoint set -r regex` | `rbreak` | Regex breakpoint |
| `breakpoint set -s lib -n func` | | Break in library |
| `breakpoint list` | `br l` | List breakpoints |
| `breakpoint delete N` | `br del N` | Delete breakpoint |
| `breakpoint delete` | | Delete all |
| `breakpoint disable N` | `br dis N` | Disable |
| `breakpoint enable N` | `br en N` | Enable |
| `breakpoint modify -c "cond" N` | | Add condition |
| `breakpoint modify -i N count` | | Ignore count |
| `breakpoint command add N` | | Add commands |

### Breakpoint Options

| Option | Description |
|--------|-------------|
| `-n name` | Function name |
| `-a address` | Address |
| `-f file` | Source file |
| `-l line` | Line number |
| `-r regex` | Regex pattern |
| `-s shlib` | Shared library |
| `-c condition` | Condition |
| `-i count` | Ignore count |
| `-o` | One-shot (auto-delete) |

## Watchpoints

| LLDB Command | Description |
|--------------|-------------|
| `watchpoint set variable var` | Watch variable |
| `watchpoint set expression -- addr` | Watch address |
| `watchpoint set expression -w write -- addr` | Watch writes |
| `watchpoint set expression -w read -- addr` | Watch reads |
| `watchpoint list` | List watchpoints |
| `watchpoint delete` | Delete all |
| `watchpoint disable N` | Disable |

## Stepping

| LLDB Command | Short | GDB Equivalent |
|--------------|-------|----------------|
| `thread step-over` | `n` | `next` |
| `thread step-in` | `s` | `step` |
| `thread step-inst` | `ni` | `nexti` |
| `thread step-inst-over` | `si` | `stepi` |
| `thread step-out` | `finish` | `finish` |
| `thread until 0x1234` | | `until *0x1234` |
| `thread jump -a 0x1234` | | `jump *0x1234` |

## Examining Data

### Expression/Print

| LLDB Command | Short | Description |
|--------------|-------|-------------|
| `expression expr` | `p expr` | Evaluate expression |
| `expression -f x -- expr` | `p/x expr` | Hex format |
| `expression -f d -- expr` | `p/d` | Decimal |
| `expression -f b -- expr` | `p/t` | Binary |
| `expression -f c -- expr` | `p/c` | Character |
| `expression -f s -- expr` | `p/s` | String |
| `po object` | | Print object (description) |

### Memory Read

| LLDB Command | Short | Description |
|--------------|-------|-------------|
| `memory read addr` | `x addr` | Read memory |
| `memory read -c N addr` | `x/N addr` | N units |
| `memory read -f x addr` | `x/x` | Hex format |
| `memory read -s 1 addr` | `x/b` | Bytes |
| `memory read -s 2 addr` | `x/h` | Halfwords |
| `memory read -s 4 addr` | `x/w` | Words |
| `memory read -s 8 addr` | `x/g` | Giant (qword) |
| `memory read -f i addr` | `x/i` | Instructions |
| `memory read -f s addr` | `x/s` | String |

### Memory Write

| LLDB Command | Description |
|--------------|-------------|
| `memory write addr value` | Write value |
| `memory write -s 1 addr val` | Write byte |
| `memory write -s 4 addr val` | Write dword |
| `memory write addr val1 val2...` | Write multiple |

### Format Specifiers

| Format | Description |
|--------|-------------|
| `x` | Hexadecimal |
| `d` | Decimal |
| `u` | Unsigned decimal |
| `o` | Octal |
| `b`, `t` | Binary |
| `c` | Character |
| `s` | String |
| `i` | Instruction |
| `f` | Float |
| `p` | Pointer |

## Registers

| LLDB Command | Short | GDB Equivalent |
|--------------|-------|----------------|
| `register read` | `re r` | `info registers` |
| `register read rax rbx` | | `info reg rax rbx` |
| `register read -a` | | All registers |
| `register read -f d rax` | | Decimal format |
| `register write rax 0x1234` | | `set $rax=0x1234` |

## Stack and Frames

| LLDB Command | Short | GDB Equivalent |
|--------------|-------|----------------|
| `thread backtrace` | `bt` | `backtrace` |
| `thread backtrace all` | `bt all` | `thread apply all bt` |
| `frame select N` | `f N` | `frame N` |
| `frame variable` | `fr v` | `info locals` |
| `frame variable -a` | | `info args` |
| `frame info` | | `info frame` |
| `up [N]` | | Move up frames |
| `down [N]` | | Move down frames |

## Threads

| LLDB Command | Description |
|--------------|-------------|
| `thread list` | List threads |
| `thread select N` | Select thread |
| `thread info` | Thread info |
| `thread return [value]` | Force return |

## Images and Symbols

| LLDB Command | GDB Equivalent |
|--------------|----------------|
| `image list` | `info sharedlibrary` |
| `image lookup -a addr` | `info symbol addr` |
| `image lookup -n name` | `info functions name` |
| `image lookup -r -n regex` | Regex symbol search |
| `image dump symtab` | `info functions` |
| `image dump sections` | `info files` |
| `target symbols add file` | `add-symbol-file` |

## Process Information

| LLDB Command | Description |
|--------------|-------------|
| `process status` | Process state |
| `process info` | Detailed info |
| `platform status` | Platform info |
| `target list` | Targets |

## Settings

| LLDB Command | Description |
|--------------|-------------|
| `settings show` | All settings |
| `settings set key value` | Set value |
| `settings write -f file` | Save settings |
| `settings read -f file` | Load settings |

### Common Settings

| Setting | Description |
|---------|-------------|
| `target.x86-disassembly-flavor intel` | Intel syntax |
| `target.prefer-dynamic-value run-target` | Dynamic types |
| `stop-line-count-before N` | Context lines |
| `stop-line-count-after N` | Context lines |

## Aliases

### Built-in Aliases

| Alias | Full Command |
|-------|--------------|
| `b` | `_regexp-break` |
| `bt` | `thread backtrace` |
| `c` | `process continue` |
| `f` | `frame select` |
| `n` | `thread step-over` |
| `ni` | `thread step-inst-over` |
| `p` | `expression --` |
| `po` | `expression -O --` |
| `r` | `process launch --` |
| `s` | `thread step-in` |
| `si` | `thread step-inst` |
| `x` | `memory read` |

### Create Alias

```bash
command alias bpl breakpoint list
command alias bpc breakpoint clear
command alias dis disassemble
```

## Command Script (Python)

| LLDB Command | Description |
|--------------|-------------|
| `command script import file.py` | Import Python |
| `command script add -f mod.func name` | Add command |
| `script` | Python REPL |
| `script lldb.debugger` | Access debugger |

## Disassembly

| LLDB Command | Description |
|--------------|-------------|
| `disassemble` | Current function |
| `disassemble -n func` | Named function |
| `disassemble -s addr` | At address |
| `disassemble -s addr -c N` | N instructions |
| `disassemble -f` | Full function |
| `disassemble -m` | Mixed source |
| `disassemble -b` | Show bytes |

## Source

| LLDB Command | Description |
|--------------|-------------|
| `source list` | Show source |
| `source list -n func` | Function source |
| `source list -f file -l N` | File at line |
| `source info` | Source info |

## Logging

| LLDB Command | Description |
|--------------|-------------|
| `log enable lldb all` | Enable logging |
| `log enable gdb-remote packets` | Debug packets |
| `log list` | List channels |
| `log disable` | Disable logging |

## Environment

| LLDB Command | Description |
|--------------|-------------|
| `settings set target.env-vars VAR=val` | Set env var |
| `settings show target.env-vars` | Show env vars |
| `settings clear target.env-vars` | Clear env vars |
| `process launch -v VAR=val` | Launch with env |
