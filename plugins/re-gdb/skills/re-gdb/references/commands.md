# GDB Command Reference

Comprehensive command reference organized by category.

## Running and Stopping

| Command | Short | Description |
|---------|-------|-------------|
| `run [args]` | `r` | Start program |
| `start` | | Run to main |
| `continue` | `c` | Continue execution |
| `kill` | | Kill program |
| `quit` | `q` | Exit GDB |

## Breakpoints

| Command | Short | Description |
|---------|-------|-------------|
| `break func` | `b` | Break at function |
| `break *addr` | | Break at address |
| `break file:line` | | Break at line |
| `break ... if cond` | | Conditional break |
| `tbreak` | `tb` | Temporary breakpoint |
| `hbreak` | `hb` | Hardware breakpoint |
| `rbreak regex` | | Break on regex match |
| `info breakpoints` | `i b` | List breakpoints |
| `delete [n]` | `d` | Delete breakpoint(s) |
| `disable [n]` | `dis` | Disable breakpoint(s) |
| `enable [n]` | `en` | Enable breakpoint(s) |
| `ignore n count` | | Skip n times |
| `condition n expr` | | Set condition |
| `commands n` | | Commands on break |

## Watchpoints

| Command | Description |
|---------|-------------|
| `watch expr` | Break on write |
| `rwatch expr` | Break on read |
| `awatch expr` | Break on access |
| `info watchpoints` | List watchpoints |

## Stepping

| Command | Short | Description |
|---------|-------|-------------|
| `next` | `n` | Step over (source) |
| `step` | `s` | Step into (source) |
| `nexti` | `ni` | Step over (instruction) |
| `stepi` | `si` | Step into (instruction) |
| `finish` | `fin` | Run until return |
| `until loc` | `u` | Run until location |
| `advance loc` | | Run to location |
| `jump loc` | `j` | Jump to location |

## Examining Data

### Print Command

| Command | Description |
|---------|-------------|
| `print expr` | Print expression |
| `p/x expr` | Print as hex |
| `p/d expr` | Print as decimal |
| `p/t expr` | Print as binary |
| `p/c expr` | Print as char |
| `p/s addr` | Print as string |
| `p/a expr` | Print as address |
| `p *ptr` | Dereference pointer |
| `p array[0]@10` | Print array slice |

### Examine Memory (x)

```
x/[count][format][size] address
```

**Formats:** `x`=hex, `d`=decimal, `u`=unsigned, `o`=octal, `t`=binary, `a`=address, `c`=char, `s`=string, `i`=instruction

**Sizes:** `b`=byte, `h`=halfword(2), `w`=word(4), `g`=giant(8)

| Example | Description |
|---------|-------------|
| `x/10x $rsp` | 10 hex words at RSP |
| `x/20i $rip` | 20 instructions at RIP |
| `x/s 0x401234` | String at address |
| `x/10b $rsp` | 10 bytes at RSP |
| `x/gx $rbp-8` | 8-byte value |

### Display

| Command | Description |
|---------|-------------|
| `display expr` | Auto-display on stop |
| `display/x $rax` | Auto-display hex |
| `undisplay n` | Remove display |
| `info display` | List displays |

## Registers

| Command | Short | Description |
|---------|-------|-------------|
| `info registers` | `i r` | All registers |
| `info registers rax` | | Specific register |
| `info all-registers` | | All including FP/vector |
| `print $rax` | | Print register |
| `set $rax = value` | | Set register |

## Stack

| Command | Short | Description |
|---------|-------|-------------|
| `backtrace` | `bt` | Call stack |
| `backtrace full` | `bt full` | With locals |
| `backtrace n` | | First n frames |
| `frame n` | `f` | Select frame |
| `up [n]` | | Up n frames |
| `down [n]` | | Down n frames |
| `info frame` | `i f` | Frame details |
| `info args` | | Arguments |
| `info locals` | | Local variables |

## Memory Modification

| Command | Description |
|---------|-------------|
| `set {type}addr = value` | Write memory |
| `set var = value` | Set variable |
| `set $reg = value` | Set register |

### Type Examples

| Command | Description |
|---------|-------------|
| `set {char}0x401234 = 0x90` | Write byte |
| `set {short}0x401234 = 0x9090` | Write 2 bytes |
| `set {int}0x401234 = 0x90909090` | Write 4 bytes |
| `set {long}0x401234 = 0x...` | Write 8 bytes |

## Process Information

| Command | Description |
|---------|-------------|
| `info proc mappings` | Memory map |
| `info sharedlibrary` | Loaded libraries |
| `info files` | Sections |
| `info functions` | All functions |
| `info variables` | Global variables |
| `info threads` | Thread list |
| `thread n` | Switch thread |
| `info signals` | Signal handling |
| `info target` | Target info |

## Source and Symbols

| Command | Description |
|---------|-------------|
| `list` | Show source |
| `list func` | Show function source |
| `disassemble` | Disassemble current |
| `disassemble func` | Disassemble function |
| `disassemble /r` | With raw bytes |
| `info functions regex` | Find functions |
| `info types regex` | Find types |
| `ptype type` | Show type definition |
| `whatis expr` | Show expression type |

## Files and Symbols

| Command | Description |
|---------|-------------|
| `file binary` | Load binary |
| `symbol-file file` | Load symbols |
| `add-symbol-file file addr` | Add symbols |
| `info sources` | Source files |
| `set sysroot path` | Set sysroot |

## Threads and Signals

| Command | Description |
|---------|-------------|
| `thread n` | Switch to thread |
| `thread apply all bt` | Backtrace all threads |
| `info threads` | List threads |
| `handle SIGINT nostop` | Don't stop on signal |
| `signal SIG` | Send signal |

## Catchpoints

| Command | Description |
|---------|-------------|
| `catch syscall` | Break on syscall |
| `catch syscall write` | Specific syscall |
| `catch load` | Break on library load |
| `catch throw` | Break on C++ throw |
| `catch catch` | Break on C++ catch |

## Convenience Variables

| Variable | Description |
|----------|-------------|
| `$_` | Last value examined |
| `$__` | Value before $_ |
| `$_exitcode` | Exit code |
| `$_siginfo` | Signal info |
| `$bpnum` | Last breakpoint number |

## Expressions

### Operators

- Arithmetic: `+ - * / %`
- Comparison: `== != < > <= >=`
- Logical: `&& || !`
- Bitwise: `& | ^ ~ << >>`
- Pointer: `* &`

### Cast

```bash
p (int)$rax
p (char *)$rdi
p *(struct foo *)0x401234
```

## Output Settings

| Command | Description |
|---------|-------------|
| `set print pretty on` | Pretty print structs |
| `set print array on` | Print arrays nicely |
| `set print elements 0` | No array limit |
| `set pagination off` | No paging |
| `set confirm off` | No confirmations |
| `set disassembly-flavor intel` | Intel syntax |

## Logging

| Command | Description |
|---------|-------------|
| `set logging on` | Enable logging |
| `set logging file name` | Set log file |
| `set logging overwrite on` | Overwrite log |
| `show logging` | Show settings |

## Scripting

| Command | Description |
|---------|-------------|
| `source file` | Execute commands from file |
| `define name` | Define command |
| `document name` | Document command |
| `if/else/end` | Conditional |
| `while/end` | Loop |
| `echo text` | Print text |
| `printf fmt, args` | Formatted print |
| `shell cmd` | Execute shell command |
