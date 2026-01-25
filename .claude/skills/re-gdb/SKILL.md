---
name: re-gdb
description: "GDB debugger for reverse engineering: breakpoints, memory examination, runtime patching, register manipulation, Python scripting, enhanced GDB (pwndbg/GEF/PEDA). Use for: debugging binaries, memory patching at runtime, setting breakpoints, examining program state. Triggers: gdb, debug binary, set breakpoint, examine memory, gdb script, pwndbg, GEF, PEDA."
---

# GDB

GNU Debugger for runtime analysis, debugging, and memory patching.

## Quick Start

```bash
gdb ./binary                    # Debug binary
gdb --args ./binary arg1 arg2   # With arguments
gdb -p PID                      # Attach to process
gdb -ex "b main" -ex "r" ./binary  # With commands
```

## Essential Commands

| Command | Purpose |
|---------|---------|
| `b func` / `b *addr` | Set breakpoint |
| `r` | Run |
| `c` | Continue |
| `n` / `s` | Step over / into |
| `ni` / `si` | Step instruction |
| `x/Nx addr` | Examine memory |
| `p expr` | Print expression |
| `bt` | Backtrace |
| `i r` | Show registers |

For comprehensive command reference, see: [references/commands.md](references/commands.md)

## Memory Patching

```bash
# Write single byte
set {char}0x401234 = 0x90

# Write multiple bytes
set {int}0x401234 = 0x90909090

# Common patches
set {char}0x401234 = 0x90           # NOP
set {int}0x401234 = 0x909090eb      # JMP + NOPs
set {long}0x401234 = 0xc3           # RET
```

## Enhanced GDB

### pwndbg (Recommended)

```bash
# Install
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Key commands
vmmap                   # Memory map
checksec                # Security features
cyclic 100              # Pattern generator
cyclic -l 0x61616167    # Find offset
rop                     # ROP gadgets
telescope 20            # Smart stack view
```

### GEF

```bash
# Install
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Key commands
vmmap / checksec / pattern create / heap bins / got / canary
```

### PEDA

```bash
# Install
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit

# Key commands
checksec / vmmap / pattern create / searchmem
```

## .gdbinit Setup

```bash
# ~/.gdbinit
set disassembly-flavor intel
set pagination off
set confirm off
```

### Breakpoint Commands

```bash
b main
commands
  silent
  printf "rax = 0x%lx\n", $rax
  continue
end
```

For Python scripting, see: [references/scripting.md](references/scripting.md)

## Integration

For memory patching workflows, see `/re-xxd`.
For ELF modifications, use `/re-patchelf` or `/re-objcopy`.
On macOS, use `/re-lldb` instead.
