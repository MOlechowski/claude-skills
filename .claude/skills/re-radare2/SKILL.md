---
name: re-radare2
description: "radare2/rizin reverse engineering framework: disassembly, analysis, patching, debugging, scripting. Use for: binary analysis, instruction patching, debug sessions, scripting with r2pipe, visual mode navigation. Triggers: radare2, r2, rizin, r2 command, radare patching, r2pipe, r2 analysis."
---

# radare2

Reverse engineering framework for binary analysis, disassembly, and patching.

## Quick Start

```bash
r2 -A binary          # Analyze binary
r2 -w binary          # Write mode (patching)
r2 -d binary          # Debug mode
r2 -qc 'aaa; afl' binary  # One-liner analysis
```

## Essential Commands

| Command | Purpose |
|---------|---------|
| `s addr` | Seek to address |
| `aaa` | Full analysis |
| `afl` | List functions |
| `pdf` | Disassemble function |
| `pdc` | Decompile function |
| `px N` | Hexdump N bytes |
| `V` / `VV` | Visual / Graph mode |

For comprehensive command reference, see: [references/commands.md](references/commands.md)

## Patching

Open in write mode: `r2 -w binary`

```bash
wa nop              # Write assembly NOP
wx 90               # Write hex byte (NOP)
wx 9090909090       # Write multiple NOPs
wao nop             # NOP over current instruction
wao jmp             # Convert to unconditional jump
```

### Common Patches

```bash
# NOP out call (5 bytes)
wx 9090909090 @ 0x401234

# Force jump (JZ -> JMP)
wx eb @ 0x401234

# Return 0 (xor eax, eax; ret)
wa "xor eax, eax; ret" @ 0x401234

# Return 1 (mov eax, 1; ret)
wa "mov eax, 1; ret" @ 0x401234
```

## Debug Mode

```bash
r2 -d binary          # Start debugging
db main               # Breakpoint at main
dc                    # Continue
ds / dso              # Step into / over
dr                    # Show registers
dr rax=0x1234         # Set register
```

## Visual Mode

```bash
V                     # Enter visual mode
VV                    # Visual graph mode
```

Navigation: `j/k` (up/down), `g` (goto), `p` (rotate modes), `:` (command), `q` (quit)

## r2pipe Scripting

```python
import r2pipe

r2 = r2pipe.open("binary")
r2.cmd("aaa")
funcs = r2.cmdj("aflj")  # JSON output
for f in funcs:
    print(f"{f['name']} @ {hex(f['offset'])}")
r2.quit()
```

For scripting patterns, see: [references/scripting.md](references/scripting.md)

## Configuration

```bash
e asm.arch=x86        # Set architecture
e asm.bits=64         # Set bits
e asm.syntax=intel    # Intel syntax
```

## Integration

For high-level RE strategy, consult `/re-expert`.
For hex-level viewing, use `/re-xxd`.
For ELF modifications, use `/re-patchelf` or `/re-objcopy`.
