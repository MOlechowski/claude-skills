---
name: re-expert
description: "Reverse engineering domain expertise: analysis methodology, tool selection (Ghidra/IDA/radare2/Binary Ninja), binary formats (ELF/PE/Mach-O), vulnerability patterns, anti-analysis bypass, CTF strategies. Use for: choosing RE approach, analyzing unknown binaries, identifying obfuscation, planning analysis workflow, understanding binary structures. Triggers: reverse engineer, analyze binary, what tool for RE, malware analysis strategy, CTF reversing, binary analysis approach."
---

# Reverse Engineering Expert

Domain expertise for binary analysis and reverse engineering. Provides methodology, tool selection guidance, and analysis strategies.

For tool-specific usage, delegate to: `re-ghidra`, `re-radare2`, `re-gdb`, `re-lldb`, `re-xxd`, `re-patchelf`, `re-objcopy`.

## Analysis Methodology

### Phase 1: Triage

Quick identification before deep analysis:

```bash
# File identification
file binary
strings -n 8 binary | head -50

# ELF-specific
readelf -h binary 2>/dev/null && echo "ELF"
readelf -l binary | grep -E "INTERP|GNU_STACK"

# Check if stripped
nm binary 2>/dev/null || echo "Stripped"

# Security features (Linux)
checksec --file=binary 2>/dev/null
```

### Phase 2: Static Analysis

Analyze without execution:
1. Identify entry points (main, _start, exports)
2. Map function call graph
3. Find interesting strings (URLs, paths, errors)
4. Identify library calls (imports)
5. Recognize code patterns

### Phase 3: Dynamic Analysis

Analyze during execution:
1. Trace system calls (strace/ltrace)
2. Set breakpoints at key functions
3. Monitor memory and registers
4. Observe network activity
5. Track file operations

### When to Use Each

| Scenario | Start With |
|----------|------------|
| Unknown binary | Static (triage first) |
| Packed/obfuscated | Dynamic (unpack at runtime) |
| Network behavior | Dynamic + traffic capture |
| Algorithm extraction | Static (Ghidra decompiler) |
| CTF challenge | Static first, dynamic to verify |

## Tool Selection

### Decision Matrix

| Task | Best Tool | Alternative |
|------|-----------|-------------|
| Initial triage | `file`, `strings`, `readelf` | `binwalk` |
| Disassembly | Ghidra | radare2, IDA |
| Decompilation | Ghidra | Hex-Rays, RetDec |
| Debugging (Linux) | GDB + pwndbg | radare2 debug |
| Debugging (macOS) | LLDB | GDB |
| Hex editing | xxd | radare2, hexedit |
| ELF patching | patchelf | objcopy |
| Section manipulation | objcopy | LIEF (Python) |
| Scripted analysis | radare2 (r2pipe) | Ghidra headless |

### Tool Capabilities

**Ghidra** - Best for:
- Complex decompilation
- Large binaries
- Collaborative analysis
- Scripted batch processing

**radare2** - Best for:
- Quick CLI analysis
- In-place patching
- Scripting with r2pipe
- Minimal resource usage

**GDB/LLDB** - Best for:
- Runtime debugging
- Memory inspection
- Breakpoint-based analysis
- Register manipulation

## Binary Format Identification

### Magic Bytes

| Format | Magic | Command |
|--------|-------|---------|
| ELF | `7F 45 4C 46` | `file binary` |
| PE/COFF | `4D 5A` (MZ) | `file binary.exe` |
| Mach-O | `CF FA ED FE` (64-bit LE) | `file binary` |
| Mach-O | `FE ED FA CF` (64-bit BE) | `file binary` |
| Java class | `CA FE BA BE` | `file Class.class` |
| DEX | `64 65 78 0A` | `file classes.dex` |
| Packed (UPX) | `UPX!` in file | `strings binary \| grep UPX` |

### ELF Quick Reference

```bash
readelf -h binary      # ELF header (arch, entry, type)
readelf -l binary      # Program headers (segments)
readelf -S binary      # Section headers
readelf -s binary      # Symbol table
readelf -d binary      # Dynamic section (libs, RPATH)
```

### PE Quick Reference

```bash
objdump -x binary.exe  # All headers
objdump -p binary.exe  # PE-specific info
```

For detailed format structures, see: [references/binary-formats.md](references/binary-formats.md)

## Static vs Dynamic Analysis

```
Is the binary packed/protected?
├── Yes → Dynamic first (dump unpacked code)
└── No
    ├── Need algorithm details? → Static (decompile)
    ├── Need runtime behavior? → Dynamic (debug/trace)
    └── CTF/crackme? → Static first, dynamic to verify
```

### Signs of Packing

- High entropy (>7.0)
- Very few imports
- Few readable strings
- UPX/ASPack/Themida markers
- Small .text, large .data sections

### Unpacking Strategy

1. Find Original Entry Point (OEP)
2. Set breakpoint at OEP
3. Run until unpacker finishes
4. Dump memory
5. Fix imports if needed

## Vulnerability Pattern Recognition

### Dangerous Functions

| Function | Risk | Look For |
|----------|------|----------|
| `gets()` | Buffer overflow | Any usage |
| `strcpy()` | Buffer overflow | Unbounded copy |
| `sprintf()` | Buffer overflow | User input |
| `scanf("%s")` | Buffer overflow | No width limit |
| `printf(user)` | Format string | User-controlled format |
| `system()` | Command injection | User input in arg |
| `exec*()` | Command injection | User input |

### Memory Corruption Patterns

- Stack buffer overflow: Fixed buffer + unbounded input
- Heap overflow: malloc size vs actual write
- Use-after-free: Free then dereference
- Double-free: Same pointer freed twice
- Integer overflow: Size calculation before allocation

For detailed patterns, see: [references/vulnerability-patterns.md](references/vulnerability-patterns.md)

## Anti-Analysis Recognition

### Common Techniques

| Technique | Indicator | Bypass |
|-----------|-----------|--------|
| Packing | High entropy, few imports | Unpack/dump |
| Anti-debug | `IsDebuggerPresent`, `ptrace` | Patch checks |
| Anti-VM | CPUID checks, registry | Bare metal |
| Obfuscation | Flat CFG, opaque predicates | Deobfuscation |
| String encryption | No readable strings | Find decrypt func |

### Detection Commands

```bash
# Check entropy (packing indicator)
binwalk -E binary

# Find anti-debug (Linux)
strings binary | grep -i "ptrace\|TracerPid"

# Find anti-debug (Windows)
strings binary | grep -i "IsDebugger\|CheckRemote"
```

For bypass techniques, see: [references/anti-analysis.md](references/anti-analysis.md)

## CTF Approach

### Challenge Type Identification

| Type | Indicators | Approach |
|------|------------|----------|
| Password check | strcmp, fixed string | Find comparison |
| Keygen | Transform + compare | Reverse algorithm |
| Crackme | Anti-debug, layers | Patch or keygen |
| Pwn | Gets/strcpy, no canary | Exploit vuln |
| Obfuscated | Flat CFG, encrypted | Dynamic + patience |

### Common Patterns

**Password validation:**
1. Find strcmp/strncmp calls
2. Trace input to comparison
3. Extract expected value

**Flag construction:**
1. Find "flag{" or similar strings
2. Trace backwards to construction
3. XOR/decode if encrypted

**License check:**
1. Find validation function
2. Understand algorithm
3. Patch or keygen

For CTF-specific techniques, see: [references/ctf-patterns.md](references/ctf-patterns.md)

## Workflow Templates

### Unknown Binary Analysis

```
1. Triage
   - file, strings, checksec
   - Identify format and protections

2. Static Overview
   - Load in Ghidra/r2
   - Find main/entry
   - Map key functions

3. Targeted Analysis
   - Interesting functions
   - String references
   - Import usage

4. Dynamic Verification
   - Confirm behavior
   - Edge cases
   - Hidden functionality
```

### Malware Analysis

```
1. Safe Environment
   - Isolated VM
   - Network monitoring
   - Snapshot before run

2. Triage
   - Identify packing
   - Check for VM detection

3. Unpack (if needed)
   - Dynamic unpacking
   - Dump and fix

4. Static Analysis
   - C2 infrastructure
   - Persistence mechanisms
   - Capabilities

5. Dynamic Analysis
   - Network traffic
   - File/registry changes
   - Process behavior
```

## Skill Delegation

This skill provides methodology. Delegate to tool-specific skills:

| Task | Delegate To |
|------|-------------|
| Ghidra scripting | `/re-ghidra` |
| radare2 commands | `/re-radare2` |
| GDB debugging | `/re-gdb` |
| LLDB debugging | `/re-lldb` |
| Hex editing | `/re-xxd` |
| ELF modification | `/re-patchelf` |
| Section manipulation | `/re-objcopy` |
