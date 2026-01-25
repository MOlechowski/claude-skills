# Anti-Analysis Techniques

Recognition and bypass strategies for common protections.

## Packing

### Detection

```bash
# Entropy analysis (packed = high entropy >7.0)
binwalk -E binary
ent binary

# Section characteristics
readelf -S binary | grep -E "\.text|\.data"
# Packed: small .text, large .data or .rsrc

# Known packer signatures
strings binary | grep -iE "UPX|ASPack|Themida|VMProtect"
```

### Common Packers

| Packer | Signature | Difficulty |
|--------|-----------|------------|
| UPX | "UPX!" in file | Easy (upx -d) |
| ASPack | .aspack section | Medium |
| PECompact | PEC2 marker | Medium |
| Themida | .themida section | Hard |
| VMProtect | .vmp sections | Very Hard |

### Generic Unpacking

1. **Find OEP (Original Entry Point)**
   - Hardware breakpoint on stack
   - Break on API calls (GetProcAddress, LoadLibrary)
   - Look for pushad/popad patterns

2. **Dump Process**
   ```bash
   # GDB
   dump memory unpacked.bin 0x400000 0x500000

   # Process dump tools
   procdump -ma PID
   ```

3. **Fix Imports**
   - Use ImpREC, Scylla
   - Rebuild IAT from memory

## Anti-Debugging

### Windows Techniques

| Technique | Detection | Bypass |
|-----------|-----------|--------|
| IsDebuggerPresent | Checks PEB.BeingDebugged | Return 0, patch PEB |
| CheckRemoteDebuggerPresent | NtQueryInformationProcess | Patch return |
| NtQueryInformationProcess | ProcessDebugPort=7 | Hook, return 0 |
| PEB.NtGlobalFlag | Checks for 0x70 | Clear flags |
| Heap Flags | Debug heap markers | Disable debug heap |
| OutputDebugString | Exception if no debugger | Ignore |
| FindWindow | Debugger window class | Hide debugger |
| RDTSC | Timing check | Single-step or skip |

### Linux Techniques

| Technique | Detection | Bypass |
|-----------|-----------|--------|
| ptrace(TRACEME) | Returns -1 if traced | LD_PRELOAD hook |
| /proc/self/status | TracerPid != 0 | Fake /proc |
| prctl(PR_SET_DUMPABLE) | Prevents attaching | Call before attach |
| SIGTRAP handling | Custom handler | Use hw breakpoints |
| Timing checks | RDTSC, clock_gettime | Patch or emulate |

### Bypass Strategies

**Patching:**
```asm
; Before
call IsDebuggerPresent
test eax, eax
jnz  detected

; After (patch jnz to jmp or nop)
call IsDebuggerPresent
test eax, eax
nop
nop
```

**GDB scripting:**
```python
# Auto-bypass IsDebuggerPresent
catch syscall ptrace
commands
  set $rax = 0
  continue
end
```

## Anti-VM Detection

### Common Checks

| Target | Check | Indicator |
|--------|-------|-----------|
| VMware | CPUID leaf 0x40000000 | "VMwareVMware" |
| VirtualBox | Registry, files | VBoxGuest.sys |
| QEMU | CPUID, /proc/cpuinfo | "QEMU" |
| Hyper-V | CPUID bit 31 | HypervisorPresent |
| Generic | MAC address prefix | 00:0C:29 (VMware) |
| Generic | Low RAM/CPU | < 2GB, 1 CPU |

### Detection Methods

```c
// CPUID check
unsigned int eax, ebx, ecx, edx;
__cpuid(0x40000000, eax, ebx, ecx, edx);
// Check for "VMwareVMware", "Microsoft Hv", etc.

// Registry (Windows)
RegOpenKeyEx(HKLM, "SOFTWARE\\VMware, Inc.\\VMware Tools", ...);

// Timing
RDTSC before/after CPUID
// VM exits cause timing anomalies
```

### Bypass

- Use bare metal for final analysis
- Patch VM checks
- Harden VM (remove tools, change MAC, increase resources)
- Use anti-detection tools (VMCloak, pafish evasion)

## Code Obfuscation

### Control Flow Flattening

**Before:**
```c
if (cond) { A(); } else { B(); }
C();
```

**After:**
```c
state = 1;
while (state != 0) {
    switch(state) {
        case 1: if (cond) state=2; else state=3; break;
        case 2: A(); state=4; break;
        case 3: B(); state=4; break;
        case 4: C(); state=0; break;
    }
}
```

### Opaque Predicates

Always true/false conditions that are hard to analyze statically:
```c
if ((x * (x + 1)) % 2 == 0)  // Always true
    real_code();
else
    fake_code();  // Never executed
```

### Dead Code Insertion

- Unreachable basic blocks
- Meaningless computations
- Never-taken branches

### Deobfuscation Approaches

1. Dynamic analysis (trace actual execution)
2. Symbolic execution (angr, Triton)
3. Pattern matching and simplification
4. Custom scripts per obfuscator

## String Encryption

### Common Patterns

| Type | Pattern | Decryption |
|------|---------|------------|
| XOR | Single/multi-byte key | Key recovery, XOR |
| RC4 | Stream cipher | Key + RC4 decrypt |
| AES | Block cipher | Key extraction |
| Stack strings | Push byte-by-byte | Trace execution |
| Base64 + XOR | Layered encoding | Decode, then XOR |

### Finding Decryption Routine

1. Set breakpoint on string-using APIs
2. Trace backwards to find decryption
3. Look for XOR loops, crypto constants

### Stack String Example

```asm
mov byte [rbp-0x10], 'f'
mov byte [rbp-0x0f], 'l'
mov byte [rbp-0x0e], 'a'
mov byte [rbp-0x0d], 'g'
```

## Self-Modifying Code

### Detection
- Writes to .text section
- VirtualProtect with PAGE_EXECUTE_READWRITE
- mprotect with PROT_EXEC | PROT_WRITE

### Analysis
1. Set memory breakpoints
2. Dump code after modification
3. Use emulator/tracer

## Anti-Disassembly

### Techniques
- Misaligned instructions
- Jump into instruction middle
- Opaque predicates confusing CFG
- Anti-recursive descent patterns

### Example
```asm
jmp short $+2
db 0xE8        ; Fake CALL opcode
; Real code continues here
```

### Handling
- Use linear sweep disassembly
- Dynamic tracing
- Manual correction in disassembler
