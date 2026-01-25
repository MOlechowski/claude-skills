# CTF Reverse Engineering Patterns

Common patterns and techniques for CTF challenges.

## Challenge Type Recognition

### Password/Key Check

**Indicators:**
- strcmp, strncmp, memcmp calls
- Character-by-character comparison loops
- Fixed expected value in binary

**Approach:**
1. Find comparison function
2. Set breakpoint before compare
3. Examine expected value
4. Or: extract from static analysis

### Keygen/License

**Indicators:**
- Transform function on input
- Algorithm produces checksum/hash
- Comparison with computed value

**Approach:**
1. Understand the algorithm
2. Reverse the transformation
3. Generate valid key for any input

### Crackme (Multi-layer)

**Indicators:**
- Multiple validation stages
- Anti-debug checks
- Encrypted/packed layers

**Approach:**
1. Bypass anti-debug first
2. Unpack if needed
3. Solve each layer sequentially

### Pwn (Exploitation)

**Indicators:**
- Dangerous functions (gets, strcpy)
- No stack canary
- Format string vulnerabilities

**Approach:**
1. Find vulnerability
2. Determine constraints
3. Build exploit

## Common Validation Patterns

### Direct String Compare

```c
if (strcmp(input, "s3cr3t_p4ss") == 0) {
    win();
}
```

**Finding it:**
```bash
strings binary | grep -E "pass|flag|key|secret"
```

### XOR Encoded Compare

```c
char encoded[] = {0x17, 0x0a, 0x1c, 0x1c, 0x08};  // "hello" ^ 0x5f
for (int i = 0; i < 5; i++) {
    if ((input[i] ^ 0x5f) != encoded[i]) fail();
}
```

**Solving:**
```python
encoded = [0x17, 0x0a, 0x1c, 0x1c, 0x08]
key = 0x5f
print(''.join(chr(b ^ key) for b in encoded))
```

### Character-by-Character

```c
if (input[0] != 'f') fail();
if (input[1] != 'l') fail();
if (input[2] != 'a') fail();
if (input[3] != 'g') fail();
```

**GDB approach:**
```
break *check_char
commands
  print (char)$rdi
  continue
end
run
```

### Transform Then Compare

```c
for (int i = 0; i < len; i++) {
    transformed[i] = (input[i] * 3 + 7) % 256;
}
if (memcmp(transformed, expected, len) == 0) win();
```

**Reversing:**
```python
def reverse_transform(expected):
    result = []
    for b in expected:
        for c in range(256):
            if (c * 3 + 7) % 256 == b:
                result.append(chr(c))
                break
    return ''.join(result)
```

## Flag Format Patterns

### Standard Formats
```
flag{...}
FLAG{...}
CTF{...}
picoCTF{...}
HTB{...}
```

### Finding Flag Construction

```bash
# Search for flag prefix
strings binary | grep -E "flag\{|FLAG\{|CTF\{"

# In Ghidra: Search > For Strings > filter "flag"
```

### Dynamic Flag Generation

Sometimes flag is computed at runtime:
1. Break at print/puts
2. Examine string argument
3. Or trace flag buffer writes

## Useful GDB Commands for CTF

```bash
# Find function
info functions main
info functions check

# Break on comparison
break strcmp
break strncmp
break memcmp

# Examine strings on break
x/s $rdi
x/s $rsi

# Modify return value
set $eax = 1
set $rax = 0

# Skip function
jump *($rip + N)

# Patch instruction
set {char}0x401234 = 0x90
```

## Useful radare2 Commands for CTF

```bash
# Analysis
aaa                    # Auto-analyze
afl                    # List functions
pdf @ main             # Disassemble main

# Strings
iz                     # Strings in data section
izz                    # All strings

# Cross-references
axt @ str.flag         # Who references "flag"?

# Patching (write mode: r2 -w)
wa nop @ 0x401234      # Write NOP
wx 9090 @ 0x401234     # Write hex bytes
```

## Angr for Automated Solving

```python
import angr
import claripy

# Load binary
proj = angr.Project('./challenge', auto_load_libs=False)

# Create symbolic input
flag = claripy.BVS('flag', 8 * 32)  # 32 bytes

# Start state at entry
state = proj.factory.entry_state(stdin=flag)

# Explore to find path to "Correct" or avoid "Wrong"
sm = proj.factory.simgr(state)
sm.explore(find=0x401234, avoid=0x401256)

if sm.found:
    solution = sm.found[0].solver.eval(flag, cast_to=bytes)
    print(f"Flag: {solution}")
```

## Z3 for Constraint Solving

```python
from z3 import *

# Create symbolic variables
flag = [BitVec(f'c{i}', 8) for i in range(10)]

s = Solver()

# Add constraints (from reverse engineering)
s.add(flag[0] == ord('f'))
s.add(flag[1] == ord('l'))
s.add(flag[2] + flag[3] == 200)
s.add(flag[4] ^ 0x42 == 0x23)

# Printable constraint
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[c].as_long()) for c in flag)
    print(f"Flag: {result}")
```

## Anti-Debug Bypass Patterns

### ptrace Bypass (LD_PRELOAD)

```c
// bypass.c
long ptrace(int request, ...) {
    return 0;
}
```

```bash
gcc -shared -fPIC -o bypass.so bypass.c
LD_PRELOAD=./bypass.so ./challenge
```

### Patch JNZ to JMP

```bash
# radare2
r2 -w challenge
[0x00401234]> s 0x401256    # Seek to jnz
[0x00401256]> wx eb         # Change 75 (jnz) to eb (jmp)
```

## Common Mistakes to Avoid

1. **Not checking all code paths** - Flag might be in error handler
2. **Ignoring argv/env** - Flag might need specific arguments
3. **Missing library functions** - Custom implementations of strcmp
4. **Anti-debug not bypassed** - Results differ under debugger
5. **Wrong architecture** - 32-bit binary on 64-bit system

## Quick Wins Checklist

- [ ] Run `strings` and grep for flag format
- [ ] Check for hardcoded passwords
- [ ] Look at function names (if not stripped)
- [ ] Try empty input, single char, long input
- [ ] Check if binary accepts arguments
- [ ] Look for obvious strcmp calls
