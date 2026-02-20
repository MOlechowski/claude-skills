---
name: re-python-expert
description: "Python reverse engineering expertise: bytecode analysis (dis, marshal, opcodes), decompilation (uncompyle6, pycdc, decompyle3), obfuscation analysis (PyArmor, pyobfuscate), frozen executable unpacking (PyInstaller, py2exe, cx_Freeze, Nuitka). Use for: .pyc/.pyo analysis, decompiling Python, unpacking frozen executables, analyzing obfuscated Python, CTF Python challenges. Triggers: python reverse, pyc analysis, decompile python, unpack pyinstaller, pyarmor, bytecode, python obfuscation, frozen python."
---

# Python Reverse Engineering Expert

Domain expertise for Python bytecode analysis, decompilation, obfuscation analysis, and frozen executable unpacking.

**Delegate to tool-specific skills:** `/re-expert`, `/re-ghidra`, `/re-frida`, `/bandit`

## Analysis Methodology

### Phase 1: Triage

Quick identification before deep analysis:

```bash
# Identify file type
file artifact

# Check for Python indicators
strings artifact | grep -i python

# Check magic bytes (pyc)
xxd -l 16 file.pyc

# Check for zip overlay (frozen exe)
unzip -l artifact.exe 2>/dev/null
```

### Phase 2: Static Analysis

Analyze without running:

1. **Version detection** - Magic bytes identify Python version
2. **Bytecode disassembly** - dis module or pycdc
3. **Decompilation** - Recover source code
4. **String extraction** - Find hardcoded values

### Phase 3: Dynamic Analysis

Runtime analysis:

1. **Tracing** - sys.settrace, Frida hooks
2. **Memory dumps** - Extract decrypted bytecode
3. **Import hooks** - Intercept module loading
4. **Debugging** - pdb, breakpoints

### When to Use Each Phase

| Scenario | Phase | Start With |
|----------|-------|------------|
| .pyc file analysis | 1 + 2 | Magic bytes, decompile |
| Frozen executable | 1 + 2 | Unpack, then decompile |
| Obfuscated Python | 2 + 3 | Static first, dynamic if needed |
| PyArmor protected | 3 | Dynamic tracing required |
| CTF challenge | 1 + 2 | Triage, targeted analysis |
| Malware analysis | 1 + 2 + 3 | Full workflow |

## Tool Selection

### Decision Matrix

| Task | Best Tool | Alternative | Notes |
|------|-----------|-------------|-------|
| Bytecode disassembly | dis module | pycdc --disasm | Built-in Python |
| Python 2.7 decompilation | uncompyle6 | pycdc | Most reliable for 2.7 |
| Python 3.0-3.8 decompilation | uncompyle6 | pycdc | Good support |
| Python 3.9+ decompilation | pycdc | decompyle3 | Best 3.9+ coverage |
| Cross-version disassembly | xdis | dis | Handles old versions |
| PyInstaller unpacking | pyinstxtractor | pyinstaller-archive-viewer | Most reliable |
| py2exe unpacking | unpy2exe | manual zip | Legacy |
| cx_Freeze unpacking | Manual unzip | - | library.zip extraction |
| Nuitka analysis | Ghidra/radare2 | IDA | Compiled to native |
| PyArmor analysis | Frida + memory dump | - | Dynamic required |
| String deobfuscation | Manual Python | - | Evaluate expressions |

### Tool Capabilities

**uncompyle6** - Python decompiler
- Python 2.7, 3.0-3.8 support
- High accuracy for supported versions
- Handles most bytecode variations
- Install: `pip install uncompyle6`

**pycdc** - Decompyle++
- Broad Python version support
- C++ implementation (fast)
- Python 3.9+ partial support
- Also provides pycdas disassembler

**decompyle3** - Fork of uncompyle6
- Python 3.7-3.8 focused
- Active development
- Install: `pip install decompyle3`

**xdis** - Cross-version disassembler
- Supports Python 1.0 to 3.12
- Version-independent bytecode handling
- Install: `pip install xdis`

**pyinstxtractor** - PyInstaller extractor
- Extracts all bundled files
- Handles encrypted archives
- Recovers PYZ contents

## Bytecode Analysis

### Magic Bytes by Python Version

| Python | Magic (hex) | Magic (int) |
|--------|-------------|-------------|
| 2.7 | 03 F3 0D 0A | 62211 |
| 3.5 | 17 0D 0D 0A | 3351 |
| 3.6 | 33 0D 0D 0A | 3379 |
| 3.7 | 42 0D 0D 0A | 3394 |
| 3.8 | 55 0D 0D 0A | 3413 |
| 3.9 | 61 0D 0D 0A | 3425 |
| 3.10 | 6F 0D 0D 0A | 3439 |
| 3.11 | A7 0D 0D 0A | 3495 |
| 3.12 | CB 0D 0D 0A | 3531 |

### Quick Version Detection

```bash
# Read magic bytes
xxd -l 4 file.pyc

# Python script to detect version
python3 -c "
import struct
with open('file.pyc', 'rb') as f:
    magic = struct.unpack('<H', f.read(2))[0]
    print(f'Magic: {magic}')
"
```

### Disassembly Commands

```bash
# Using dis module (same Python version required)
python3 -m dis file.pyc

# Using dis on code object
python3 -c "
import dis, marshal
with open('file.pyc', 'rb') as f:
    f.read(16)  # Skip header (adjust for version)
    code = marshal.load(f)
    dis.dis(code)
"

# Using xdis (cross-version)
pydisasm file.pyc
```

For detailed bytecode structure, see: [references/bytecode-reference.md](references/bytecode-reference.md)

## Decompilation Workflows

### Standard .pyc Decompilation

```bash
# Step 1: Identify Python version
xxd -l 4 file.pyc

# Step 2: Choose decompiler based on version
# Python 2.7 - 3.8:
uncompyle6 file.pyc > recovered.py

# Python 3.9+:
pycdc file.pyc > recovered.py

# Alternative:
decompyle3 file.pyc > recovered.py
```

### Batch Decompilation

```bash
# Decompile directory of pyc files
uncompyle6 -o output_dir/ *.pyc

# Recursive decompilation
find . -name "*.pyc" -exec uncompyle6 {} \; > all_sources.py
```

### Handling Decompilation Failures

| Error | Cause | Solution |
|-------|-------|----------|
| Bad magic number | Version mismatch | Use matching Python or xdis |
| Unsupported opcode | Too new Python | Try pycdc or manual dis |
| Parse error | Complex bytecode | Try different decompiler |
| Incomplete output | Partial support | Combine dis + manual analysis |

**Fallback strategy:**
```bash
# If decompilation fails, get disassembly
pycdc --disasm file.pyc > disasm.txt

# Or use Python's dis
python3 -c "
import dis, marshal
with open('file.pyc', 'rb') as f:
    f.read(16)
    code = marshal.load(f)
    dis.dis(code)
" > disasm.txt
```

## Frozen Executable Unpacking

### PyInstaller Analysis

**Identification:**
```bash
# Check for PyInstaller markers
strings executable | grep -i pyinstaller
strings executable | grep "PYZ-"

# Check for MEIPASS
strings executable | grep MEIPASS
```

**Extraction:**
```bash
# Using pyinstxtractor
python pyinstxtractor.py executable.exe

# Output structure:
# executable.exe_extracted/
# ├── PYZ-00.pyz_extracted/   # Imported modules (.pyc)
# ├── struct                   # PyInstaller metadata
# ├── pyiboot01_bootstrap.pyc  # Bootstrap
# └── your_script.pyc          # Main script
```

**Post-extraction:**
```bash
# Decompile main script
cd executable.exe_extracted
uncompyle6 your_script.pyc > your_script.py

# Decompile imported modules
cd PYZ-00.pyz_extracted
for f in *.pyc; do uncompyle6 "$f" > "${f%.pyc}.py"; done
```

### py2exe Analysis

**Identification:**
```bash
# Check for py2exe markers
strings executable.exe | grep -i py2exe
```

**Extraction:**
```bash
# Using unpy2exe
unpy2exe executable.exe

# Manual extraction (py2exe uses zipfile)
python3 -c "
import zipfile
try:
    z = zipfile.ZipFile('executable.exe')
    z.extractall('extracted')
    print('Extracted:', z.namelist())
except:
    print('Not a valid zip overlay')
"
```

### cx_Freeze Analysis

**Identification:**
```bash
# Look for library.zip
strings executable | grep library.zip
ls -la | grep library.zip
```

**Extraction:**
```bash
# Extract library.zip
unzip library.zip -d extracted/

# Main module is typically __main__.pyc
uncompyle6 extracted/__main__.pyc
```

### Nuitka Recognition

Nuitka compiles Python to C, then to native code.

**Identification:**
```bash
# No Python bytecode - native binary
file executable
# Output: ELF 64-bit / PE32+

# May contain Python strings but no .pyc
strings executable | grep -c "\.pyc"  # Usually 0
```

**Analysis approach:**
- Use binary RE tools: Ghidra, radare2, IDA
- Delegate to `/re-ghidra` or `/re-radare2`
- Look for Python C API calls

### Unpacking Decision Tree

```
File Type?
├── Has .pyc magic at offset
│   └── Direct .pyc file → Decompile
├── ZIP signature at end
│   ├── "PYZ" in strings → PyInstaller → pyinstxtractor
│   ├── "py2exe" in strings → py2exe → unpy2exe
│   └── library.zip nearby → cx_Freeze → unzip
└── Native binary (ELF/PE)
    ├── Python strings present → Embedded Python
    └── No Python artifacts → Nuitka → Binary RE
```

## Obfuscation Analysis

### Common Obfuscators

| Obfuscator | Difficulty | Detection | Approach |
|------------|------------|-----------|----------|
| PyArmor | Hard | `pytransform`, `__pyarmor__` | Dynamic + memory |
| pyobfuscate | Medium | Mangled names | Pattern matching |
| Oxyry | Medium | Encoded strings | Deobfuscation scripts |
| pyminifier | Easy | Compressed code | Decompress |
| Custom exec chains | Easy-Medium | `exec(`, `eval(` | Unwrap layers |

### PyArmor Detection

```python
# PyArmor indicators in code:
from pytransform import pyarmor_runtime
pyarmor_runtime()
__pyarmor__(__name__, __file__, b'...')

# File indicators:
# - pytransform.pyd / pytransform.so
# - license.lic
# - pytransform/__init__.py
```

**PyArmor analysis approach:**
1. Run with Frida to hook code execution
2. Intercept decrypted code objects
3. Dump to .pyc format
4. Decompile recovered bytecode

```bash
# Frida hook example (conceptual)
frida -l dump_code_objects.js target.py
```

### Simple Obfuscation Unwrapping

**exec/eval chains:**
```python
# Original obfuscated:
exec(__import__('base64').b64decode('cHJpbnQoIkhlbGxvIik='))

# Unwrap by replacing exec with print:
print(__import__('base64').b64decode('cHJpbnQoIkhlbGxvIik='))
# Output: print("Hello")
```

**String deobfuscation patterns:**

| Pattern | Example | Decode Method |
|---------|---------|---------------|
| Base64 | `b64decode('...')` | `base64.b64decode()` |
| Hex | `bytes.fromhex('...')` | `bytes.fromhex()` |
| Chr chain | `''.join(chr(i) for i in [...])` | Evaluate list |
| Zlib | `zlib.decompress(b'...')` | `zlib.decompress()` |
| XOR | `bytes([b^key for b in data])` | Apply XOR |
| Rot13 | `codecs.decode('...', 'rot13')` | `codecs.decode()` |

**Automated unwrapping:**
```python
import ast

code = open('obfuscated.py').read()

# Find exec/eval calls and extract argument
tree = ast.parse(code)
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id in ('exec', 'eval'):
                print("Found:", ast.dump(node.args[0]))
```

## Python Version Considerations

### Header Structure Differences

| Python | Header Size | Contents |
|--------|-------------|----------|
| 2.7 | 8 bytes | magic (4) + timestamp (4) |
| 3.0-3.2 | 8 bytes | magic (4) + timestamp (4) |
| 3.3-3.6 | 12 bytes | magic (4) + timestamp (4) + size (4) |
| 3.7+ | 16 bytes | magic (4) + flags (4) + timestamp/hash (4) + size/hash (4) |

### Reading Headers

```python
import struct

def read_pyc_header(filename):
    with open(filename, 'rb') as f:
        magic = struct.unpack('<HH', f.read(4))
        print(f"Magic: {magic[0]}")

        # Try 3.7+ format first
        flags = struct.unpack('<I', f.read(4))[0]
        if flags == 0:  # Timestamp-based
            timestamp = struct.unpack('<I', f.read(4))[0]
            size = struct.unpack('<I', f.read(4))[0]
            print(f"Timestamp: {timestamp}, Size: {size}")
        else:  # Hash-based
            hash1 = struct.unpack('<I', f.read(4))[0]
            hash2 = struct.unpack('<I', f.read(4))[0]
            print(f"Hash-based validation")
```

### Bytecode Changes by Version

| Version | Notable Changes |
|---------|----------------|
| 3.6 | Word-aligned bytecode, CALL_FUNCTION changed |
| 3.8 | Walrus operator (:=), positional-only params |
| 3.9 | Merged comparison opcodes |
| 3.10 | Pattern matching opcodes |
| 3.11 | Specializing adaptive interpreter, new opcodes |
| 3.12 | More inline caching |

## CTF Patterns

### Common Challenge Types

| Type | Indicators | Approach |
|------|------------|----------|
| Simple pyc | Single .pyc, flag check | Decompile, read logic |
| Frozen crackme | EXE checking serial | Unpack, patch or keygen |
| Bytecode-only | Decompilers fail | Manual dis analysis |
| Multi-layer obfuscation | exec chains | Unwrap iteratively |
| Custom VM | Non-standard opcodes | Reverse the VM |

### Bytecode Patching

```python
import marshal
import types

# Read original
with open('challenge.pyc', 'rb') as f:
    header = f.read(16)  # Adjust for version
    code = marshal.load(f)

# View bytecode
print(code.co_code.hex())

# Create modified code object (Python 3.8+)
new_bytecode = code.co_code.replace(b'\x6e', b'\x6d')  # Example patch

new_code = code.replace(co_code=new_bytecode)

# Write patched pyc
with open('patched.pyc', 'wb') as f:
    f.write(header)
    marshal.dump(new_code, f)
```

### Flag Extraction Shortcuts

```python
# Dump all constants (flags often here)
import marshal
with open('challenge.pyc', 'rb') as f:
    f.read(16)
    code = marshal.load(f)

def dump_consts(code, depth=0):
    indent = "  " * depth
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            dump_consts(const, depth+1)
        else:
            print(f"{indent}{const}")

dump_consts(code)
```

## Workflow Templates

### Unknown Python Artifact

```
1. Triage
   file artifact
   xxd -l 16 artifact
   strings artifact | grep -i python

2. Identify Type
   ├── .pyc magic → Direct bytecode
   ├── ZIP overlay → Frozen executable
   └── Native binary → Nuitka or embedded

3. Version Detection
   Check magic bytes against table

4. Extract/Decompile
   ├── .pyc → uncompyle6/pycdc
   ├── PyInstaller → pyinstxtractor + decompile
   ├── py2exe → unpy2exe + decompile
   └── Nuitka → Binary RE (delegate to /re-ghidra)

5. Analyze
   Review recovered source
   Run with tracing if obfuscated
```

### Protected Application Analysis

```
1. Identify Protection
   grep -r "pytransform\|pyarmor\|obfuscate" .
   Check for unusual import patterns

2. Static Analysis First
   Try decompilation
   Extract strings and constants
   Map code structure

3. Dynamic Analysis (if needed)
   Set up Frida hooks
   Trace code object creation
   Dump decrypted bytecode

4. Reconstruction
   Rebuild .pyc from dumped code
   Decompile recovered files
   Verify functionality
```

## Skill Delegation

| Task | Delegate To |
|------|-------------|
| General RE methodology | `/re-expert` |
| Nuitka binary analysis | `/re-ghidra` |
| Dynamic instrumentation | `/re-frida` |
| Python security scanning | `/bandit` |
| Binary debugging | `/re-gdb` or `/re-lldb` |
| Memory analysis | `/re-frida` |

## Quick Reference

### Triage Commands

```bash
file artifact                          # File type
xxd -l 16 file.pyc                     # Magic bytes
strings artifact | grep -i python      # Python indicators
unzip -l executable.exe 2>/dev/null    # Check zip overlay
```

### Decompilation Commands

```bash
uncompyle6 file.pyc > out.py           # Python 2.7-3.8
pycdc file.pyc > out.py                # Broad support
decompyle3 file.pyc > out.py           # Python 3.7-3.8
python3 -m dis file.pyc                # Disassembly only
```

### Unpacking Commands

```bash
python pyinstxtractor.py app.exe       # PyInstaller
unpy2exe app.exe                       # py2exe
unzip library.zip -d out/              # cx_Freeze
```

### Analysis Commands

```bash
# Dump constants
python3 -c "import marshal; print(marshal.loads(open('f.pyc','rb').read()[16:]).co_consts)"

# Dump names
python3 -c "import marshal; print(marshal.loads(open('f.pyc','rb').read()[16:]).co_names)"
```
