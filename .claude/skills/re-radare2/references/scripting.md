# radare2 Scripting Reference

Scripting patterns for r2pipe and native r2 scripting.

## r2pipe (Python)

### Basic Usage

```python
import r2pipe

# Open binary
r2 = r2pipe.open("/path/to/binary")

# Open with flags
r2 = r2pipe.open("-d /path/to/binary")  # Debug mode
r2 = r2pipe.open("-w /path/to/binary")  # Write mode

# Commands
r2.cmd("aaa")           # Execute command
output = r2.cmd("afl")  # Get output

# JSON commands (append 'j')
funcs = r2.cmdj("aflj")  # Returns parsed JSON

r2.quit()
```

### Analysis Script

```python
import r2pipe
import json

def analyze_binary(path):
    r2 = r2pipe.open(path)
    r2.cmd("aaa")  # Full analysis

    # Get basic info
    info = r2.cmdj("ij")
    print(f"Arch: {info['bin']['arch']}")
    print(f"Bits: {info['bin']['bits']}")

    # List functions
    funcs = r2.cmdj("aflj") or []
    print(f"\nFunctions: {len(funcs)}")
    for f in funcs[:10]:
        print(f"  {f['name']}: {hex(f['offset'])} ({f['size']} bytes)")

    # Find main
    main = r2.cmdj("aflj~main")
    if main:
        print(f"\nmain @ {hex(main[0]['offset'])}")
        print(r2.cmd("pdf @ main"))

    # Get strings
    strings = r2.cmdj("izj") or []
    print(f"\nStrings: {len(strings)}")

    # Imports
    imports = r2.cmdj("iij") or []
    print(f"Imports: {len(imports)}")

    r2.quit()

if __name__ == "__main__":
    import sys
    analyze_binary(sys.argv[1])
```

### Function Analysis

```python
def analyze_function(r2, func_addr):
    """Analyze a specific function."""
    # Seek to function
    r2.cmd(f"s {func_addr}")

    # Get function info
    info = r2.cmdj("afij")[0]

    result = {
        "name": info.get("name"),
        "offset": info.get("offset"),
        "size": info.get("size"),
        "nargs": info.get("nargs", 0),
        "nlocals": info.get("nlocals", 0),
        "cc": info.get("cc"),  # Calling convention
    }

    # Get basic blocks
    blocks = r2.cmdj("afbj") or []
    result["blocks"] = len(blocks)

    # Get called functions
    calls = r2.cmdj("axfj") or []
    result["calls"] = [c["name"] for c in calls if c.get("type") == "CALL"]

    # Get callers
    xrefs = r2.cmdj("axtj") or []
    result["callers"] = [x["from"] for x in xrefs]

    return result
```

### Patching Script

```python
def patch_binary(path, patches):
    """
    Apply patches to binary.

    patches: list of (addr, hex_bytes) or (addr, "asm instruction")
    """
    r2 = r2pipe.open(f"-w {path}")

    for addr, data in patches:
        if data.startswith("0x") or all(c in "0123456789abcdef" for c in data.lower()):
            # Hex patch
            r2.cmd(f"wx {data} @ {addr}")
        else:
            # Assembly patch
            r2.cmd(f'wa "{data}" @ {addr}')
        print(f"Patched @ {hex(addr)}: {data}")

    r2.quit()
    print("Done")

# Example usage
patches = [
    (0x401234, "9090909090"),           # NOP slide
    (0x401300, "xor eax, eax; ret"),    # Return 0
    (0x401400, "eb"),                    # JZ -> JMP
]
patch_binary("binary", patches)
```

### Find Patterns

```python
def find_vulnerable_calls(r2):
    """Find potentially vulnerable function calls."""
    dangerous = ["strcpy", "sprintf", "gets", "scanf", "strcat"]

    results = []
    for func in dangerous:
        xrefs = r2.cmdj(f"axtj @ sym.imp.{func}") or []
        for xref in xrefs:
            results.append({
                "function": func,
                "caller": xref.get("fcn_name"),
                "address": hex(xref.get("from", 0)),
            })

    return results
```

## Native r2 Scripts

### Script File (.r2)

```bash
# analysis.r2
# Run with: r2 -qi analysis.r2 binary

# Analyze
aaa

# Print info
i
echo ---Functions---
afl

# Find dangerous imports
echo ---Dangerous Functions---
ii~strcpy
ii~sprintf
ii~gets

# Disassemble main
echo ---Main---
pdf @ main
```

### Conditional Logic

```bash
# Use ? for conditions
?e Hello
?vi 0x100 + 0x20   # Print value

# Iterate over functions
afl~[0]            # Get function addresses
@@f:pdf            # Disassemble each function
```

### Loop Patterns

```bash
# Iterate addresses
s 0x401000
.(loop 10 pd 1; s+1)

# Iterate functions
afl~[0] > /tmp/funcs.txt
.!cat /tmp/funcs.txt | while read f; do echo $f; done
```

## r2 One-Liners

### Analysis

```bash
# List functions
r2 -qc 'aaa; afl' binary

# Export functions as JSON
r2 -qc 'aaa; aflj' binary > functions.json

# Find strings containing "flag"
r2 -qc 'izz~flag' binary

# List imports
r2 -qc 'ii' binary

# Disassemble main
r2 -qc 'aaa; pdf @ main' binary
```

### Searching

```bash
# Search for hex pattern
r2 -qc '/x 4889e5' binary

# Search for string
r2 -qc '/ password' binary

# Search for assembly
r2 -qc '/a jmp' binary
```

### Information

```bash
# File info
r2 -qc 'i' binary

# Security features
r2 -qc 'iI~canary,nx,pic,relro' binary

# Entry point
r2 -qc 'ie' binary

# Sections
r2 -qc 'iS' binary
```

## r2ghidra Integration

```python
# Use Ghidra decompiler through r2
r2 = r2pipe.open(path)
r2.cmd("aaa")

# Decompile function with Ghidra
decomp = r2.cmd("pdg @ main")
print(decomp)

# Get decompilation as structured output
r2.cmd("pdgj @ main")  # JSON output
```

## Batch Processing

```python
import r2pipe
import os
from concurrent.futures import ProcessPoolExecutor

def analyze_one(path):
    try:
        r2 = r2pipe.open(path)
        r2.cmd("aaa")
        funcs = r2.cmdj("aflj") or []
        strings = r2.cmdj("izj") or []
        r2.quit()
        return {
            "path": path,
            "functions": len(funcs),
            "strings": len(strings),
        }
    except Exception as e:
        return {"path": path, "error": str(e)}

def batch_analyze(directory):
    binaries = [
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, f))
    ]

    with ProcessPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(analyze_one, binaries))

    return results
```

## Tips

### Performance

```python
# Disable analysis for fast open
r2 = r2pipe.open(path)
r2.cmd("e anal.autoname=false")
r2.cmd("e anal.calls=false")
r2.cmd("aa")  # Basic analysis only
```

### Error Handling

```python
def safe_cmdj(r2, cmd):
    """Safe JSON command execution."""
    try:
        result = r2.cmdj(cmd)
        return result if result else []
    except:
        return []
```

### Context Manager

```python
from contextlib import contextmanager

@contextmanager
def r2_session(path, flags=""):
    r2 = r2pipe.open(f"{flags} {path}".strip())
    try:
        yield r2
    finally:
        r2.quit()

# Usage
with r2_session("/path/to/binary", "-A") as r2:
    funcs = r2.cmdj("aflj")
```
