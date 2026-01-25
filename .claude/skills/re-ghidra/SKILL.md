---
name: re-ghidra
description: "Ghidra reverse engineering tool: GUI workflows, Python/Java scripting, headless batch analysis, decompiler API, function analysis, cross-references. Use for: Ghidra scripting, automated analysis, batch processing binaries, decompilation. Triggers: ghidra script, ghidra headless, analyzeHeadless, ghidra python, ghidra api, use ghidra."
---

# Ghidra

NSA's reverse engineering suite. GUI and headless analysis, Python/Java scripting.

## Quick Start

### Environment Check

```bash
# Verify installation
which ghidraRun || echo "Ghidra not in PATH"
echo $GHIDRA_HOME  # Should point to Ghidra install

# Launch GUI
ghidraRun
```

### First Analysis

1. File > New Project > Non-Shared Project
2. File > Import File > Select binary
3. Analyze (Yes when prompted)
4. Navigate with Symbol Tree or Go To (G)

## GUI Workflow

### Navigation

| Action | Shortcut |
|--------|----------|
| Go to address | G |
| Search strings | Search > For Strings |
| Find references | Ctrl+Shift+F |
| Rename symbol | L |
| Edit function signature | F |
| Add comment | ; |
| Undo | Ctrl+Z |

### Function Analysis

1. **Find function**: Symbol Tree > Functions, or `G` then enter name/address
2. **View decompilation**: Window > Decompile (or auto-opens)
3. **Edit signature**: Click function name, press F, set return type and params
4. **Rename variables**: Click variable in decompiler, press L

### Cross-References

- **References TO**: Right-click > References > Show References To
- **References FROM**: Right-click > References > Show References From
- **Call graph**: Window > Function Call Graph

For keyboard shortcuts, see: [references/keyboard-shortcuts.md](references/keyboard-shortcuts.md)

## Headless Mode

Batch analysis without GUI.

### Basic Usage

```bash
# Create project and import
$GHIDRA_HOME/support/analyzeHeadless \
    /project/path project_name \
    -import /path/to/binary

# Analyze existing project
$GHIDRA_HOME/support/analyzeHeadless \
    /project/path project_name \
    -process binary_name
```

### With Scripts

```bash
# Run post-analysis script
$GHIDRA_HOME/support/analyzeHeadless \
    /project/path project_name \
    -import /path/to/binary \
    -postScript ExportFunctions.py \
    -scriptPath /path/to/scripts

# Pass arguments to script
$GHIDRA_HOME/support/analyzeHeadless \
    /project/path project_name \
    -process binary \
    -postScript MyScript.py "arg1" "arg2"
```

### Common Options

| Option | Purpose |
|--------|---------|
| `-import FILE` | Import and analyze file |
| `-process NAME` | Process existing program |
| `-postScript SCRIPT` | Run script after analysis |
| `-preScript SCRIPT` | Run script before analysis |
| `-scriptPath PATH` | Additional script directories |
| `-noanalysis` | Skip auto-analysis |
| `-overwrite` | Overwrite existing program |
| `-log FILE` | Write log to file |

For detailed patterns, see: [references/headless-mode.md](references/headless-mode.md)

## Python Scripting

### Script Template

```python
# MyScript.py
# @category: Analysis
# @author: Your Name

from ghidra.program.model.symbol import SourceType

def run():
    program = getCurrentProgram()
    fm = program.getFunctionManager()

    for func in fm.getFunctions(True):
        print(f"{func.getName()} @ {func.getEntryPoint()}")

run()
```

### Common Operations

```python
# Get current program info
program = getCurrentProgram()
name = program.getName()
base = program.getImageBase()

# Get function at address
func = getFunctionAt(toAddr(0x401000))
func = getFunction("main")

# Iterate all functions
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    print(func.getName(), func.getEntryPoint())

# Get references to address
refs = getReferencesTo(toAddr(0x401000))
for ref in refs:
    print(f"From: {ref.getFromAddress()}")

# Rename function
func.setName("decrypt_string", SourceType.USER_DEFINED)

# Add comment
setPreComment(toAddr(0x401234), "Decryption routine")
setPostComment(toAddr(0x401234), "Returns decrypted string")

# Read memory
byte_val = getByte(toAddr(0x401000))
bytes_arr = getBytes(toAddr(0x401000), 16)
```

For full API reference, see: [references/scripting-api.md](references/scripting-api.md)

## Decompiler API

```python
from ghidra.app.decompiler import DecompInterface

def decompile_function(func):
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    # Decompile with 30 second timeout
    results = decomp.decompileFunction(func, 30, getMonitor())

    if results.decompileCompleted():
        # Get C code as string
        c_code = results.getDecompiledFunction().getC()
        return c_code
    else:
        print(f"Failed: {results.getErrorMessage()}")
        return None

    decomp.dispose()

# Usage
func = getFunction("main")
code = decompile_function(func)
print(code)
```

## Common Tasks

### Export All Functions

```python
# ExportFunctions.py
import json

def run():
    output = []
    fm = currentProgram.getFunctionManager()

    for func in fm.getFunctions(True):
        output.append({
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses()
        })

    args = getScriptArgs()
    outfile = args[0] if args else "functions.json"

    with open(outfile, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Exported {len(output)} functions to {outfile}")

run()
```

### Find String References

```python
# FindStringRefs.py
def run():
    target = "password"  # Or use getScriptArgs()[0]

    # Search defined strings
    listing = currentProgram.getListing()
    for data in listing.getDefinedData(True):
        try:
            val = str(data.getValue())
            if target.lower() in val.lower():
                print(f"\nFound: {val}")
                print(f"  At: {data.getAddress()}")

                # Show who references this string
                refs = getReferencesTo(data.getAddress())
                for ref in refs:
                    func = getFunctionContaining(ref.getFromAddress())
                    fname = func.getName() if func else "unknown"
                    print(f"  Referenced from: {ref.getFromAddress()} ({fname})")
        except:
            pass

run()
```

### Find Dangerous Functions

```python
# FindDangerousFunctions.py
DANGEROUS = ["gets", "strcpy", "sprintf", "scanf", "system"]

def run():
    fm = currentProgram.getFunctionManager()

    for name in DANGEROUS:
        func = getFunction(name)
        if func:
            print(f"\n=== {name} ===")
            refs = getReferencesTo(func.getEntryPoint())
            for ref in refs:
                caller = getFunctionContaining(ref.getFromAddress())
                if caller:
                    print(f"  Called from {caller.getName()} at {ref.getFromAddress()}")

run()
```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Decompiler hangs | Complex function | Increase timeout, simplify manually |
| Wrong architecture | Auto-detect failed | Manually set processor on import |
| Missing symbols | Stripped binary | Import from debug build if available |
| Script not found | Wrong path | Use -scriptPath or place in ghidra_scripts |
| Headless OOM | Large binary | Increase heap: `MAXMEM=8G analyzeHeadless` |
| Analysis incomplete | Timeout | Use -analysisTimeoutPerFile |

## Script Location

Scripts are searched in:
1. `$HOME/ghidra_scripts/`
2. `$GHIDRA_HOME/Ghidra/Features/*/ghidra_scripts/`
3. Paths specified with `-scriptPath`

## Integration

For binary analysis methodology, use `/re-expert`.
For debugging after analysis, use `/re-gdb` or `/re-lldb`.
