# Ghidra Headless Mode

Batch analysis without GUI using analyzeHeadless.

## Basic Syntax

```bash
$GHIDRA_HOME/support/analyzeHeadless \
    <project_location> <project_name> \
    [options]
```

## Common Workflows

### Import and Analyze Single Binary

```bash
analyzeHeadless /tmp/projects myproject \
    -import /path/to/binary
```

### Import Multiple Binaries

```bash
analyzeHeadless /tmp/projects myproject \
    -import /path/to/dir \
    -recursive
```

### Process Existing Program

```bash
analyzeHeadless /tmp/projects myproject \
    -process binary_name
```

### Run Script After Analysis

```bash
analyzeHeadless /tmp/projects myproject \
    -import /path/to/binary \
    -postScript ExportFunctions.py \
    -scriptPath ~/ghidra_scripts
```

### Pass Arguments to Script

```bash
analyzeHeadless /tmp/projects myproject \
    -process binary \
    -postScript MyScript.py "arg1" "arg2" "arg3"
```

Access in script:
```python
args = getScriptArgs()
print(args[0])  # "arg1"
```

## Options Reference

### Import Options

| Option | Description |
|--------|-------------|
| `-import FILE/DIR` | Import file or directory |
| `-recursive` | Import subdirectories |
| `-overwrite` | Replace existing program |
| `-readOnly` | Open in read-only mode |

### Processing Options

| Option | Description |
|--------|-------------|
| `-process PROGRAM` | Process specific program |
| `-noanalysis` | Skip auto-analysis |
| `-analysisTimeoutPerFile SEC` | Timeout per file |

### Script Options

| Option | Description |
|--------|-------------|
| `-preScript SCRIPT [args]` | Run before analysis |
| `-postScript SCRIPT [args]` | Run after analysis |
| `-scriptPath DIR` | Additional script paths |
| `-scriptLog FILE` | Script output to file |

### Project Options

| Option | Description |
|--------|-------------|
| `-deleteProject` | Delete project when done |
| `-log FILE` | Write log to file |

### Memory Options

```bash
# Increase heap (set before running)
export MAXMEM=8G
analyzeHeadless ...

# Or edit analyzeHeadless script
```

## Batch Processing Pattern

### Process All Binaries in Directory

```bash
#!/bin/bash
PROJECT_DIR="/tmp/ghidra_projects"
SCRIPT_DIR="./scripts"

for binary in /path/to/binaries/*; do
    name=$(basename "$binary")
    echo "Processing: $name"

    analyzeHeadless \
        "$PROJECT_DIR" "batch_project" \
        -import "$binary" \
        -overwrite \
        -postScript ExportAnalysis.py "${name}.json" \
        -scriptPath "$SCRIPT_DIR" \
        2>&1 | tee "logs/${name}.log"
done
```

### Parallel Processing

```bash
#!/bin/bash
# Using GNU parallel
find /path/to/binaries -type f | parallel -j 4 '
    analyzeHeadless /tmp/projects project_{#} \
        -import {} \
        -postScript Analyze.py \
        -deleteProject
'
```

## Script Patterns for Headless

### Export to JSON

```python
# ExportAnalysis.py
import json

def run():
    args = getScriptArgs()
    outfile = args[0] if args else f"{currentProgram.getName()}.json"

    result = {
        "name": currentProgram.getName(),
        "base": str(currentProgram.getImageBase()),
        "functions": [],
        "strings": []
    }

    # Functions
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        result["functions"].append({
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses()
        })

    # Strings
    listing = currentProgram.getListing()
    for data in listing.getDefinedData(True):
        try:
            if hasattr(data.getValue(), '__str__'):
                val = str(data.getValue())
                if len(val) >= 4:
                    result["strings"].append({
                        "address": str(data.getAddress()),
                        "value": val[:100]
                    })
        except:
            pass

    with open(outfile, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"Exported to {outfile}")

run()
```

### Find Vulnerable Functions

```python
# FindVulns.py
DANGEROUS = ["gets", "strcpy", "sprintf", "scanf", "system", "exec"]

def run():
    findings = []

    for name in DANGEROUS:
        func = getFunction(name)
        if func:
            refs = getReferencesTo(func.getEntryPoint())
            for ref in refs:
                caller = getFunctionContaining(ref.getFromAddress())
                findings.append({
                    "function": name,
                    "caller": caller.getName() if caller else "unknown",
                    "address": str(ref.getFromAddress())
                })

    args = getScriptArgs()
    outfile = args[0] if args else "vulns.txt"

    with open(outfile, 'w') as f:
        for finding in findings:
            f.write(f"{finding['function']} called from {finding['caller']} at {finding['address']}\n")

    print(f"Found {len(findings)} potential issues")

run()
```

## Error Handling

### Check Exit Code

```bash
analyzeHeadless ... ; echo "Exit code: $?"
```

Exit codes:
- 0: Success
- Non-zero: Error (check log)

### Common Errors

| Error | Solution |
|-------|----------|
| "Unable to find project" | Check project path exists |
| "Script not found" | Add -scriptPath |
| "Out of memory" | Increase MAXMEM |
| "Analysis timeout" | Use -analysisTimeoutPerFile |

## Integration with CI/CD

```yaml
# GitHub Actions example
- name: Analyze Binary
  run: |
    $GHIDRA_HOME/support/analyzeHeadless \
      /tmp/project analysis \
      -import ./binary \
      -postScript FindVulns.py vulns.json \
      -scriptPath ./scripts

- name: Check Results
  run: |
    if [ -s vulns.json ]; then
      echo "Vulnerabilities found!"
      cat vulns.json
      exit 1
    fi
```
