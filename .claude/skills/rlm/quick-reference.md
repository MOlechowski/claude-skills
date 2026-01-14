# RLM Quick Reference

## Python Engine Commands

```bash
# Scan and index all files in current directory
python3 ~/.claude/skills/rlm/rlm.py scan

# Search for term with surrounding context (200 chars)
python3 ~/.claude/skills/rlm/rlm.py peek "search_term"

# Get file chunks for processing
python3 ~/.claude/skills/rlm/rlm.py chunk

# Get chunks matching pattern
python3 ~/.claude/skills/rlm/rlm.py chunk --pattern "*.py"
```

## Native Mode Commands

### Index (Scan Structure)

```bash
# Count files by type
find . -type f -name "*.py" | wc -l

# List file structure
find . -type f \( -name "*.ts" -o -name "*.tsx" \) | head -50

# Tree view (if available)
tree -I 'node_modules|.git' --dirsfirst
```

### Filter (Narrow Candidates)

```bash
# Files containing pattern
grep -rl "pattern" --include="*.go" .

# Files with match count
grep -rc "TODO" --include="*.py" . | grep -v ":0$" | sort -t: -k2 -rn

# Ripgrep (faster)
rg -l "pattern" --type py
rg -c "pattern" --type ts | sort -t: -k2 -rn
```

### Map (Parallel Processing)

```bash
# Process files in parallel (bash)
find . -name "*.py" | xargs -P 4 -I {} sh -c 'echo "Processing {}"; grep -c "def " {}'

# With Task tool (in Claude)
# Use run_in_background: true for each file
```

## Four-Stage Pipeline Summary

| Stage | Purpose | Tools |
|-------|---------|-------|
| Index | Scan structure | `find`, `ls`, `tree` |
| Filter | Narrow candidates | `grep`, `rg`, `rlm.py peek` |
| Map | Parallel process | Background agents, `xargs -P` |
| Reduce | Synthesize | Aggregate results |

## Constraints Checklist

| Do | Don't |
|----|-------|
| Filter before loading | `cat *` or `cat *.py` |
| Load 3-5 files max at once | Load entire directories |
| Use background agents | Sequential file-by-file in main context |
| Use grep/rg to search | Read files to search |
| Python for state tracking | Manual state in context |

## Background Agent Pattern

**Actual Task tool syntax:**
```
Task(
  description="Analyze batch 1",
  prompt="Analyze these files. Write to /tmp/rlm_0.json as JSON",
  run_in_background=true
)
```

**Workflow:**
1. Filter: `Grep pattern="X" output_mode="files_with_matches"`
2. Spawn: 3-5 `Task(..., run_in_background=true)`
3. Collect: `TaskOutput(task_id=<id>)`
4. Merge: `jq -s '[.[].findings] | add' /tmp/rlm_*.json`

## Merge & Filter with jq

```bash
# Merge all agent outputs
jq -s '[.[].findings] | add' /tmp/rlm_*.json > /tmp/report.json

# Filter by severity
jq '[.[] | select(.severity == "high")]' /tmp/report.json

# Filter by file
jq '[.[] | select(.file | contains("auth"))]' /tmp/report.json

# Count by severity
jq 'group_by(.severity) | map({(.[0].severity): length}) | add' /tmp/report.json

# Top 10 issues
jq '.[0:10]' /tmp/report.json
```

## Recovery: Iterative Python

When background agents fail:

```python
import os, json

results = []
for root, _, files in os.walk('.'):
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            # Process each file
            results.append(process(path))

print(json.dumps(results))
```

## rlm.py API

```python
from rlm import RLMContext

ctx = RLMContext(".")

# Load files into index
ctx.load_context("**/*.py")

# Search with context window
matches = ctx.peek("search_term", context_window=200)

# Get chunks for batch processing
chunks = ctx.get_chunks(file_pattern="*.py")
```

## Quick Decision Tree

```
Large codebase analysis?
    │
    ├─► Yes → Use RLM pipeline
    │         │
    │         ├─► Many files to search → grep/rg first
    │         │
    │         ├─► Need state tracking → Use rlm.py
    │         │
    │         └─► Parallel analysis → Background agents
    │
    └─► No → Standard file reading
```
