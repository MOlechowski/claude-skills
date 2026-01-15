---
name: rlm
description: Process massive codebases with parallel agents.
---

# Recursive Language Model (RLM) Skill

Use this skill when:
- Analyzing large codebases (100+ files, millions of lines)
- Searching patterns across many files without loading all into context
- Processing repositories that exceed normal context limits
- Running parallel analysis with background agents

Examples:
- "analyze this large codebase"
- "scan all files for security issues"
- "find all usages of X across the entire repo"
- "process this massive repository"

You are an expert at processing massive codebases using the RLM paradigm. This skill enables handling 100+ files and millions of lines of code efficiently.

## Core Philosophy

> **"Context is an external resource, not a local variable."**

Instead of loading files directly into context, treat the filesystem as a queryable database. The Root Node (you) orchestrates sub-agents that analyze code in parallel.

## Four-Stage Pipeline

### 1. Index
Scan file structure without loading content:

```bash
# Find all relevant files
find . -type f -name "*.py" | head -100

# Or use ls for structure overview
ls -laR src/
```

### 2. Filter
Narrow candidates using pattern matching:

```bash
# Find files containing pattern
grep -rl "pattern" --include="*.ts" .

# Count matches per file
grep -rc "TODO" --include="*.py" . | grep -v ":0$"
```

### 3. Map (Parallel Processing)
Spawn background agents based on file count:

```
<50 files:     5-10 agents
50-200:        10-20 agents
200-500:       20-40 agents
500+:          40-60 agents
```

Each agent processes files independently:

```bash
# Launch background agents for each file
for file in file1.py file2.py file3.py; do
    # Each agent analyzes one file and outputs findings
done
```

Use the Task tool with `run_in_background: true` to parallelize.

### 4. Reduce
Synthesize findings from all sub-agents:
- Aggregate results
- Identify patterns across files
- Build final answer from parallel outputs

## Two Processing Modes

### Native Mode
Use standard tools for general traversal:

```bash
# Index
find . -type f -name "*.go" | wc -l

# Filter
grep -rl "func.*Error" --include="*.go" .

# Map with background agents
# (use Task tool with background agents)
```

Best for: General codebase analysis, pattern searching

### Strict Mode (Python Engine)
Use the bundled Python engine for dense data:

```bash
# Scan and index files
python3 ~/.claude/skills/rlm/rlm.py scan

# Search with context
python3 ~/.claude/skills/rlm/rlm.py peek "searchterm"

# Get chunks for processing
python3 ~/.claude/skills/rlm/rlm.py chunk --pattern "*.py"
```

Best for: State tracking, structured analysis, chunk processing

## Key Constraints

### Never Do
- `cat *` or `cat *.py` - loads too much at once
- Load many files into main context - use agents instead
- Try to process entire codebase in single pass

### Always Do
- Use `grep`/`ripgrep` to filter before loading
- Prefer `background_task` for file analysis
- Use Python scripting for state tracking across many files
- Process in parallel when possible

## Background Agent Pattern

Spawn multiple Task agents in parallel using `run_in_background: true`:

**Agent 1:**
```
Task(
  description="Analyze auth files",
  prompt="Analyze these files for security issues:
- src/auth/login.py
- src/auth/session.py

Write findings to /tmp/rlm_0.json as JSON:
{\"findings\": [{\"file\": \"\", \"line\": 0, \"issue\": \"\"}]}",
  run_in_background=true
)
```

**Agent 2:**
```
Task(
  description="Analyze API files",
  prompt="Analyze these files for security issues:
- src/api/users.py
- src/api/payments.py

Write findings to /tmp/rlm_1.json as JSON:
{\"findings\": [{\"file\": \"\", \"line\": 0, \"issue\": \"\"}]}",
  run_in_background=true
)
```

**Collect results with TaskOutput:**
```
TaskOutput(task_id=<agent1_id>)
TaskOutput(task_id=<agent2_id>)
```

**Merge with jq:**
```bash
jq -s '[.[].findings] | add' /tmp/rlm_*.json
```

## Handling Large Outputs

Agent outputs can exceed token limits. Solution: agents write to files.

**In agent prompt:**
```
"... Write your findings to /tmp/rlm_agent_0.json as JSON"
```

**Merge all agent outputs:**
```bash
jq -s '[.[].findings] | add' /tmp/rlm_*.json > /tmp/report.json
```

**Filter if report too large:**
```bash
# By severity
jq '[.[] | select(.severity == "high")]' /tmp/report.json

# By file
jq '[.[] | select(.file | contains("auth"))]' /tmp/report.json
```

## Recovery Method

If background agents fail, fall back to iterative Python:

```python
import os
import json

results = []
for root, dirs, files in os.walk('.'):
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            with open(path) as file:
                content = file.read()
                # Process and collect findings
                results.append(analyze(content))

print(json.dumps(results))
```

## Integration Notes

This skill works well with:
- **grep/ripgrep** for filtering
- **Task tool** for parallel background agents
- **Python scripts** for state management

## Quick Reference

See `quick-reference.md` for command patterns and rlm.py usage.

## Credits

Based on the Recursive Language Modeling paradigm. Original skill by [BowTiedSwan](https://github.com/BowTiedSwan/rlm-skill).
