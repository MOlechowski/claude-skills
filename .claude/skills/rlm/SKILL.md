---
name: rlm
description: Process massive codebases with parallel agents.
---

# Recursive Language Model (RLM) Skill

Use this skill when:
- Investigating code behavior or patterns across a codebase
- Analyzing large codebases (100+ files, millions of lines)
- Searching patterns across many files without loading all into context
- Processing repositories that exceed normal context limits

Examples:
- "how are errors handled in this codebase?"
- "analyze this large codebase"
- "scan all files for security issues"
- "find all usages of X across the entire repo"

You are an expert at processing codebases using the RLM paradigm. This skill enables efficient analysis through parallel agents.

## Core Philosophy

> **"Context is an external resource, not a local variable."**

Instead of loading files directly into context, treat the filesystem as a queryable database. Orchestrate sub-agents that analyze code in parallel.

## Two Operation Modes

### Mode 1: Investigation (3-5 Explore Agents)

Use when answering questions about a codebase. Deploy agents with **different perspectives**:

```
Task(
  description="Explore error handling patterns",
  prompt="Search the codebase for error handling patterns...",
  subagent_type="Explore",
  run_in_background=true
)

Task(
  description="Find application structure",
  prompt="Map the architecture and key components...",
  subagent_type="Explore",
  run_in_background=true
)

Task(
  description="Examine specific file",
  prompt="Deep dive into src/api/handler.go...",
  subagent_type="Explore",
  run_in_background=true
)
```

**Agent Strategy - Broad + Narrow:**
| Agent | Focus | Purpose |
|-------|-------|---------|
| 1 | Broad pattern search | Find all instances |
| 2 | Architecture/structure | Understand context |
| 3 | Targeted file analysis | Deep dive specific code |
| 4 | (optional) Related code paths | Trace dependencies |
| 5 | (optional) Test coverage | Verify behavior |

**Real-world example:**
```
├─ Explore error handling patterns · 27 tool uses · 43.8k tokens
├─ Find integration app structure · 36 tool uses · 45.8k tokens
└─ Examine modified HTTPHeaderFormatter · 12 tool uses · 15.2k tokens
```

### Mode 2: Bulk Processing (5-10 Agents)

Use for systematic analysis of all files. Split by **file groups or categories**:

```
Scaling guidelines:
- Max 10 concurrent agents (resource limits)
- 10-20 files per agent (context efficiency)
- Group by: directory, file type, or domain
```

**Example - Security Audit:**
```
Task(
  description="Analyze auth module",
  prompt="Analyze src/auth/ for security issues.
  Write findings to /tmp/rlm_auth.json",
  subagent_type="general-purpose",
  run_in_background=true
)

Task(
  description="Analyze API endpoints",
  prompt="Analyze src/api/ for security issues.
  Write findings to /tmp/rlm_api.json",
  subagent_type="general-purpose",
  run_in_background=true
)
```

## Four-Stage Pipeline

### 1. Index
Scan file structure without loading content:

```bash
# Count files by type
find . -type f -name "*.py" | wc -l

# Structure overview
ls -laR src/ | head -50
```

### 2. Filter
Narrow candidates using pattern matching:

```bash
# Find files containing pattern
rg -l "error" --type py

# Count matches per file
rg -c "TODO" --type py | grep -v ":0$"
```

### 3. Map (Parallel Processing)

**Choose mode based on task:**

| Task Type | Mode | Agents | Subagent Type |
|-----------|------|--------|---------------|
| Answer a question | Investigation | 3-5 | Explore |
| Analyze all files | Bulk | 5-10 | general-purpose |
| Find specific pattern | Investigation | 2-3 | Explore |
| Security audit | Bulk | 5-10 | general-purpose |

### 4. Reduce
Synthesize findings from all sub-agents:

```bash
# Merge JSON outputs
jq -s '.' /tmp/rlm_*.json

# Aggregate findings
jq -s '[.[].findings] | add' /tmp/rlm_*.json
```

## Agent Output Pattern

Agents write to files to avoid context overflow:

```
Task(
  description="Analyze auth files",
  prompt="Analyze these files for security issues:
- src/auth/login.py
- src/auth/session.py

Write findings to /tmp/rlm_auth.json as JSON:
{\"category\": \"auth\", \"findings\": [{\"file\": \"\", \"line\": 0, \"issue\": \"\"}]}",
  subagent_type="general-purpose",
  run_in_background=true
)
```

**Collect results:**
```
TaskOutput(task_id=<agent_id>, block=true, timeout=60000)
```

**Merge and filter:**
```bash
# Merge all
jq -s '.' /tmp/rlm_*.json > /tmp/report.json

# Filter by severity
jq '[.[].findings[] | select(.severity == "high")]' /tmp/report.json

# Filter by file
jq '[.[].findings[] | select(.file | contains("auth"))]' /tmp/report.json
```

## Key Constraints

### Never Do
- `cat *` or `cat *.py` - loads too much at once
- Load many files into main context - use agents instead
- Spawn more than 10 concurrent agents

### Always Do
- Use `rg`/`grep` to filter before spawning agents
- Use Explore agents for investigation tasks
- Write agent outputs to /tmp/ files
- Use descriptive agent names (shown in UI)

## Python Engine (Optional)

For structured analysis, use the bundled Python engine:

```bash
# Scan and index files
python3 ~/.claude/skills/rlm/rlm.py scan

# Search with context
python3 ~/.claude/skills/rlm/rlm.py peek "searchterm"

# Get chunks for processing
python3 ~/.claude/skills/rlm/rlm.py chunk --pattern "*.py"
```

## Recovery Method

If background agents fail, fall back to iterative processing:

```python
import os, json

results = []
for root, dirs, files in os.walk('.'):
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            with open(path) as file:
                content = file.read()
                results.append(analyze(content))

print(json.dumps(results))
```

## Integration

Works well with:
- **Explore agents** for codebase investigation
- **rg/grep** for filtering before agent spawn
- **jq** for merging and filtering results
- **Python scripts** for state management

## Quick Reference

See `quick-reference.md` for command patterns and rlm.py usage.

## Credits

Based on the Recursive Language Modeling paradigm. Original skill by [BowTiedSwan](https://github.com/BowTiedSwan/rlm-skill).
