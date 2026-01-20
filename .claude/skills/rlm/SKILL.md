---
name: rlm
description: "Process massive codebases with parallel agents using the RLM paradigm. Use when: investigating code behavior across large codebases (100+ files), analyzing patterns without loading all files into context, scanning for issues across entire repos. Triggers: how are errors handled in this codebase, analyze this large codebase, scan all files for security issues, find all usages of X."
---

# Recursive Language Model (RLM) Skill

## Core Philosophy

> **"Context is an external resource, not a local variable."**

Treat filesystem as queryable database. Orchestrate sub-agents for parallel code analysis.

## Two Operation Modes

### Mode 1: Investigation (3-5 Explore Agents)

For answering codebase questions. Deploy agents with **different perspectives**:

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
| 3 | Targeted file analysis | Deep dive |
| 4 | (optional) Related code paths | Trace dependencies |
| 5 | (optional) Test coverage | Verify behavior |

### Mode 2: Bulk Processing (5-10 Agents)

For systematic analysis. Split by **file groups or categories**:

```
Scaling:
- Max 10 concurrent agents
- 10-20 files per agent
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
Scan structure without loading content.

```bash
find . -type f -name "*.py" | wc -l
ls -laR src/ | head -50
```

### 2. Filter
Narrow candidates with pattern matching.

```bash
rg -l "error" --type py
rg -c "TODO" --type py | grep -v ":0$"
```

### 3. Map (Parallel Processing)

| Task Type | Mode | Agents | Subagent Type |
|-----------|------|--------|---------------|
| Answer question | Investigation | 3-5 | Explore |
| Analyze all files | Bulk | 5-10 | general-purpose |
| Find pattern | Investigation | 2-3 | Explore |
| Security audit | Bulk | 5-10 | general-purpose |

### 4. Reduce
Synthesize findings:

```bash
jq -s '.' /tmp/rlm_*.json
jq -s '[.[].findings] | add' /tmp/rlm_*.json
```

## Agent Output Pattern

Write to files to avoid context overflow.

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
jq -s '.' /tmp/rlm_*.json > /tmp/report.json
jq '[.[].findings[] | select(.severity == "high")]' /tmp/report.json
jq '[.[].findings[] | select(.file | contains("auth"))]' /tmp/report.json
```

## Key Constraints

### Never
- `cat *` or `cat *.py` - loads too much
- Load many files into main context
- Spawn more than 10 concurrent agents

### Always
- Filter with `rg`/`grep` before spawning agents
- Use Explore agents for investigation
- Write agent outputs to /tmp/
- Use descriptive agent names

## Python Engine (Optional)

```bash
python3 ~/.claude/skills/rlm/rlm.py scan
python3 ~/.claude/skills/rlm/rlm.py peek "searchterm"
python3 ~/.claude/skills/rlm/rlm.py chunk --pattern "*.py"
```

## Recovery Method

Fallback if background agents fail:

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

Works with:
- **Explore agents** for codebase investigation
- **rg/grep** for filtering before spawn
- **jq** for merging/filtering results
- **Python scripts** for state management

## Quick Reference

See `quick-reference.md` for command patterns.

## Credits

Based on RLM paradigm. Original skill by [BowTiedSwan](https://github.com/BowTiedSwan/rlm-skill).
