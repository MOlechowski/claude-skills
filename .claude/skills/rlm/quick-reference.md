# RLM Quick Reference

## Two Operation Modes

| Mode | When | Agents | Subagent Type |
|------|------|--------|---------------|
| **Investigation** | Answer questions about code | 3-5 | Explore |
| **Bulk Processing** | Analyze all files systematically | 5-10 | general-purpose |

## Mode 1: Investigation Pattern

```
Task(
  description="Explore error handling patterns",
  prompt="Search the codebase for...",
  subagent_type="Explore",
  run_in_background=true
)
```

**Agent strategy (broad + narrow):**
| Agent | Focus |
|-------|-------|
| 1 | Broad pattern search |
| 2 | Architecture/structure |
| 3 | Targeted file analysis |
| 4 | (optional) Related code paths |
| 5 | (optional) Test coverage |

## Mode 2: Bulk Processing Pattern

```
Task(
  description="Analyze auth module",
  prompt="Analyze src/auth/. Write to /tmp/rlm_auth.json",
  subagent_type="general-purpose",
  run_in_background=true
)
```

**Scaling:**
- Max 10 concurrent agents
- 10-20 files per agent
- Group by: directory, file type, or domain

## Four-Stage Pipeline

| Stage | Purpose | Tools |
|-------|---------|-------|
| Index | Scan structure | `find`, `ls`, `tree` |
| Filter | Narrow candidates | `rg`, `grep`, `rlm.py peek` |
| Map | Parallel process | Background agents |
| Reduce | Synthesize | `jq` merge |

## Index Commands

```bash
# Count files by type
find . -type f -name "*.py" | wc -l

# List file structure
find . -type f \( -name "*.ts" -o -name "*.tsx" \) | head -50

# Tree view
tree -I 'node_modules|.git' --dirsfirst
```

## Filter Commands

```bash
# Files containing pattern (ripgrep)
rg -l "pattern" --type py

# Files with match count
rg -c "TODO" --type py | grep -v ":0$" | sort -t: -k2 -rn

# grep alternative
grep -rl "pattern" --include="*.go" .
```

## Agent Output Pattern

```
Task(
  description="Analyze batch 1",
  prompt="Analyze these files:
- file1.py
- file2.py

Write findings to /tmp/rlm_0.json as JSON:
{\"category\": \"...\", \"findings\": [...]}",
  subagent_type="general-purpose",
  run_in_background=true
)
```

## Collect & Merge Results

```bash
# Merge all agent outputs
jq -s '.' /tmp/rlm_*.json > /tmp/report.json

# Aggregate findings
jq -s '[.[].findings] | add' /tmp/rlm_*.json

# Filter by severity
jq '[.[].findings[] | select(.severity == "high")]' /tmp/report.json

# Filter by file
jq '[.[].findings[] | select(.file | contains("auth"))]' /tmp/report.json
```

## Python Engine (Optional)

```bash
# Scan and index
python3 ~/.claude/skills/rlm/rlm.py scan

# Search with context
python3 ~/.claude/skills/rlm/rlm.py peek "search_term"

# Get chunks
python3 ~/.claude/skills/rlm/rlm.py chunk --pattern "*.py"
```

## Constraints

| Do | Don't |
|----|-------|
| Use Explore agents for questions | `cat *` or `cat *.py` |
| Use general-purpose for bulk | Spawn > 10 concurrent agents |
| Filter before spawning agents | Load many files into main context |
| Write agent outputs to /tmp/ | Sequential processing in main context |
| Use descriptive agent names | Generic descriptions |

## Quick Decision Tree

```
What's your task?
    │
    ├─► Question about code
    │   └─► Investigation mode (3-5 Explore agents)
    │       - Broad search agent
    │       - Structure/architecture agent
    │       - Targeted analysis agent
    │
    ├─► Analyze all files
    │   └─► Bulk mode (5-10 general-purpose agents)
    │       - Group by directory or file type
    │       - Max 10-20 files per agent
    │       - Write outputs to /tmp/rlm_*.json
    │
    └─► Simple file read
        └─► Standard tools (no RLM needed)
```
