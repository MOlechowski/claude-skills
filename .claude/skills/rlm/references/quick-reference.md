# RLM Quick Reference

## Two Operation Modes

| Mode | When | Agents | Type |
|------|------|--------|------|
| **Investigation** | Answer code questions | 3-5 | Explore |
| **Bulk Processing** | Analyze all files | 5-10 | general-purpose |

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

**Scaling:** Max 10 agents, 10-20 files each, group by directory/type/domain

## Four-Stage Pipeline

| Stage | Purpose | Tools |
|-------|---------|-------|
| Index | Scan structure | `find`, `ls`, `tree` |
| Filter | Narrow candidates | `rg`, `grep`, `rlm.py peek` |
| Map | Parallel process | Background agents |
| Reduce | Synthesize | `jq` merge |

## Index Commands

```bash
find . -type f -name "*.py" | wc -l
find . -type f \( -name "*.ts" -o -name "*.tsx" \) | head -50
tree -I 'node_modules|.git' --dirsfirst
```

## Filter Commands

```bash
rg -l "pattern" --type py
rg -c "TODO" --type py | grep -v ":0$" | sort -t: -k2 -rn
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
jq -s '.' /tmp/rlm_*.json > /tmp/report.json
jq -s '[.[].findings] | add' /tmp/rlm_*.json
jq '[.[].findings[] | select(.severity == "high")]' /tmp/report.json
jq '[.[].findings[] | select(.file | contains("auth"))]' /tmp/report.json
```

## Python Engine (Optional)

```bash
python3 ~/.claude/skills/rlm/rlm.py scan
python3 ~/.claude/skills/rlm/rlm.py peek "search_term"
python3 ~/.claude/skills/rlm/rlm.py chunk --pattern "*.py"
```

## Constraints

| Do | Don't |
|----|-------|
| Use Explore for questions | `cat *` or `cat *.py` |
| Use general-purpose for bulk | Spawn > 10 agents |
| Filter before spawning | Load many files into main context |
| Write outputs to /tmp/ | Sequential processing in main |
| Use descriptive names | Generic descriptions |

## Quick Decision Tree

```
What's your task?
    |
    +-> Question about code
    |   -> Investigation (3-5 Explore agents)
    |
    +-> Analyze all files
    |   -> Bulk (5-10 general-purpose agents)
    |       - Group by directory/type
    |       - Write to /tmp/rlm_*.json
    |
    +-> Simple file read
        -> Standard tools (no RLM needed)
```
