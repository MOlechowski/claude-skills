# RLM Quick Reference

## Context Engine (rlm.py)

All commands: `python3 ~/.claude/skills/rlm/scripts/rlm.py <command> [args]`
All commands support: `--output /path/to/file.json`

| Command | Purpose | Reads Content? |
|---------|---------|---------------|
| `stats` | Codebase overview | No |
| `stats --type py` | Filtered stats | No |
| `grep "pattern" --type py` | Regex search (streaming) | Yes, one file at a time |
| `peek "term" --context 300` | Substring search with context | Yes, one file at a time |
| `read path/to/file --lines 50-100` | Read file or line range | Yes, single file |
| `chunk --type py --size 15` | Partition files for agents | No |

## Fallback (Without rlm.py)

| rlm.py | Native equivalent |
|--------|-------------------|
| `stats` | `find . -type f \| wc -l` + `tree -L 2` |
| `grep` | Grep tool or `rg -l "pattern" --type py` |
| `peek` | Grep tool with `-C` context |
| `read` | Read tool with offset/limit |
| `chunk` | Glob + manual partitioning |

## Pipeline

```
Index (stats) → Filter (grep/peek) → Map (agents) → Reduce (jq merge)
```

## Strategy Decision Tree

```
Run: rlm.py stats [--type X]
    │
    ▼
How many candidate files?
    │
    ├── 0 files
    │   → Wrong pattern. Adjust filter.
    │
    ├── 1-4 files
    │   → PEEK / GREP+READ
    │     Handle in main context. No agents.
    │
    ├── 5-50 files
    │   ├── Question about behavior/patterns?
    │   │   → FAN-OUT EXPLORE (2-5 Explore agents)
    │   │     Each agent: different angle on same question
    │   │
    │   └── Systematic analysis of each file?
    │       → PARTITION+MAP (3-5 general-purpose agents)
    │         rlm.py chunk → distribute partitions
    │
    ├── 50-200 files
    │   ├── Can partition into <5 meaningful groups?
    │   │   → PARTITION+MAP (3-5 general-purpose agents)
    │   │     Group by directory or domain
    │   │
    │   └── Partitions still complex (50+ files each)?
    │       → RECURSIVE DECOMPOSE
    │         Depth 0: split into domains (3-5 agents)
    │         Depth 1: each domain splits into modules (2-3 agents)
    │         Depth 2: leaf analysis (no further spawn)
    │
    └── 200+ files
        → RECURSIVE DECOMPOSE (mandatory)
          Coarse grouping at depth 0.
          Workers decide depth-1 strategy.
```

## Agent Patterns

### Fan-out Explore

```
Task(
  description="Trace error patterns",
  prompt="Search for error handling in this codebase...",
  subagent_type="Explore",
  run_in_background=true
)
```

### Partition + Map

```
Task(
  description="Analyze partition 1/4",
  prompt="Analyze these files: [list]
  Write to /tmp/rlm_p1.json as JSON:
  {\"partition\": 1, \"findings\": [...]}",
  subagent_type="general-purpose",
  run_in_background=true
)
```

### Recursive Decompose

```
Task(
  description="Analyze auth domain (depth 1)",
  prompt="Analyze src/auth/ for security issues.

  RECURSION RULES:
  - Current depth: 1. Max depth: 2.
  - You may spawn up to 3 sub-agents if scope has 50+ files.
  - Sub-agents write to /tmp/rlm_d2_*.json
  - Merge sub-agent results into /tmp/rlm_d1_auth.json",
  subagent_type="general-purpose",
  run_in_background=true
)
```

## Recursion Rules

| Rule | Value |
|------|-------|
| Max depth | 2 (main → worker → leaf) |
| Max total agents | 15 |
| Max concurrent (any level) | 5 |
| Leaf agents spawn | Never |
| Recurse when | Partition has 50+ files or distinct sub-problems |
| Output routing | `/tmp/rlm_d{depth}_{id}.json` |

## Guardrails

| Metric | Limit |
|--------|-------|
| Concurrent agents | 5 |
| Total agents | 15 |
| Recursion depth | 2 |
| Files per leaf agent | 20 |
| Agent timeout | 120s |
| Max spawn rounds | 3 |

## Reduce (Merge Results)

```bash
jq -s '.' /tmp/rlm_*.json > /tmp/rlm_report.json
jq -s '[.[].findings] | add' /tmp/rlm_*.json
jq '[.[].findings[] | select(.severity == "high")]' /tmp/rlm_report.json
```

## Constraints

| Do | Don't |
|----|-------|
| Run `stats` before choosing strategy | Pick strategy without data |
| Use rlm.py or rg for Index/Filter | `cat *` or load all files |
| Write outputs to `/tmp/rlm_*` | Read agent output raw into main |
| Include recursion rules in prompts | Exceed depth/agent limits |
| Clean `/tmp/rlm_*` when done | Leave temp files behind |
