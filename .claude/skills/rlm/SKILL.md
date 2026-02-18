---
name: rlm
description: "Recursive codebase analysis using the RLM paradigm. Use when: analyzing large codebases (100+ files), investigating cross-cutting patterns, recursive decomposition of complex code questions, scanning for issues across entire repos. Triggers: analyze this codebase, how does X work across the codebase, scan all files for Y, recursive analysis, RLM."
---

# Recursive Language Model (RLM) Skill

## Core Philosophy

> **"Context is an external resource, not a local variable."**

Three principles:

1. **Never load what you can query** — Filesystem is a database. Use `rlm.py` to query it.
2. **The model decides the strategy** — No fixed modes. Assess the task, pick the approach.
3. **Recurse when complexity demands it** — If a sub-task is too complex for one agent, that agent spawns its own sub-agents.

## Context Engine (rlm.py)

The streaming query engine for filesystem interaction. Never loads all files into RAM.

```bash
# Codebase overview (no file reads)
python3 ~/.claude/skills/rlm/scripts/rlm.py stats
python3 ~/.claude/skills/rlm/scripts/rlm.py stats --type py

# Regex search across files (streaming)
python3 ~/.claude/skills/rlm/scripts/rlm.py grep "pattern" --type py

# Substring search with context window
python3 ~/.claude/skills/rlm/scripts/rlm.py peek "error_handler" --context 300

# Read single file or line range
python3 ~/.claude/skills/rlm/scripts/rlm.py read src/auth/login.py --lines 50-100

# Partition files for agent distribution
python3 ~/.claude/skills/rlm/scripts/rlm.py chunk --type py --size 15 --output /tmp/rlm_chunks.json
```

All commands support `--output /path/to/file.json` to write results to file.

**Fallback**: If rlm.py unavailable, use native tools: Grep, Glob, Read, `rg`, `find`.

## Pipeline: Index → Filter → Map → Reduce

### 1. Index

Discover structure without reading file content.

```bash
python3 ~/.claude/skills/rlm/scripts/rlm.py stats
python3 ~/.claude/skills/rlm/scripts/rlm.py stats --type py
```

### 2. Filter

Narrow candidates programmatically.

```bash
python3 ~/.claude/skills/rlm/scripts/rlm.py grep "TODO|FIXME|HACK" --type py
rg -l "error" --type py
```

### 3. Map (Parallel Agents)

Distribute filtered work across agents. See Strategy Selection below.

### 4. Reduce

Aggregate results from /tmp/.

```bash
jq -s '.' /tmp/rlm_*.json > /tmp/rlm_report.json
jq -s '[.[].findings] | add | group_by(.severity)' /tmp/rlm_*.json
```

## Strategy Selection

Assess the task. Pick the strategy that fits. Combine strategies within a single analysis.

### Strategies

| Strategy | When | Agent Type | Agents |
|----------|------|------------|--------|
| **Peek** | Quick answer, few files relevant | None (main context) | 0 |
| **Grep + Read** | Pattern in known locations | None (main context) | 0 |
| **Fan-out Explore** | Question about code behavior/patterns | Explore | 2-5 |
| **Partition + Map** | Systematic analysis of many files | general-purpose | 3-8 |
| **Recursive Decompose** | Partitions still complex | general-purpose | 2-4 per level |
| **Summarize + Drill** | Large result set needs synthesis first | Mixed | 2-6 |

### Selection Logic

1. Run Index (`stats`). How many candidate files?
2. **< 5 files**: Peek or Grep+Read. Handle in main context. No agents needed.
3. **5-50 files**: Fan-out Explore (questions) or Partition+Map (analysis).
4. **50-200 files**: Partition+Map with coarse grouping. Consider Recursive Decompose if partitions remain complex.
5. **200+ files**: Recursive Decompose. Split into domains at depth 0, let workers decide depth-1 strategy.

Do NOT pick a strategy before running Index. Let the data decide.

## Agent Patterns

### Fan-out Explore

Deploy Explore agents with complementary perspectives.

```
Task(
  description="Trace error propagation paths",
  prompt="Search for error handling patterns in this codebase.
  Focus on: try/catch, error types, propagation chains.
  Write summary to /tmp/rlm_errors.md",
  subagent_type="Explore",
  run_in_background=true
)
```

Assign each agent a distinct angle: architecture, patterns, specific modules, tests, dependencies.

### Partition + Map

Split files into groups. Each general-purpose agent processes a partition.

```
Task(
  description="Analyze auth module (partition 1/4)",
  prompt="Analyze these files for security issues:
  [file list from rlm.py chunk output]

  Write findings to /tmp/rlm_p1.json as JSON:
  {\"partition\": 1, \"findings\": [{\"file\": \"\", \"line\": 0, \"issue\": \"\", \"severity\": \"\"}]}",
  subagent_type="general-purpose",
  run_in_background=true
)
```

**Partition sources**: `rlm.py chunk` output, directory boundaries, file type grouping.

### Collect Results

```
TaskOutput(task_id=<agent_id>, block=true, timeout=120000)
```

## Recursive Decomposition

When a sub-task is too complex for a single agent, that agent spawns its own sub-agents. Only `general-purpose` agents can recurse (Explore agents cannot spawn agents).

### When to Recurse

An agent should recurse when:
- Its assigned partition has 50+ files and the analysis requires understanding, not just scanning
- It discovers distinct sub-problems (e.g., "this module has 3 independent subsystems")
- The prompt explicitly allows recursion

### Depth Control

| Level | Role | Max Agents | Spawns? |
|-------|------|-----------|---------|
| 0 (Main) | Orchestrator | 5 | Yes |
| 1 (Worker) | Domain analyzer | 3 per worker | Yes |
| 2 (Leaf) | Module specialist | 0 | **Never** |

**Hard limits:**
- Max recursion depth: **2** (main → worker → leaf)
- Max total agents: **15** across all levels
- Leaf agents MUST NOT spawn sub-agents

### Recursive Agent Prompt Template

Include these instructions when spawning agents that may recurse:

```
"You are analyzing [SCOPE]. You may spawn up to [N] sub-agents if needed.

RECURSION RULES:
- Current depth: [D]. Max depth: 2.
- If depth=2, you are a leaf. Do NOT spawn agents.
- Only recurse if your scope has 50+ files or distinct sub-problems.
- Each sub-agent writes to /tmp/rlm_d[D+1]_[ID].json
- After sub-agents complete, merge their results into your output file."
```

### Output Routing

| Depth | Output Path | Merged By |
|-------|-------------|-----------|
| 2 (leaf) | `/tmp/rlm_d2_*.json` | Depth-1 parent |
| 1 (worker) | `/tmp/rlm_d1_*.json` | Main orchestrator |
| 0 (main) | `/tmp/rlm_report.json` | Main context |

## Guardrails

### Limits

| Metric | Limit |
|--------|-------|
| Max concurrent agents (any level) | 5 |
| Max total agents (all levels) | 15 |
| Max recursion depth | 2 |
| Max files per leaf agent | 20 |
| Timeout per agent | 120s |
| Max spawn rounds (main orchestrator) | 3 |

### Iteration Control

- Each round of agent spawning should have a clear purpose
- If 2 rounds produce no new information, stop
- Never "try again" — refine the query or change strategy

### Token Protection

- Agents write to `/tmp/rlm_*`, not to main context
- Main context reads only summaries and aggregated JSON
- Never `cat` agent output files raw into main context

## Constraints

### Never

- `cat *` or load entire codebases into context
- Spawn agents without running Index (`stats`) first
- Skip Filter stage for 50+ file codebases
- Exceed depth or agent limits
- Load rlm.py output raw into main context for large results

### Always

- Use `rlm.py stats` before choosing strategy
- Filter with `rlm.py grep` or `rg` before spawning agents
- Write agent outputs to `/tmp/rlm_*`
- Include recursion depth and limits in recursive agent prompts
- Clean up `/tmp/rlm_*` after delivering results

## Fallback (Without rlm.py)

If rlm.py is unavailable, use native Claude Code tools:

| rlm.py command | Native equivalent |
|----------------|-------------------|
| `stats` | `find . -type f \| wc -l` + `tree -L 2 -I 'node_modules\|.git'` |
| `grep` | Grep tool or `rg -l "pattern" --type py` |
| `peek` | Grep tool with `-C` context |
| `read` | Read tool with offset/limit |
| `chunk` | Glob + manual partitioning |

The pipeline and strategy selection remain the same. Only the tooling changes.

## Integration

- **rlm.py** for Index/Filter stages
- **Explore agents** for fan-out investigation
- **general-purpose agents** for partition+map and recursive decomposition
- **rg/grep** as rlm.py fallback for Filter
- **jq** for Reduce stage (merge and filter results)

## Quick Reference

See `quick-reference.md` for decision tree and command patterns.

## Credits

Based on the RLM paradigm ([arXiv:2512.24601](https://arxiv.org/abs/2512.24601)). Original skill by [BowTiedSwan](https://github.com/BowTiedSwan/rlm-skill).
