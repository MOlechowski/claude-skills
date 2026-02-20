---
name: dev-swarm
description: "Parallelize tasks using Claude agents. Use when: processing multiple files/items concurrently, running analysis across independent code modules, batch operations with cognitive tasks. Triggers: parallelize this task, run on all files in parallel, analyze modules concurrently, batch process these items."
---

# Parallel Flow Skill

## Workflow

```
Input -> Analyze -> Partition -> Execute (parallel) -> Aggregate -> Output
```

## Phase 1: Analyze

Determine:

### Task Type

| Type | Characteristics | Parallel Method |
|------|-----------------|-----------------|
| **Cognitive** | Requires reasoning, analysis, understanding | Claude agents |
| **Command** | Simple shell command per item | GNU parallel / xargs |
| **Hybrid** | Mix of both | Agents for logic, shell for execution |

### Parallelizable Units

Independent units that run concurrently:
- **Files**: Each file processed independently
- **Modules**: Code directories/packages
- **Items**: List elements, URLs, records
- **Chunks**: Portions of large data

### Dependencies

Check for blockers:
- Shared state or resources
- Sequential ordering requirements
- Resource contention (same output file, limited API)
- Circular dependencies

**If dependencies exist:** Fall back to sequential or find independent subsets

## Phase 2: Partition

### Strategy

**By count:**
```
Items: [A, B, C, D, E, F]
Partitions (3 agents): [[A, B], [C, D], [E, F]]
```

**By size:**
- Group small items together
- Keep large items separate
- Target ~equal work per partition

**By category:**
- Group related items (same directory, same type)
- Separate unrelated items

### Limits

- **Max concurrent agents:** 5 (avoid overwhelming system)
- **Max items per agent:** 10-20 files (keep context manageable)
- **Shell parallel jobs:** Match CPU cores or I/O capacity

### Output Strategy

Each parallel unit needs a defined output location:
```
/tmp/parallel_flow_{task_id}/
  agent_0.json
  agent_1.json
  agent_2.json
  aggregated.json
```

## Phase 3: Execute

### Agent Parallelism (Cognitive Tasks)

For tasks requiring reasoning, analysis, or understanding:

**Launch multiple agents in single message:**

```
Task(
  description="Analyze auth module",
  prompt="Analyze these files for security issues:
- src/auth/login.py
- src/auth/session.py

Output JSON to /tmp/parallel_flow_123/agent_0.json:
{
  \"partition\": 0,
  \"files\": [...],
  \"findings\": [{\"file\": \"\", \"line\": 0, \"issue\": \"\", \"severity\": \"\"}]
}",
  subagent_type="general-purpose",
  run_in_background=true
)

Task(
  description="Analyze API module",
  prompt="Analyze these files for security issues:
- src/api/users.py
- src/api/payments.py

Output JSON to /tmp/parallel_flow_123/agent_1.json:
{...same structure...}",
  subagent_type="general-purpose",
  run_in_background=true
)
```

**Critical:** Launch all agents in a single message for true parallelism.

**Collect results:**
```
TaskOutput(task_id=<agent_0_id>, block=true)
TaskOutput(task_id=<agent_1_id>, block=true)
```

### Shell Parallelism (Command Tasks)

For simple command execution per item:

**Using GNU parallel:**
```bash
parallel convert {} {.}.png ::: *.jpg
```

**Using Bash run_in_background:**
```
Bash(
  command="find . -name '*.log' | parallel gzip",
  run_in_background=true
)
```

**For complex shell orchestration, see the `cli-parallel` skill.**

### Hybrid Execution

When tasks require both:
1. Use agents to generate/plan commands
2. Execute commands via shell parallelism
3. Use agents to analyze results

## Phase 4: Aggregate

### Collect Outputs

```bash
# Merge JSON outputs
jq -s '[.[].findings] | add' /tmp/parallel_flow_*/agent_*.json > aggregated.json
```

### Handle Partial Failures

```bash
# Check which succeeded
for f in /tmp/parallel_flow_123/agent_*.json; do
  if [ -f "$f" ] && jq empty "$f" 2>/dev/null; then
    echo "$f: OK"
  else
    echo "$f: FAILED"
  fi
done
```

### Summarize

Provide:
- Summary of findings/results
- List of failed partitions
- Path to detailed output if large

## Decision Matrix

| Question | If Yes | If No |
|----------|--------|-------|
| Requires understanding code? | Agents | Shell |
| Simple transformation? | Shell | Agents |
| Reason about output? | Agents | Shell |
| Run command per file? | Shell | Agents |
| Complex logic per item? | Agents | Shell |
| >50 items, simple task? | Shell (parallel) | Agents |
| <10 items, complex task? | Agents | Shell |

## Error Handling

### Partial Failure

1. **Continue on failure:** Complete other partitions, report failures
2. **Aggregate successes:** Include only successful results
3. **Report failures:** List which partitions failed and why

### Timeouts

- Set reasonable agent timeouts
- Use `--timeout` with GNU parallel
- Fallback for hung operations

### Retries

For transient failures:
1. Identify failed partitions
2. Re-launch only failed partitions
3. Merge with previous successes

## Best Practices

### DO

- Analyze task before partitioning
- Launch all agents in single message
- Use structured JSON for aggregation
- Clean up temp files after completion
- Report progress

### DON'T

- Launch >5 concurrent agents
- Put >20 files in one partition
- Parallelize tasks with dependencies
- Skip result aggregation
- Leave temp files behind

## Quick Reference

See `quick-reference.md` for patterns.

## Examples

See `examples.md` for workflow examples.
