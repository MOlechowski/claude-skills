# Parallel Flow Quick Reference

## Workflow

```
Input -> Analyze -> Partition -> Execute -> Aggregate -> Output
```

## Decision Matrix

| Task Type | Method | Example |
|-----------|--------|---------|
| Code analysis | Agents | "find security issues" |
| File transformation | GNU parallel | "convert images" |
| Reasoning per item | Agents | "summarize each doc" |
| Simple command | Shell | "compress files" |
| < 10 complex items | Agents | analysis tasks |
| > 50 simple items | Shell | batch operations |

## Agent Parallelism

**Launch (single message, multiple calls):**
```
Task(
  description="Process partition 0",
  prompt="...",
  subagent_type="general-purpose",
  run_in_background=true
)

Task(
  description="Process partition 1",
  prompt="...",
  subagent_type="general-purpose",
  run_in_background=true
)
```

**Collect:**
```
TaskOutput(task_id=<id_0>, block=true)
TaskOutput(task_id=<id_1>, block=true)
```

## Shell Parallelism

**GNU parallel:**
```bash
parallel command {} ::: items
find . -name "*.txt" | parallel process {}
```

**Background bash:**
```
Bash(command="...", run_in_background=true)
```

## Output

```
/tmp/parallel_flow_{id}/
├── agent_0.json
├── agent_1.json
└── aggregated.json
```

**Agent output format:**
```json
{
  "partition": 0,
  "items": ["file1.py", "file2.py"],
  "results": [...]
}
```

## Aggregation

```bash
# Merge JSON results
jq -s '[.[].results] | add' /tmp/parallel_flow_*/agent_*.json

# Count successes
ls /tmp/parallel_flow_123/agent_*.json | wc -l

# Filter by status
jq -s '[.[] | select(.status == "success")]' *.json
```

## Limits

| Resource | Limit |
|----------|-------|
| Concurrent agents | 5 max |
| Files per agent | 10-20 |
| Shell parallel jobs | CPU cores |

## Error Handling

```bash
# Check for failures
for f in agent_*.json; do
  jq empty "$f" 2>/dev/null || echo "FAILED: $f"
done

# Aggregate only successes
jq -s '[.[] | select(.error == null)]' *.json
```
