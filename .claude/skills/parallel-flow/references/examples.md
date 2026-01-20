# Parallel Flow Examples

## Example 1: Multi-Module Security Analysis

**Request:** "Analyze all modules for security issues"

**Analysis:**
- Type: Cognitive (requires understanding code)
- Units: Modules (src/auth, src/api, src/db)
- Dependencies: None
- Method: Claude agents

**Execution:**
```
# Launch 3 agents in single message

Task(
  description="Analyze auth module",
  prompt="Analyze src/auth/ for security issues. Output to /tmp/pf_001/agent_0.json",
  run_in_background=true
)

Task(
  description="Analyze API module",
  prompt="Analyze src/api/ for security issues. Output to /tmp/pf_001/agent_1.json",
  run_in_background=true
)

Task(
  description="Analyze DB module",
  prompt="Analyze src/db/ for security issues. Output to /tmp/pf_001/agent_2.json",
  run_in_background=true
)
```

**Aggregation:**
```bash
jq -s '[.[].findings] | add | group_by(.severity) |
  map({severity: .[0].severity, count: length})' /tmp/pf_001/agent_*.json
```

---

## Example 2: Batch Image Conversion

**Request:** "Convert all images to webp"

**Analysis:**
- Type: Command (simple transformation)
- Units: Each image file
- Dependencies: None
- Method: GNU parallel

**Execution:**
```bash
parallel cwebp -q 80 {} -o {.}.webp ::: images/*.png images/*.jpg
```

---

## Example 3: Parallel API Testing

**Request:** "Test all API endpoints"

**Analysis:**
- Type: Hybrid (run commands, analyze results)
- Units: Each endpoint
- Dependencies: None
- Method: Shell for requests, agent for analysis

**Execution:**

Step 1 - Parallel requests:
```bash
parallel 'curl -s -w "\n%{http_code}" {} > /tmp/api_test/{#}.txt' \
  :::: endpoints.txt
```

Step 2 - Agent analysis:
```
Task(
  description="Analyze API test results",
  prompt="Review /tmp/api_test/*.txt and identify failures or issues",
  run_in_background=false
)
```

---

## Example 4: Parallel Documentation Summary

**Request:** "Summarize all markdown docs"

**Analysis:**
- Type: Cognitive (reading and summarizing)
- Units: Each markdown file
- Method: Claude agents (files grouped into partitions)

**Partition:**
```
docs/*.md (15 files) -> 3 partitions of 5 files each
```

**Execution:**
```
Task(
  description="Summarize docs batch 1",
  prompt="Summarize these docs: doc1.md, doc2.md, doc3.md, doc4.md, doc5.md
Output JSON to /tmp/pf_002/agent_0.json",
  run_in_background=true
)

Task(
  description="Summarize docs batch 2",
  prompt="Summarize these docs: doc6.md, doc7.md, doc8.md, doc9.md, doc10.md
Output JSON to /tmp/pf_002/agent_1.json",
  run_in_background=true
)

Task(
  description="Summarize docs batch 3",
  prompt="Summarize these docs: doc11.md, doc12.md, doc13.md, doc14.md, doc15.md
Output JSON to /tmp/pf_002/agent_2.json",
  run_in_background=true
)
```

---

## Example 5: Parallel Linting

**Request:** "Run linting on all packages"

**Analysis:**
- Type: Command
- Units: Each package
- Method: GNU parallel

**Execution:**
```bash
parallel --tag 'cd {} && npm run lint 2>&1' ::: packages/*
```

---

## Example 6: Mixed Agent + Shell

**Request:** "Find and fix all TODO comments"

**Analysis:**
- Type: Hybrid
- Phase 1: Shell (find TODOs)
- Phase 2: Agents (generate fixes)
- Phase 3: Shell (apply fixes)

**Execution:**

Step 1 - Find:
```bash
grep -rn "TODO" src/ > /tmp/todos.txt
```

Step 2 - Partition and analyze with agents:
```
Task(
  description="Generate fixes for TODOs 1-10",
  prompt="For each TODO in this list, generate the fix code...",
  run_in_background=true
)
```

Step 3 - Apply:
```bash
# Use agent-generated patch or sed commands
```

---

## Example 7: Concurrent Dependency Checks

**Request:** "Check dependencies for vulnerabilities"

**Analysis:**
- Type: Command
- Units: Each package.json location
- Method: Shell parallel

**Execution:**
```bash
find . -name "package.json" -not -path "*/node_modules/*" | \
  parallel 'cd {//} && npm audit --json > /tmp/audit_{#}.json 2>&1'
```

**Aggregation:**
```bash
jq -s '[.[] | select(.vulnerabilities | length > 0)]' /tmp/audit_*.json
```
