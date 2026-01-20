# Parallel Flow Examples

## Example 1: Multi-Module Security Analysis

**User request:** "Analyze all modules for security issues"

**Analysis:**
- Task type: Cognitive (requires understanding code)
- Parallelizable units: Modules (src/auth, src/api, src/db)
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

**User request:** "Convert all images to webp"

**Analysis:**
- Task type: Command (simple transformation)
- Parallelizable units: Each image file
- Dependencies: None
- Method: GNU parallel

**Execution:**
```bash
parallel cwebp -q 80 {} -o {.}.webp ::: images/*.png images/*.jpg
```

---

## Example 3: Parallel API Testing

**User request:** "Test all API endpoints"

**Analysis:**
- Task type: Hybrid (run commands, analyze results)
- Parallelizable units: Each endpoint
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

**User request:** "Summarize all markdown docs"

**Analysis:**
- Task type: Cognitive (reading and summarizing)
- Parallelizable units: Each markdown file
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

**User request:** "Run linting on all packages"

**Analysis:**
- Task type: Command
- Parallelizable units: Each package
- Method: GNU parallel

**Execution:**
```bash
parallel --tag 'cd {} && npm run lint 2>&1' ::: packages/*
```

---

## Example 6: Mixed Agent + Shell

**User request:** "Find and fix all TODO comments"

**Analysis:**
- Task type: Hybrid
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

**User request:** "Check dependencies for vulnerabilities"

**Analysis:**
- Task type: Command
- Parallelizable units: Each package.json location
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
