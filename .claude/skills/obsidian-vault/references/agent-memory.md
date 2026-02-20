# AI Agent Memory Patterns

Patterns for using an Obsidian vault as persistent memory for Claude Code and other AI agents.

## Vault Organization for Agent Memory

```
vault/
├── memory/
│   ├── patterns.md          # Reusable patterns and solutions
│   ├── decisions.md         # Architecture and design decisions
│   ├── learnings.md         # Lessons learned, debugging insights
│   └── sessions/
│       ├── 2026-02-20.md    # Per-session notes
│       └── ...
├── projects/
│   ├── project-a/
│   │   ├── overview.md
│   │   ├── architecture.md
│   │   └── tasks.md
│   └── ...
├── references/
│   ├── apis.md
│   ├── tools.md
│   └── ...
└── daily/
    ├── 2026-02-20.md
    └── ...
```

## Store Operations

### Save Session Notes

```bash
notesmd-cli create "memory/sessions/$(date +%Y-%m-%d)" \
  --content "# Session $(date '+%Y-%m-%d %H:%M')\n\n## Context\n\n## Decisions\n\n## Learnings\n" \
  --overwrite
```

### Append a Learning

```bash
notesmd-cli create "memory/learnings" \
  --content "\n\n### $(date '+%Y-%m-%d') -- Topic\n- Insight here\n- Another insight" \
  --append
```

### Record a Decision

```bash
notesmd-cli create "memory/decisions" \
  --content "\n\n### $(date '+%Y-%m-%d') -- Decision Title\n- **Context:** Why this came up\n- **Decision:** What we chose\n- **Rationale:** Why\n- **Alternatives:** What we didn't choose" \
  --append
```

### Tag with Frontmatter

```bash
notesmd-cli fm "memory/sessions/2026-02-20" --edit --key "tags" --value "[session,auth,refactor]"
notesmd-cli fm "memory/sessions/2026-02-20" --edit --key "project" --value "api-gateway"
```

## Retrieve Operations

### Semantic Recall

```bash
# "What do I know about..." queries
qmd vsearch "how did we solve the rate limiting problem" --md -n 5
qmd query "authentication architecture decisions" --full -n 3
```

### Keyword Recall

```bash
# Exact term lookup
qmd search "JWT token rotation" --json -n 10
qmd search "error: connection refused" -n 5
```

### Retrieve by Path

```bash
# Direct document access
qmd get vault/memory/decisions.md
qmd get vault/projects/api-gateway/architecture.md

# Batch retrieve project context
qmd multi-get "vault/projects/api-gateway/*.md" --json
```

### Build LLM Context from Memory

```bash
# Get relevant memories as markdown for prompt injection
qmd query "relevant topic for current task" --md -n 5

# Get all project docs under size limit
qmd multi-get "vault/projects/current/*.md" --json --max-bytes 30000

# Get recent session notes
qmd multi-get "vault/memory/sessions/*.md" --json -l 50
```

## Automation Scripts

### Auto-Capture Script

```bash
#!/usr/bin/env bash
# vault-capture: Append a timestamped entry to a memory file
# Usage: vault-capture <category> <message>
# Example: vault-capture learnings "Redis SCAN is better than KEYS for large datasets"

CATEGORY="${1:-learnings}"
shift
MESSAGE="$*"

[ -z "$MESSAGE" ] && echo "Usage: vault-capture <category> <message>" && exit 1

notesmd-cli create "memory/$CATEGORY" \
  --content "\n- $(date '+%Y-%m-%d %H:%M') -- $MESSAGE" \
  --append

echo "Captured to memory/$CATEGORY"
```

### Daily Memory Sync

```bash
#!/usr/bin/env bash
# Run after work sessions to keep search index current
qmd update
qmd embed
echo "Memory index updated: $(qmd status | grep 'Total')"
```

### Memory Search Function

```bash
# Add to ~/.zshrc or ~/.bashrc
vault_recall() {
    if [ -z "$1" ]; then
        echo "Usage: vault_recall <query>"
        return 1
    fi
    qmd query "$*" --md -n 5
}

vault_find() {
    qmd search "$*" --json -n 10
}
```

## Agent Workflow Example

A typical agent session using vault as memory:

```bash
# 1. Load context from previous sessions
qmd query "what was I working on for project X" --md -n 5

# 2. Search for relevant knowledge
qmd vsearch "error handling patterns we've established" --full -n 3

# 3. Read specific reference docs
notesmd-cli print "projects/api/architecture" --mentions

# 4. Do work...

# 5. Save learnings
notesmd-cli create "memory/learnings" \
  --content "\n\n### $(date '+%Y-%m-%d') -- API Error Handling\n- Use structured errors with codes\n- Always include request ID in error response" \
  --append

# 6. Update session log
notesmd-cli create "memory/sessions/$(date +%Y-%m-%d)" \
  --content "\n\n## $(date '+%H:%M') -- Completed API error handling refactor\n- Updated 12 endpoints\n- Added structured error types" \
  --append

# 7. Refresh index for next session
qmd update && qmd embed
```

## Tips

- **Keep notes atomic** -- one topic per note for better search relevance
- **Use frontmatter tags** -- enables filtering and organization
- **Run `qmd update && qmd embed`** after bulk writes to keep index fresh
- **Use `--md` output** for injecting search results into LLM prompts
- **Use `--json` output** for programmatic processing
- **Prefer `qmd query`** (hybrid) for important retrieval -- slower but highest quality
- **Use `notesmd-cli move`** instead of `mv` -- it updates all internal links
