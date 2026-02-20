---
name: obsidian-vault
description: "Obsidian vault management combining qmd (search) and notesmd-cli (CRUD). No Obsidian app needed. Use for: (1) searching notes with keyword, semantic, or hybrid search, (2) creating/editing/moving/deleting notes, (3) daily journaling, (4) frontmatter management, (5) backlink discovery, (6) AI agent memory workflows, (7) vault automation and scripting. Triggers: obsidian vault, obsidian notes, vault search, note management, daily notes, agent memory, knowledge base, markdown vault."
---

# Obsidian Vault Management

Unified vault operations using two CLI tools. No Obsidian app required.

| Tool | Role | Install |
|------|------|---------|
| **qmd** | Search (keyword, semantic, hybrid) | `npm i -g @anthropic/qmd` or check `which qmd` |
| **notesmd-cli** | CRUD, move, frontmatter, daily notes, backlinks | `brew install yakitrak/yakitrak/notesmd-cli` |

## Setup

### First-Time Setup

```bash
# 1. Set default vault for notesmd-cli
notesmd-cli set-default "VaultName"

# 2. Index vault in qmd
qmd collection add ~/path/to/vault --name vault --mask "**/*.md"
qmd embed    # generate vector embeddings for semantic search
```

### Verify

```bash
notesmd-cli print-default    # shows vault name + path
qmd status                   # shows indexed docs + embedding status
```

### Keep Index Fresh

```bash
qmd update       # re-index changed files
qmd embed        # embed new/changed docs
```

## Tool Selection

| Task | Tool | Command |
|------|------|---------|
| **Search by keyword** | qmd | `qmd search "term"` |
| **Search by meaning** | qmd | `qmd vsearch "conceptual question"` |
| **Best search quality** | qmd | `qmd query "complex question"` |
| **Create note** | notesmd-cli | `notesmd-cli create "name" --content "text"` |
| **Append to note** | notesmd-cli | `notesmd-cli create "name" --content "text" --append` |
| **Read note** | notesmd-cli | `notesmd-cli print "name"` |
| **Move/rename** | notesmd-cli | `notesmd-cli move "old" "new"` (updates all links) |
| **Delete note** | notesmd-cli | `notesmd-cli delete "name"` (permanent, no trash) |
| **Daily note** | notesmd-cli | `notesmd-cli daily` |
| **Frontmatter** | notesmd-cli | `notesmd-cli fm "name" --print / --edit / --delete` |
| **Backlinks** | notesmd-cli | `notesmd-cli print "name" --mentions` |
| **List files** | notesmd-cli | `notesmd-cli list [path]` |
| **Get document** | qmd | `qmd get vault/note.md` |
| **Batch retrieve** | qmd | `qmd multi-get "folder/*.md" --json` |

## Search Workflows

### Quick Lookup (keyword)

```bash
qmd search "authentication" -n 10
qmd search "authentication" --json      # structured output
qmd search "authentication" --md        # markdown for LLM context
```

### Conceptual Search (semantic)

```bash
qmd vsearch "how do we handle user sessions"
qmd vsearch "error recovery patterns" --json -n 5
```

### Deep Search (hybrid -- best quality)

```bash
qmd query "what decisions did we make about the API design?"
qmd query "deployment strategy" --full   # full document content
```

### Search + Read Pattern

```bash
# Find relevant notes, then read full content
qmd search "auth" --json -n 3    # find candidates
notesmd-cli print "auth-design"  # read the one you need
```

## Note CRUD

### Create

```bash
notesmd-cli create "project/meeting-notes" --content "# Meeting\n\n## Agenda\n"
notesmd-cli create "inbox" --content "\n- New thought" --append
notesmd-cli create "scratch" --content "Replaced" --overwrite
```

`--append` and `--overwrite` are mutually exclusive. Without either, existing files are unchanged.

Content supports escape sequences: `\n`, `\t`, `\r`, `\\`, `\"`, `\'`.

### Read

```bash
notesmd-cli print "architecture"                # raw content to stdout
notesmd-cli print "architecture" --mentions      # with backlinks appended
qmd get vault/architecture.md                    # via qmd (by indexed path)
```

### Move/Rename (with link updates)

```bash
notesmd-cli move "drafts/post" "published/post"
```

All `[[wikilinks]]` and `[markdown](links)` across the vault are updated automatically.

### Delete

```bash
notesmd-cli delete "scratch-note"    # permanent, no undo
```

Does NOT update links in other files referencing the deleted note.

## Daily Notes

```bash
notesmd-cli daily              # create/open today's note
notesmd-cli daily --editor     # open in $EDITOR
```

Reads `.obsidian/daily-notes.json` for folder, date format (Moment.js), and template. Template content is applied only when creating a new note.

### Append to Daily Note

```bash
DATE=$(date '+%Y-%m-%d')
notesmd-cli create "$DATE" --content "\n- $(date '+%H:%M') Task completed" --append
```

## Templates

notesmd-cli does not have a `--template` flag. Templates are plain markdown files stored in `meta/templates/` — create them once, reuse via `cp`.

### Create Templates

```bash
notesmd-cli create "meta/templates/meeting" --content "# Meeting Notes\n\n**Date:** \n**Attendees:** \n\n## Agenda\n\n## Discussion\n\n## Action Items\n\n- [ ] "

notesmd-cli create "meta/templates/project" --content "# Project Name\n\n## Overview\n\n## Goals\n\n## Timeline\n\n## Status\n"

notesmd-cli create "meta/templates/decision" --content "# Decision: \n\n## Context\n\n## Options\n\n## Decision\n\n## Rationale\n\n## Consequences\n"
```

### Create Note from Template

```bash
VAULT=$(notesmd-cli print-default --path-only)
cp "$VAULT/meta/templates/meeting.md" "$VAULT/meetings/$(date +%Y-%m-%d).md"
```

Daily note templates are handled automatically — configure in `.obsidian/daily-notes.json` with a `template` field pointing to the template note path.

## Frontmatter

```bash
notesmd-cli fm "note" --print
notesmd-cli fm "note" --edit --key "status" --value "done"
notesmd-cli fm "note" --edit --key "tags" --value "[cli,tools]"
notesmd-cli fm "note" --delete --key "draft"
```

Type inference: `true`/`false` -> boolean, `[a,b]` -> array, else string.

## AI Agent Memory

Use the vault as persistent memory for Claude Code or other AI agents.

### Store Knowledge

```bash
notesmd-cli create "memory/session-$(date +%Y%m%d)" \
  --content "# Session Notes\n\n## Learnings\n- Key insight here" \
  --overwrite
```

### Retrieve Context

```bash
# Semantic search for relevant memories
qmd vsearch "how did we solve the caching issue" --md -n 5

# Hybrid search for best results
qmd query "authentication architecture decisions" --full -n 3
```

### Append Learnings

```bash
notesmd-cli create "memory/patterns" \
  --content "\n\n## $(date '+%Y-%m-%d')\n- New pattern discovered" \
  --append
```

### Build LLM Context

```bash
# Get structured results for injection into prompts
qmd search "relevant topic" --json -n 10
qmd multi-get "memory/*.md" --json --max-bytes 20480
```

For detailed search patterns and agent memory workflows, see:
- `references/search.md` -- qmd search modes, output formats, score interpretation
- `references/agent-memory.md` -- Memory organization, retrieval patterns, automation
