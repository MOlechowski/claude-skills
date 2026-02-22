# qmd Search Reference

Complete reference for searching Obsidian vaults with qmd.

## Search Modes

### Keyword Search (BM25)

Fast exact-term matching. Use when you know the specific words.

```bash
qmd search "error handling" -n 10
qmd search "error handling" -c vault          # filter to vault collection
qmd search "error handling" --full            # full document content
qmd search "error handling" --line-numbers    # with line numbers
```

### Vector Search (Semantic)

Finds conceptually similar content even with different wording.

```bash
qmd vsearch "how to handle failures gracefully"
qmd vsearch "authentication flow" -n 5
```

Requires embeddings: run `qmd embed` after indexing or updating.

### Hybrid Search (Best Quality)

Combines query expansion + BM25 + vector + LLM reranking.

```bash
qmd query "how did we decide on the auth approach?"
qmd query "database migration strategy" --full
```

Slowest but highest quality. Use for important or ambiguous queries.

## Output Formats

| Flag | Format | Best For |
|------|--------|----------|
| (none) | Human-readable text | Terminal reading |
| `--json` | JSON | Programmatic/agent workflows |
| `--md` | Markdown | LLM context injection |
| `--files` | docid,score,path,context | Scripting |
| `--csv` | CSV | Spreadsheet export |
| `--xml` | XML | Structured processing |

### JSON Output

```bash
qmd search "auth" --json -n 3
```

Returns structured array with docid, score, filepath, and context snippet.

### Markdown Output for LLM Context

```bash
qmd search "relevant topic" --md -n 5
```

Clean markdown suitable for injecting into prompts as context.

## Common Options

| Flag | Short | Description |
|------|-------|-------------|
| `-n <num>` | | Number of results (default: 5 text, 20 json/files) |
| `-c <name>` | `--collection` | Filter to specific collection |
| `--all` | | Return all matches |
| `--min-score <n>` | | Minimum similarity threshold |
| `--full` | | Full document content instead of snippet |
| `--line-numbers` | | Add line numbers to output |

## Score Interpretation

| Range | Meaning |
|-------|---------|
| 0.8 - 1.0 | Highly relevant |
| 0.5 - 0.8 | Moderately relevant |
| 0.2 - 0.5 | Somewhat relevant |
| 0.0 - 0.2 | Low relevance |

## Document Retrieval

### Single Document

```bash
qmd get vault/meeting-notes.md            # by path
qmd get "#abc123"                          # by 6-char docid hash
qmd get vault/file.md:50 -l 100           # from line 50, max 100 lines
```

### Multiple Documents

```bash
qmd multi-get "vault/projects/*.md"                  # glob pattern
qmd multi-get "file1.md,file2.md"                    # comma-separated
qmd multi-get "vault/*.md" -l 50                     # max 50 lines per file
qmd multi-get "vault/*.md" --max-bytes 20480         # skip files > 20KB
qmd multi-get "vault/*.md" --json                    # JSON output
```

## Collection Management

### Setup

```bash
qmd collection add ~/path/to/vault --name vault --mask "**/*.md"
qmd embed                       # generate embeddings
```

### Maintenance

```bash
qmd update                      # re-index changed files
qmd update --pull               # git pull first, then re-index
qmd embed                       # embed new/changed docs
qmd status                      # check index health
qmd cleanup                     # remove orphaned data, vacuum DB
```

### Multiple Indexes

```bash
qmd --index work collection add ~/work-vault --name work
qmd --index personal collection add ~/personal-vault --name personal
qmd --index work search "quarterly report"
```

## Search Patterns for Common Tasks

### Find Notes About a Topic

```bash
qmd query "what do we know about rate limiting" --full -n 5
```

### Find Notes Modified Recently

`qmd ls` shows every indexed file with its last-modified date and size. After `qmd update`, it reflects the current filesystem state regardless of source (mobile, CLI, Obsidian app, agents).

```bash
# Re-index then list by modification date (most recent first)
qmd update
qmd ls vault | awk '{print $3, $4, $0}' | sort -r | head -20 | sed 's/^[^ ]* [^ ]* //'
```

**Limitations:**
- Shows last-modified date, not creation date — editing an old note moves it to the top
- Snapshot of current state, not a log — can't query "what was added last Tuesday" without periodic snapshots

### Find and Read

```bash
# Search, then retrieve full content
qmd search "deployment" --json -n 3    # identify candidates
qmd get vault/deployment-guide.md      # read the match
```

### Build Context Window

```bash
# Retrieve multiple docs for LLM context
qmd multi-get "vault/architecture/*.md" --json --max-bytes 20480
```
