---
name: qmd
description: "Local on-device search engine for markdown knowledge bases. Hybrid search with BM25, vector, and LLM reranking. Use for: (1) indexing markdown collections, (2) searching notes and docs with keyword/semantic/hybrid search, (3) retrieving documents for LLM context, (4) managing collections and embeddings, (5) running MCP server for Claude integration. Triggers: qmd, search notes, index markdown, knowledge base, semantic search, find in notes."
---

# qmd

Local markdown search engine by Tobias Lutke. Indexes markdown files and provides keyword, semantic, and hybrid search — fully on-device with no cloud dependencies.

## Search Mode Selection

| Mode | Command | Speed | Quality | When to Use |
|------|---------|-------|---------|-------------|
| Keyword | `qmd search` | Fast | Exact matches | Known terms, filenames, specific phrases |
| Vector | `qmd vsearch` | Medium | Semantic | Conceptual queries, paraphrased content |
| Hybrid | `qmd query` | Slow | Best | Important queries, complex questions |

## Collection Management

### Add a Collection

```bash
# Index a directory of markdown files
qmd collection add ~/notes --name notes --mask "**/*.md"

# Index with custom glob pattern
qmd collection add ~/docs --name docs --mask "**/*.{md,txt}"
```

### List and Manage

```bash
qmd collection list                    # List all collections
qmd collection remove <name>           # Remove a collection
qmd collection rename <old> <new>      # Rename
qmd ls                                 # List all collections and file counts
qmd ls notes                           # List files in a collection
qmd ls notes/subfolder                 # List files in a subdirectory
```

### Sync with Git

```bash
qmd update              # Re-index all collections
qmd update --pull       # Git pull first, then re-index
```

## Embedding

Generate vector embeddings after adding or updating collections:

```bash
qmd embed               # Create embeddings for new/changed docs
qmd embed -f            # Force re-embed all documents
```

Run `qmd embed` after every `qmd collection add` or `qmd update`.

## Searching

### Common Options

```bash
-n <num>                # Number of results (default: 5 for text, 20 for --files/--json)
-c, --collection <name> # Filter to a specific collection
--all                   # Return all matches
--min-score <num>       # Minimum similarity score threshold
--full                  # Output full document content instead of snippet
--line-numbers          # Add line numbers to output
```

### Output Formats

```bash
# Default: human-readable text
qmd search "authentication"

# JSON (structured, best for agentic workflows)
qmd search "authentication" --json

# Files only (docid,score,filepath,context)
qmd search "authentication" --files

# Markdown (good for LLM context injection)
qmd search "authentication" --md

# CSV or XML
qmd search "authentication" --csv
qmd search "authentication" --xml
```

### Keyword Search (BM25)

```bash
qmd search "error handling" -n 10
qmd search "error handling" -c notes --full
```

### Vector Search (Semantic)

```bash
qmd vsearch "how to handle failures gracefully"
qmd vsearch "authentication flow" --json -n 5
```

### Hybrid Search (Best Quality)

Uses query expansion + BM25 + vector + LLM reranking:

```bash
qmd query "how did we decide on the auth approach?"
qmd query "database migration strategy" -c docs --full
```

### Score Interpretation

| Range | Meaning |
|-------|---------|
| 0.8 - 1.0 | Highly relevant |
| 0.5 - 0.8 | Moderately relevant |
| 0.2 - 0.5 | Somewhat relevant |
| 0.0 - 0.2 | Low relevance |

## Document Retrieval

### Get Single Document

```bash
qmd get notes/meeting-notes.md           # By path
qmd get "#abc123"                         # By 6-char docid hash
qmd get notes/file.md:50 -l 100          # From line 50, max 100 lines
```

### Get Multiple Documents

```bash
qmd multi-get "docs/*.md"                         # By glob pattern
qmd multi-get "file1.md,file2.md"                  # Comma-separated
qmd multi-get "docs/*.md" -l 50                    # Max 50 lines per file
qmd multi-get "docs/*.md" --max-bytes 20480        # Skip files > 20KB
qmd multi-get "docs/*.md" --json                   # JSON output
```

## Context Management

Add descriptive metadata to help understand document relationships:

```bash
qmd context add qmd://notes "Personal notes and journal entries"
qmd context add qmd://docs "Technical documentation for projects"
qmd context list
qmd context rm qmd://notes
```

## MCP Server

Expose qmd as an MCP server for Claude Desktop or Claude Code:

```bash
qmd mcp                          # Start MCP server (stdio transport)
qmd mcp --http                   # Start MCP server (HTTP, port 8181)
qmd mcp --http --port 9000       # Custom port
qmd mcp --http --daemon          # Run as background daemon
qmd mcp stop                     # Stop background daemon
```

MCP tools exposed: `qmd_search`, `qmd_vector_search`, `qmd_deep_search`, `qmd_get`, `qmd_multi_get`, `qmd_status`.

## Maintenance

```bash
qmd status              # Index health, collections, model info, device info
qmd cleanup             # Remove cache and orphaned data, vacuum DB
```

## Multiple Indexes

Use `--index` to maintain separate knowledge bases:

```bash
qmd --index work collection add ~/work-docs --name work-docs
qmd --index work search "quarterly report"
qmd --index personal search "recipe ideas"
```

## Workflows

### Index and Search Notes

```bash
# Initial setup
qmd collection add ~/notes --name notes --mask "**/*.md"
qmd embed

# Search
qmd query "meeting decisions about deployment"
```

### Build LLM Context

```bash
# Find relevant docs and output as markdown for context injection
qmd search "authentication" --md -n 5

# Get structured results for programmatic use
qmd query "user onboarding flow" --json -n 10

# Retrieve full content of relevant files
qmd multi-get "docs/auth/*.md" --json
```

### Keep Collections Synced

```bash
# Pull latest from git and re-index
qmd update --pull
qmd embed
```
