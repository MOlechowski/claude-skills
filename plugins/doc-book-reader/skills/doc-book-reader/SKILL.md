---
name: doc-book-reader
description: "Read entire books (PDF, EPUB, DOCX, TXT) and produce structured synthesis reports or convert to markdown. Orchestrates doc-extract with parallel agent coordination for chapter-aware processing. Use for: (1) reading and summarizing entire books, (2) extracting key themes and arguments from long documents, (3) producing book reports with chapter summaries, (4) processing large PDFs with parallel agents, (5) converting books to markdown files. Triggers: read book, book report, summarize book, read entire pdf, book synthesis, book analysis, convert book to markdown, book to md, doc-book-reader."
---

# doc-book-reader

Read an entire book and produce a structured synthesis report.

## Architecture

```
doc-extract (extraction) → book.py (split + chunk + report) → done
```

| Component | Role |
|-----------|------|
| `book.py` (bundled script) | Text extraction, chapter splitting, chunking, manifest generation, JSON merging |
| doc-extract (sibling plugin) | PDF/image text extraction with tiered OCR engines (heading hierarchy preserved) |
| Claude agents (Task tool) | Parallel chunk summarization |

doc-extract picks the best available engine automatically. When a heading-aware engine is available (pymupdf4llm, docling, etc.), chapter splitting is trivial (split on H1). When only pypdf is available, book.py falls back to pattern matching on `Chapter N` / `Part N` lines.

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| uv | Python package manager (runs the script) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

For best results (structured headings), install pymupdf4llm:
```bash
pip install pymupdf4llm
```

Without pymupdf4llm, extraction falls back to pypdf (flat text, no heading hierarchy).

## Quick Convert: Book to Markdown

Use the `extract` command to convert a book to markdown:

```bash
# Single markdown file
uv run scripts/book.py extract book.pdf --output book.md

# One file per chapter
uv run scripts/book.py extract book.pdf --split --output-dir ./chapters/

# To stdout (pipe-friendly)
uv run scripts/book.py extract book.pdf
```

| Flag | Purpose | Default |
|------|---------|---------|
| `--output`, `-o` | Output file path | stdout |
| `--split` | Write one `.md` file per detected chapter | off |
| `--output-dir` | Directory for `--split` output | current directory |

When using `--split`, files are named `01-chapter-title.md`, `02-chapter-title.md`, etc.

Output is JSON with file paths and word counts:
```json
{
  "mode": "split-chapters",
  "output_dir": "./chapters/",
  "chapters": 8,
  "total_words": 95000,
  "engine": "pymupdf4llm",
  "structured": true,
  "files": [...]
}
```

## Synthesis Workflow

For full book analysis with agent-powered summarization:

```
1. Chunk  →  2. Summarize (parallel agents)  →  3. Merge  →  4. Report
```

### Step 1: Chunk

```bash
uv run scripts/book.py chunk <file> [--max-words 15000]
```

Extracts text, detects chapters, and splits into `chunk_N.md` files in a session directory. Returns manifest JSON:

```json
{
  "session_dir": "/tmp/book_reader_abc123",
  "file": "/path/to/book.pdf",
  "engine": "pymupdf4llm",
  "structured": true,
  "estimated_words": 95000,
  "chapter_count": 8,
  "chunk_count": 8,
  "chunks": [
    {"id": 0, "label": "Chapter 1: Introduction", "file": "/tmp/book_reader_abc123/chunk_0.md", "word_count": 12000}
  ]
}
```

Chapters that exceed `--max-words` are sub-split into parts. Chapters within the limit remain as single chunks.

### Step 2: Summarize (parallel agents)

Launch up to 5 background agents in a **single message** using the Task tool:

```
Task(
  description="Summarize chunk N",
  prompt="Read the file <chunk_path> and write a JSON summary to <session_dir>/summary_N.json.

The JSON must follow this exact schema:
{
  \"id\": N,
  \"label\": \"Chapter title from manifest\",
  \"summary\": \"200-500 word summary of this section\",
  \"key_themes\": [\"theme1\", \"theme2\"],
  \"notable_quotes\": [{\"text\": \"exact quote\", \"page\": N}],
  \"key_arguments\": [\"argument1\", \"argument2\"],
  \"word_count\": N
}

Focus on: main arguments, key evidence, notable quotes, recurring themes.
Do NOT include meta-commentary about the summarization process.",
  subagent_type="general-purpose",
  run_in_background=true
)
```

Wait for all agents with `TaskOutput(task_id=..., block=true, timeout=180000)`.

If more than 5 chunks, process in batches of 5. Wait for each batch before launching the next. Max 15 agents total.

### Step 3: Merge

```bash
uv run scripts/book.py merge <session_dir>
```

Combines agent summary JSONs into `merged.json` for final synthesis. Deduplicates themes, aggregates quotes and arguments.

### Step 4: Report

Read `merged.json` and `references/report-template.md`. Write the report following the template structure:

1. Fill in metadata from the manifest (title, author, format, words).
2. Write the executive summary by synthesizing all chapter summaries.
3. Write chapter summaries from the merged data.
4. Identify key themes that span multiple chapters.
5. List key arguments with chapter references.
6. Include notable quotes with page numbers.
7. Write critical analysis (strengths, weaknesses, audience).
8. Fill in processing statistics.

Save the report as `{title}_report.md` in the current working directory.

### Step 5: Clean up

Remove the session directory (`/tmp/book_reader_*`) after writing the report.

## Agent JSON Schema

Every agent writes a JSON file with this structure:

```json
{
  "id": 0,
  "label": "Chapter 1: Introduction",
  "summary": "200-500 word summary of this section",
  "key_themes": ["theme1", "theme2"],
  "notable_quotes": [{"text": "exact quote from the text", "page": 42}],
  "key_arguments": ["argument1", "argument2"],
  "word_count": 350
}
```

## Agent Limits

| Limit | Value |
|-------|-------|
| Max concurrent agents | 5 |
| Max total agents per book | 15 |
| Agent timeout | 180 seconds |

## Constraints

**DO:**
- Launch all agents in a single message for true parallelism
- Wait for all agents before running `merge`
- Clean up the session directory after writing the report
- Report progress at each phase (chunk → summarize → merge → report)
- Include page numbers in quotes when available

**DON'T:**
- Launch more than 5 concurrent agents
- Launch more than 15 total agents per book
- Modify chunk files after creation
- Leave session directories in `/tmp` after completion
- Include meta-commentary about the summarization process in the report
