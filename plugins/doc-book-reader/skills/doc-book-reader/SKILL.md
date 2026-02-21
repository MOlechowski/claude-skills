---
name: doc-book-reader
description: "Read entire books (PDF, EPUB, DOCX, TXT) and produce structured synthesis reports or convert to markdown. Orchestrates doc-extract and doc-pandoc with parallel agent coordination for chapter-aware processing. Use for: (1) reading and summarizing entire books, (2) extracting key themes and arguments from long documents, (3) producing book reports with chapter summaries, (4) processing large PDFs with parallel agents, (5) converting books to markdown files. Triggers: read book, book report, summarize book, read entire pdf, book synthesis, book analysis, convert book to markdown, book to md, doc-book-reader."
---

# doc-book-reader

Read an entire book and produce a structured synthesis report.

## Architecture

Orchestrates two helper skills with parallel agent coordination:

| Component | Role |
|-----------|------|
| `book.py` (bundled script) | Format detection, metadata extraction, text extraction, book-to-markdown conversion, chapter-aware chunking, manifest generation, JSON merging |
| doc-extract (sibling plugin) | PDF/image text extraction with tiered OCR engines |
| doc-pandoc (sibling plugin) | EPUB/DOCX/HTML → Markdown via pandoc CLI |
| Claude agents (Task tool) | Parallel chunk summarization |

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| uv | Python package manager (runs the script) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| pandoc | EPUB/DOCX/HTML conversion (optional for PDF-only) | `brew install pandoc` |

doc-extract is optional — book.py falls back to bundled pypdf for digital PDFs.

## Quick Convert: Book to Markdown

For converting a book to markdown without synthesis, use the `extract` command directly:

```bash
# Single markdown file
uv run scripts/book.py extract book.pdf --output book.md

# One file per chapter
uv run scripts/book.py extract book.pdf --split-chapters --output-dir ./chapters/

# EPUB to markdown
uv run scripts/book.py extract book.epub --output book.md

# To stdout (pipe-friendly)
uv run scripts/book.py extract book.pdf | head -100
```

| Flag | Purpose | Default |
|------|---------|---------|
| `--output`, `-o` | Output file path | stdout |
| `--split-chapters` | Write one `.md` file per detected chapter | off |
| `--output-dir` | Directory for `--split-chapters` output | current directory |

When using `--split-chapters`, files are named `01-chapter-title.md`, `02-chapter-title.md`, etc.

## Synthesis Workflow

For full book analysis with agent-powered summarization:

```
1. Detect  →  2. Chunk  →  3. Summarize (agents)  →  4. Merge  →  5. Synthesize  →  6. Report
```

### Step 1: Detect

```bash
uv run scripts/book.py detect <file>
```

Returns JSON with format, pages, words, chapters, and recommended strategy.

### Step 2: Chunk

```bash
uv run scripts/book.py chunk <file> [--strategy S] [--max-words 15000] [--max-pages 30]
```

Extracts text into `chunk_N.md` files in a session directory. Returns manifest JSON with chunk metadata and paths.

### Step 3: Summarize (strategy-dependent — see below)

### Step 4: Merge

```bash
uv run scripts/book.py merge <session_dir>
```

Combines agent summary JSONs into `merged.json` for final synthesis.

### Step 5: Synthesize

Read `merged.json` and produce the final report using the template in `references/report-template.md`.

### Step 6: Clean up

Remove the session directory after writing the report.

## Strategy Selection

Select strategy based on `detect` output:

| Condition | Strategy | Agents |
|-----------|----------|--------|
| ≤10 pages OR ≤5k words | `direct` | 0 |
| 11–50 pages OR 5k–25k words | `sequential` | 0 |
| 51–450 pages OR 25k–225k words | `map-reduce` | up to 5 |
| 450+ pages OR 225k+ words | `two-tier` | up to 5 |

Always use the strategy from `detect` output unless the user explicitly overrides.

## Strategy: direct

For short documents that fit in context.

1. Run `chunk` — produces a single chunk.
2. Read the chunk file directly.
3. Summarize and write the report. No agents needed.

## Strategy: sequential

For medium documents processed one chunk at a time.

1. Run `chunk` — produces multiple chunks.
2. Process chunks one-by-one in order:
   - Read `chunk_0.md`, summarize it (200–500 words).
   - Read `chunk_1.md`, summarize it while carrying forward a running summary (max 500 words) from previous chunks.
   - Continue until all chunks processed.
3. Write each `summary_N.json` to the session directory.
4. Run `merge` and write the final report.

Running summary format — carry this between chunks:
```
So far: [running summary of key points, themes, arguments from all previous chunks, max 500 words]
```

## Strategy: map-reduce

For large documents processed in parallel.

1. Run `chunk` — produces multiple chunks.
2. Launch up to 5 background agents in a **single message** using the Task tool:

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

3. Wait for all agents with `TaskOutput(task_id=..., block=true, timeout=180000)`.
4. If more than 5 chunks, launch next batch after first batch completes. Max 15 agents total.
5. Run `merge` and write the final report.

## Strategy: two-tier

For very large documents. Two levels of summarization.

1. Run `chunk` — produces chunks and `tier2_groups` in the manifest.
2. Launch up to 5 tier-1 agents. Each processes a **group** of chunks sequentially:

```
Task(
  description="Summarize group G",
  prompt="Process these chunks sequentially and write a group synthesis to <session_dir>/group_G.json.

Chunks to read in order:
- <chunk_path_1>
- <chunk_path_2>
- ...

For each chunk, build a running summary. After processing all chunks in this group,
write the final group synthesis JSON:
{
  \"id\": G,
  \"label\": \"Group G: <first chunk label> – <last chunk label>\",
  \"summary\": \"500-800 word synthesis of this group\",
  \"key_themes\": [\"theme1\", \"theme2\"],
  \"notable_quotes\": [{\"text\": \"exact quote\", \"page\": N}],
  \"key_arguments\": [\"argument1\", \"argument2\"],
  \"word_count\": N
}

Focus on: main arguments, key evidence, notable quotes, recurring themes.
Show how ideas develop across chapters in this group.",
  subagent_type="general-purpose",
  run_in_background=true
)
```

3. Wait for all agents.
4. Run `merge` and write the final report.

## Agent JSON Schema

Every agent writes a JSON file with this structure:

```json
{
  "id": 0,
  "label": "Chapter 1: Introduction",
  "summary": "200-500 words (map-reduce) or 500-800 words (two-tier group)",
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

If a batch has more than 5 chunks, process in batches of 5. Wait for each batch to complete before launching the next.

## Report Writing

After merge, read `merged.json` and `references/report-template.md`. Write the report following the template structure:

1. Fill in metadata from the manifest (title, author, format, pages, words, strategy).
2. Write the executive summary by synthesizing all chapter summaries.
3. Write chapter summaries from the merged data.
4. Identify key themes that span multiple chapters.
5. List key arguments with chapter references.
6. Include notable quotes with page numbers.
7. Write critical analysis (strengths, weaknesses, audience).
8. Fill in processing statistics.

Save the report as `{title}_report.md` in the current working directory.

## Constraints

**DO:**
- Always run `detect` first to understand the document
- Use the recommended strategy unless the user overrides
- Launch all agents in a single message for true parallelism
- Wait for all agents before running `merge`
- Clean up the session directory (`/tmp/book_reader_*`) after writing the report
- Report progress at each phase (detect → chunk → summarize → merge → report)
- Include page numbers in quotes when available

**DON'T:**
- Launch more than 5 concurrent agents
- Launch more than 15 total agents per book
- Skip the detect step
- Modify chunk files after creation
- Leave session directories in `/tmp` after completion
- Use direct strategy for documents over 50 pages
- Include meta-commentary about the summarization process in the report
