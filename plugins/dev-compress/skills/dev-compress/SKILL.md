---
name: dev-compress
description: "Rewrite markdown for conciseness. Use when: optimizing markdown for LLM context, making documentation more concise, reducing token count in files. Triggers: optimize this file, make this more concise, reduce tokens, token optimize."
---

# Token Optimize

Rewrite markdown files for conciseness while preserving meaning.

## Workflow

1. Read the target file
2. Identify code blocks (preserve exactly)
3. Rewrite prose for conciseness
4. Preserve structure (headings, lists, links)
5. Edit file in-place

## Preserve Exactly

- YAML frontmatter (---...---)
- Fenced code blocks (```...```)
- Inline code (`...`)
- URLs and paths
- Technical identifiers

## Rewrite Rules

**Remove filler words:**
- just, very, really, basically, actually, simply
- in order to -> to
- due to the fact that -> because
- at this point in time -> now

**Shorten phrases:**
- is able to -> can
- in the event that -> if
- for the purpose of -> for
- with regard to -> about
- a large number of -> many

**Active voice:**
- Bad: "The file is read by the system"
- Good: "The system reads the file"

**Combine sentences:**
- Bad: "This is a tool. It helps optimize files."
- Good: "This tool optimizes files."

**Remove redundancy:**
- Bad: "completely finished"
- Good: "finished"

**Cut hedging:**
- Bad: "This might possibly help"
- Good: "This helps"

## Structure Rules

Keep:
- Heading hierarchy
- List semantics
- Table structure
- Link references

Simplify:
- Long paragraphs -> shorter
- Nested lists -> flatter when possible
- Verbose headings -> concise

## Structural Optimization

**Key info placement:**
- Critical info at start and end (avoid "lost in the middle")
- Lead sections with the most important point
- End with actionable takeaways

**Heading compression:**
- "Installation and Setup Instructions" -> "Setup"
- "How to Configure the System" -> "Configuration"

**Table vs prose:**
- Convert verbose lists to tables when comparing items
- Tables are 20-30% more compact than equivalent prose

## Semantic Compression

**Deduplication:**
- Remove concepts repeated across sections
- Consolidate overlapping explanations

**Reference consolidation:**
- "See X" instead of restating
- Link to single source of truth

**Abbreviation introduction:**
- Define once: "Large Language Model (LLM)"
- Use short form after: "The LLM processes..."

## Format Efficiency

**Format selection:**
- YAML over JSON (15-20% fewer tokens)
- Bullets over prose paragraphs
- Tables over verbose comparisons

**Code comments:**
- Minimal; code should self-document
- Only explain "why", not "what"

## Document Structure

**Progressive disclosure:**
- Core info in main file
- Details in references/ subdirectory
- Summary at top, details below

**Semantic sections:**
- Split by topic, not arbitrary length
- Each section independently useful
- Enable selective loading for RAG

## Process

1. Read the file completely
2. Parse sections (identify code blocks)
3. For each prose section:
   - Apply rewrite rules
   - Keep meaning intact
   - Reduce word count
4. Reassemble document
5. Write back to original file

## Output

- Edit file in-place
- Report before/after line count
- List major changes

For aggregation, output JSON:
```json
{"file": "path.md", "before": 100, "after": 85}
```

## Batch Processing

For multiple files:

1. **Discover**: `glob .claude/skills/**/*.md`
2. **Partition**: Group ~10 files per agent
3. **Parallelize**: Use `/parallel-flow` with git-worktree for isolation
4. **Aggregate**: Collect JSON results, merge branches

For 10+ files, use cli-parallel agents with disjoint file sets to avoid conflicts.

See `references/quick-reference.md` for optimization checklist.
