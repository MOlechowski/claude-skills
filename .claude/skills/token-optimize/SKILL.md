---
name: token-optimize
description: "Rewrite markdown for conciseness. Use when: optimizing markdown for LLM context, making documentation more concise, reducing token count in files. Triggers: optimize this file, make this more concise, reduce tokens, token optimize."
---

# Token Optimize

Rewrite markdown files to be more concise while preserving meaning.

## Workflow

1. Read the target markdown file
2. Identify code blocks (preserve exactly)
3. Rewrite all prose for conciseness
4. Preserve structure (headings, lists, links)
5. Edit file in-place

## Preserve Exactly

Do not modify:
- Fenced code blocks (```...```)
- Inline code (`...`)
- URLs and paths
- Technical identifiers

## Rewrite Rules

Apply these to all prose:

**Remove filler words:**
- just, very, really, basically, actually, simply
- in order to → to
- due to the fact that → because
- at this point in time → now

**Shorten phrases:**
- is able to → can
- in the event that → if
- for the purpose of → for
- with regard to → about
- a large number of → many

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
- Long paragraphs → shorter ones
- Nested lists → flatter when possible
- Verbose headings → concise ones

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
- List major changes made

See `quick-reference.md` for optimization checklist.
