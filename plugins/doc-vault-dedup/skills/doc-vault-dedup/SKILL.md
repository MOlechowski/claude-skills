---
name: doc-vault-dedup
description: "Detect and consolidate overlapping research notes in Obsidian vault. Semantic similarity scanning, section-level overlap mapping, merge planning, and execution with wikilink redirect. Use when: notes overlap, research is scattered, vault has duplicates, consolidating notes, dedup vault, merge research. Triggers: dedup, deduplicate, consolidate notes, merge notes, find duplicates, overlap analysis, vault cleanup."
---

# Vault Dedup

Detect and consolidate overlapping research notes in an Obsidian vault.

## Prerequisites

| Skill | Required | Purpose |
|-------|----------|---------|
| doc-obsidian | Yes | Vault CRUD via notesmd-cli + search via qmd |

## Step 0: Setup

Run before every operation:

```bash
VAULT=$(notesmd-cli print-default --path-only)
qmd status
```

If either fails, stop and tell the user to set up doc-obsidian first.

## Commands

### scan — Detect Overlapping Notes

**Trigger:** "find duplicates", "scan for overlaps", "dedup scan", "which notes overlap"

#### Workflow

1. Determine scope:
   - Specific notes: user provides list of notes to compare
   - Topic-based: user provides topic, search via `qmd vsearch "{topic}" --json -n 20`
   - Folder-based: user provides folder, list all notes in it
   - Full vault: scan all research notes (use `qmd search "type: research" --json`)

2. For each note in scope, extract:
   - Frontmatter (`type`, `topic`, `tags`)
   - Section headings (`## ` lines)
   - Line count

3. Build similarity matrix — for each pair of notes:

```bash
# Semantic similarity via qmd
qmd vsearch "{note-A topic}" --json -n 20
# Check if note-B appears in results and at what score
```

4. Classify overlap for pairs with score > 0.5:

| Score | Overlap | Action |
|-------|---------|--------|
| > 0.8 | Near-duplicate | Strong merge candidate |
| 0.6–0.8 | Significant overlap | Section-level analysis needed |
| 0.5–0.6 | Related | Link, don't merge |
| < 0.5 | Distinct | No action |

5. For pairs with significant overlap, compare section headings to identify which sections duplicate.

6. Output overlap report:

```
## Overlap Report

### Near-Duplicates (merge recommended)
- [[note-a]] ↔ [[note-b]] (score: 0.85)
  Overlapping sections: "How It Works", "Sources"

### Significant Overlap (review needed)
- [[note-c]] ↔ [[note-d]] (score: 0.67)
  Overlapping sections: "Threat Model"

### Related (link only)
- [[note-e]] ↔ [[note-f]] (score: 0.52)

### Distinct (no action)
{remaining pairs}

Notes scanned: {N}
Pairs compared: {N}
Merge candidates: {N}
```

### plan — Propose Consolidation

**Trigger:** "plan merge", "how to consolidate", "dedup plan"

#### Workflow

1. Run `scan` if no recent scan results
2. For each merge candidate pair/group, determine merge strategy:

| Pattern | Strategy | Example |
|---------|----------|---------|
| A is superset of B | **Absorb** B into A | Deep dive absorbs related overview |
| A and B have distinct sections with some overlap | **Merge** into new note | Two complementary research notes |
| A has section that duplicates B's section | **Extract** shared section | Same "Threat Model" in two notes |
| A is outdated version of B | **Archive** A, keep B | Old draft superseded by complete research |

3. For each proposed action, show:

```
### Proposed Action 1: Absorb

Target: [[obsidian-vault-hardening]] (keep, 288 lines)
Source: [[obsidian-vault-encryption-cc-bypass]] (absorb, 159 lines)

Sections to absorb:
- "Obsidian Encryption Plugins" → into "How It Works" section
- "Encrypted Sparsebundle" → into "Hardening Checklist"

Sections already covered (skip):
- "Threat Model" — covered in target's "Attack Surface"

After merge:
- Target gains: 2 sections (~80 lines of unique content)
- Source: archived with redirect to target
- Wikilinks updated: [[obsidian-vault-encryption-cc-bypass]] → [[obsidian-vault-hardening]]
```

4. Present full plan, ask user to approve/modify before execution.

### merge — Execute Consolidation

**Trigger:** "merge notes", "execute dedup", "consolidate now"

#### Workflow

Requires an approved plan from `plan` step. For each action in the plan:

**Absorb:**
1. Read both notes fully
2. Identify unique sections from source not in target
3. Read target note, find insertion point
4. Insert unique sections at appropriate location
5. Update target frontmatter:
   - Merge tags (deduplicate)
   - Update `sources:` count (sum unique sources)
   - Update `date:` to today
6. Archive source (see Archive step below)
7. Update wikilinks (see Redirect step below)

**Merge into new:**
1. Read all source notes
2. Build merged note:
   - Frontmatter: combine metadata, sum sources
   - Body: interleave sections by topic, deduplicate
   - Sources: merge and deduplicate
3. Write new note
4. Archive all source notes
5. Update wikilinks

**Extract shared section:**
1. Read both notes
2. Create new note with shared content
3. Replace shared sections in both originals with wikilink reference
4. Update originals' frontmatter

**Archive (superseded):**
1. Keep source note, mark as archived

After all actions:
```bash
qmd update && qmd embed
```

#### Archive Step

For each absorbed/superseded note:

1. Add redirect notice at top of note (after frontmatter):

```markdown
> [!info] Consolidated
> This note was merged into [[target-note]] on {YYYY-MM-DD}.
> Unique content preserved in target. This note kept for backlink compatibility.
```

2. Update frontmatter:
   - Set `status: archived`
   - Add `merged-into: "{target-note-slug}"`
   - Add `archived: "{YYYY-MM-DD}"`

3. Do NOT delete the note — keeps backlinks working from external references.

#### Redirect Step

Find all notes that wikilink to archived source:

```bash
VAULT=$(notesmd-cli print-default --path-only)
# Search for wikilinks to source note
qmd search "[[{source-slug}]]" --json
```

For each note containing a wikilink to the source:
1. Read the note
2. Replace `[[source-slug]]` with `[[target-slug]]`
3. If in a `Related:` line, deduplicate (don't link target twice)
4. Save

### status — Show Dedup History

**Trigger:** "dedup status", "what was merged"

#### Workflow

Find all archived/merged notes:

```bash
VAULT=$(notesmd-cli print-default --path-only)
# Search for notes with merged-into frontmatter
qmd search "merged-into" --json
```

Display:

```
## Dedup History

| Archived Note | Merged Into | Date |
|---------------|-------------|------|
| [[source-a]] | [[target-a]] | 2026-02-25 |
| [[source-b]] | [[target-b]] | 2026-02-25 |

Total: {N} notes consolidated
```

## Constraints

**DO:**
- Always run Step 0 first
- Always present the plan and get user approval before merging
- Always read notes fully before editing
- Always preserve unique content — never lose information
- Always archive (don't delete) source notes
- Always update wikilinks after merging
- Always re-index after changes
- Resolve vault path dynamically via `notesmd-cli print-default --path-only`

**DON'T:**
- Delete notes — archive with redirect notice instead
- Merge without user approval
- Lose unique content from source notes
- Skip wikilink updates
- Hardcode vault paths
- Auto-trigger — only respond to explicit dedup commands
- Merge notes of different types (e.g., don't merge a `project` note into a `research` note)
