---
name: doc-vault-save
description: "Save structured content to Obsidian vault with standardized frontmatter, folder routing, deduplication, and wikilink generation. Persists res-deep research, res-price-compare reports, and generic content. Use when: saving to vault, persisting results, store in obsidian. Triggers: save to vault, vault save, persist this, save research, store in vault, update vault note."
---

# Vault Save

Persist structured content from conversation to an Obsidian vault. Handles content detection, frontmatter generation, folder routing, deduplication, wikilink injection, and re-indexing.

**This skill does NOT do research.** It only persists content already in the conversation.

## Prerequisites

| Skill | Required | Purpose |
|-------|----------|---------|
| doc-obsidian | Yes | Vault CRUD via notesmd-cli + search via qmd |

## Workflow

```
Step 0: Setup → Step 1: Detect Content → Step 2: Name & Route → Step 3: Dedup Check → Step 4: Build Note → Step 5: Save → Step 6: Wikilinks → Step 7: Re-index & Confirm
```

## Step 0: Setup

Run before every save:

```bash
# 1. Vault path (MANDATORY)
VAULT=$(notesmd-cli print-default --path-only)

# 2. Verify qmd available
qmd status
```

If either fails, stop and tell the user to set up doc-obsidian first.

## Step 1: Detect Content Type

Examine conversation context. Use the FIRST matching rule:

| Type | Detection | Signals |
|------|-----------|---------|
| **res-deep** | Has header with `Framework:` field, has `Research Statistics` footer | COMPARISON / LANDSCAPE / DEEP_DIVE / DECISION |
| **res-price-compare** | Has price tables with PLN/EUR, has `TOP 3` or `PURCHASE RECOMMENDATION` | Shop comparison tables, warranty analysis |
| **generic** | Everything else | User-provided text, pasted content, dictated notes |

**Explicit override:** User can force type with "save as research", "save as price comparison", "save as note".

## Step 2: Name & Route

### Note Naming

| Type | Pattern | Example |
|------|---------|---------|
| res-deep | `{topic-slug}` from Topic field | `agent-swarms-hardware-decision` |
| res-price-compare | `{product-slug}-pricing` | `mac-studio-m4-max-128gb-pricing` |
| generic | `{topic-slug}` from first heading or user instruction | `kubernetes-setup-notes` |

Rules: kebab-case, lowercase, no special characters, max 60 chars. If user specifies a name, use it.

### Folder Routing

| Type | Default Folder | Override |
|------|---------------|---------|
| res-deep | `research/` | "save to {folder}" |
| res-price-compare | `research/` | "save to {folder}" |
| generic | vault root | "save to {folder}" |

Load `references/folder-routing.md` for customization and sub-routing rules.

### Confirm Before Saving

```
Save: research/agent-swarms-hardware-decision
Type: res-deep (DECISION framework)
Proceed? [Y / change name / change folder]
```

Skip confirmation if user already specified name and location.

## Step 3: Dedup Check

```bash
# Keyword search on the topic
qmd search "{topic}" --json -n 5

# Check exact name match
notesmd-cli print "{folder}/{note-name}" 2>/dev/null
```

### Decision Matrix

| Existing Note | Action |
|--------------|--------|
| No match | Create new → Step 4 |
| Exact name match | Ask: **overwrite** / **append** / **create with suffix** (-2, -3) |
| Similar topic, different name | Show matches, ask: **create alongside** / **overwrite existing** / **append to existing** |

Show found notes with dates so user can judge recency:

```
Found existing notes on this topic:
1. research/agent-swarms-analysis (2026-02-20, 43 sources)
2. research/ai-agents-hardware (2026-02-15, 28 sources)
Action: [create new / overwrite #1 / append to #1 / cancel]
```

## Step 4: Build Note

### Frontmatter

Load `references/frontmatter-schemas.md` for full schemas. Summary:

**res-deep:**
```yaml
---
type: research
topic: {Topic from header}
date: {YYYY-MM-DD}
sources: {N}
framework: {comparison|landscape|deep-dive|decision}
depth: {quick|default|deep}
status: complete
tags: [{domain-tags}, research]
---
```

Use `type: decision` when framework is DECISION.

**res-price-compare:**
```yaml
---
type: price-comparison
product: {Full product name}
date: {YYYY-MM-DD}
market: pl
status: complete
tags: [{product-category}, price-comparison]
---
```

**generic:**
```yaml
---
type: note
topic: {From heading or user input}
date: {YYYY-MM-DD}
status: draft
tags: [{auto-derived}]
---
```

### Tag Generation

Auto-derive 2-5 tags:
1. Content type tag: `research`, `price-comparison`, or `note`
2. Domain tags: key nouns from topic (e.g., `ai`, `agents`, `hardware`)
3. User-specified tags if provided

### Body Construction

**res-deep:** Strip the YAML-like header block (`Framework:`/`Topic:`/`Depth:`/`Sources:`/`Date:` lines) — that data moves to proper frontmatter. Keep everything else.

**res-price-compare:** Keep full report body. Strip any file-export artifacts.

**generic:** Use content as-is. Add `# {Topic}` if no heading exists.

## Step 5: Save

### Create Mode (default)

```bash
notesmd-cli create "{folder}/{note-name}" --content "{frontmatter + body}" --overwrite
```

Use `--overwrite` only after Step 3 confirmed no conflict or user approved.

### Append Mode

```bash
notesmd-cli create "{folder}/{note-name}" --content "\n\n---\n\n## Update: {YYYY-MM-DD}\n\n{new content}" --append
```

### Update Mode (surgical edit)

For updating a specific section of an existing note:

```bash
# 1. Read current note
notesmd-cli print "{folder}/{note-name}"

# 2. Edit via vault path
VAULT=$(notesmd-cli print-default --path-only)
# Use Edit tool on "$VAULT/{folder}/{note-name}.md"
```

### Large Content Fallback

If content exceeds ~100KB, `notesmd-cli create --content` may hit shell argument limits. Use the Write tool directly:

```bash
VAULT=$(notesmd-cli print-default --path-only)
# Write tool → "$VAULT/{folder}/{note-name}.md"
```

### Update Date After Save

```bash
notesmd-cli fm "{folder}/{note-name}" --edit --key "date" --value "{YYYY-MM-DD}"
```

## Step 6: Wikilinks

Find related notes and add a `Related:` block after frontmatter.

### Find Related

```bash
qmd vsearch "{topic}" --json -n 10
```

Filter: exclude the note just saved, exclude score < 0.3, keep top 3-5.

### Insert Related Line

After frontmatter closing `---`, before first `#` heading:

```markdown
Related: [[note-a]] | [[note-b]] | [[note-c]]
```

If the note already has a `Related:` line, replace it (don't duplicate).

### Implementation

```bash
notesmd-cli print "{folder}/{note-name}"
VAULT=$(notesmd-cli print-default --path-only)
# Use Edit tool to insert/replace Related line
```

## Step 7: Re-index & Confirm

```bash
qmd update && qmd embed
```

### Confirmation Output

```
Saved: [[{note-name}]]
Path: {folder}/{note-name}
Type: {type}
Tags: {tags}
Related: [[note-a]], [[note-b]], [[note-c]]
Vault re-indexed: Yes
```

## Modes

| Mode | Trigger | Behavior |
|------|---------|----------|
| **save** (default) | "save to vault", "vault save" | Full workflow: Steps 0-7 |
| **quick** | "quick save", "save, no dedup" | Skip Steps 3 + 6 (no dedup, no wikilinks) |
| **update** | "update vault note", "add to existing" | Surgical edit of existing note (Step 5 update mode) |
| **dry-run** | "where would this go?", "preview save" | Show name, folder, frontmatter, related notes — no save |

## Constraints

**DO:**
- Always run Step 0 first
- Always detect content type before building frontmatter
- Always check for duplicates before creating (unless quick mode)
- Always re-index after saving
- Resolve vault path dynamically via `notesmd-cli print-default --path-only`
- Present name + folder for user approval before saving
- Read notes before editing — never guess content

**DON'T:**
- Do research — this skill only persists content
- Hardcode vault paths
- Create notes without frontmatter
- Skip dedup check (unless quick mode)
- Duplicate what doc-daily-digest does
- Modify notes from other skills without user approval
- Save empty or stub notes

## References

- `references/frontmatter-schemas.md` — Full schemas per content type, field extraction rules, tag generation, validation
- `references/folder-routing.md` — Routing rules, user overrides, sub-routing, conflict resolution
