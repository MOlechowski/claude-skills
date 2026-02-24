---
name: doc-daily-digest
description: "Process Obsidian daily notes: classify raw URLs and loose ideas, fetch content (X tweets, GitHub repos, web pages), run deep research on ideas, create structured vault notes, replace raw items with wikilinks. Orchestrates doc-obsidian, res-x, and res-deep skills. Use when: processing daily note links, digesting saved URLs into notes, turning ideas into research, daily note cleanup. Triggers: daily digest, process daily, daily links, triage daily, digest daily note."
---

# Daily Digest

Process an Obsidian daily note by classifying raw items, fetching/researching content, creating structured notes, and replacing raw items with wikilinks.

## Prerequisites

| Skill | Required | Purpose |
|-------|----------|---------|
| doc-obsidian | Yes | Vault CRUD via notesmd-cli + search via qmd |
| res-x | For X/Twitter URLs | Fetch tweet content via xAI |
| res-deep | For loose ideas | Multi-round research |

## Workflow

```
Step 0: Setup → Step 1: Scan & Classify → Step 2: Process → Step 3: Create Notes → Step 4: Update Daily → Step 5: Re-index & Report
```

## Step 0: Setup

Run all three checks:

```bash
# 1. Vault path
VAULT=$(notesmd-cli print-default --path-only)

# 2. Read daily note (today or user-specified date)
DATE=$(date '+%Y-%m-%d')
notesmd-cli print "$DATE"

# 3. xAI key (needed for res-x and res-deep full mode)
security find-generic-password -s "xai-api" -w ~/Library/Keychains/claude-keys.keychain-db 2>/dev/null && echo "XAI_AVAILABLE=true" || echo "XAI_AVAILABLE=false"
```

If user specifies a date, use that instead of today.

## Step 1: Scan & Classify

Parse the daily note and classify every item. Items live in these sections: `## Notes`, `## Log`, `## Links`.

### Classification Rules

| Type | Pattern | Action |
|------|---------|--------|
| **Skip** | `[[wikilink]]` anywhere in line | Already processed — skip |
| **Skip** | Section headers (`##`), frontmatter, empty lines, task checkboxes | Structural — skip |
| **X tweet** | URL matching `https://(x\.com\|twitter\.com)/\w+/status/\d+` | Fetch via res-x |
| **X article** | URL matching `https://(x\.com\|twitter\.com)/i/article/[\w-]+` | Fetch via res-x |
| **GitHub repo** | URL matching `https://github\.com/[\w-]+/[\w-]+` | WebFetch repo page |
| **Web URL** | Any other `https://...` URL | WebFetch page |
| **Loose idea** | Non-empty text that is not a URL, not a wikilink, not structural | Deep research via res-deep |

### Present Classification

Before processing, show the user a classification table:

```
## Daily Digest: {DATE}

| # | Section | Type | Item (truncated) | Action |
|---|---------|------|-------------------|--------|
| 1 | Links | X tweet | https://x.com/user/status/123... | res-x fetch |
| 2 | Notes | Loose idea | Train a model to click on... | res-deep |
| 3 | Links | GitHub | https://github.com/org/repo | WebFetch |
| 4 | Log | Skip | [[already-processed]] — ... | skip |
```

Ask user to confirm or exclude items before proceeding. User may:
- Approve all
- Exclude specific items by number
- Change action for an item (e.g., skip an idea, or upgrade a URL to res-deep)

## Step 2: Process Items

Process approved items. Run independent fetches in parallel where possible.

### X/Twitter URLs

Requires xAI key (XAI_AVAILABLE=true).

```bash
uv run ~/.claude/skills/res-x/scripts/x_fetch.py fetch "URL1" "URL2" "URL3"
```

The script batches 3 URLs per API call. Extract from results:
- Author handle and display name
- Full tweet text
- Engagement metrics (likes, reposts, replies, views)
- Thread context and quoted tweets if present

If XAI_AVAILABLE=false, report that X URLs require xAI key and skip them.

### GitHub URLs

```
WebFetch: https://github.com/{owner}/{repo}
Prompt: "Extract: repo name, description, star count, language, license, last update date, and a 2-3 sentence summary of what this project does based on the README."
```

### Web URLs

```
WebFetch: {URL}
Prompt: "Extract: page title, author if available, publication date if available, and a 3-5 sentence summary of the key content."
```

If WebFetch returns 403 or empty content, note the failure and move on.

### Loose Ideas

Invoke res-deep skill with the idea text as the query. Use `quick` depth (1 round, 10-15 sources) unless user requests deeper research.

For ideas, the res-deep output becomes the note body directly.

## Step 3: Create Notes

For each processed item, create an Obsidian note.

### Note Naming

| Type | Naming Pattern | Example |
|------|---------------|---------|
| X tweet | `{topic}-{descriptor}` from content | `scrapling-undetectable-web-scraping` |
| X article | `{author}-x-article-{date}` | `irabukht-x-article-2026-02-23` |
| GitHub repo | `{repo-name}` | `scrapling` or `huggingface-skills-agent-plugins` |
| Web page | `{topic}-{descriptor}` from title | `kubernetes-practical-learning-path` |
| Loose idea | `{concept}-{descriptor}` | `agent-sort-through-the-slop` |
| Deep research | `{topic}-deep-research` | `scrapling-deep-research` |

All names: kebab-case, lowercase, no special characters.

Check for existing notes with same name before creating. If exists, append `-2` or ask user.

### Note Structure

**For X tweets / web pages / GitHub repos (quick captures):**

```bash
notesmd-cli create "NOTE_NAME" --content "---
tags: [TYPE_TAG]
source: SOURCE_URL
author: AUTHOR
date: DATE
---

# TITLE

## Key Points

- Point 1
- Point 2
- Point 3

## Summary

Brief paragraph summarizing the content.

## Source

- [Original](SOURCE_URL)"
```

Type tags: `tweet` for X, `github` for GitHub, `web` for web pages, `idea` for ideas.

**For deep research (ideas):**

The res-deep skill produces its own structured output. Create the note with that output as body, adding frontmatter:

```bash
notesmd-cli create "NOTE_NAME" --content "---
tags: [idea, research]
date: DATE
---

{res-deep output here}"
```

## Step 4: Update Daily Note

For each processed item, replace the raw text in the daily note with a wikilink.

### Wikilink Format by Section

**## Links section** (URLs from bookmarks/saves):
```
- [[note-name]] — @author: summary with key metrics (stars, likes, etc.)
```

**## Notes section** (ideas and thoughts):
```
- [[note-name]] — Brief: what the idea/research covers
```

**## Log section** (activity entries):
```
- [[note-name]] — Summary of what was captured
```

### Edit Procedure

1. Read the daily note: `notesmd-cli print "$DATE"`
2. Resolve vault path: `VAULT=$(notesmd-cli print-default --path-only)`
3. Use the Edit tool to replace each raw item with its wikilink line
4. Replace one item at a time to avoid Edit conflicts
5. Verify the final note by reading it again

### Rules

- Preserve existing wikilinks — never modify already-processed lines
- Keep section structure intact (## headers, empty lines between items)
- If an item spans multiple lines (e.g., a paragraph idea), replace all lines with one wikilink line
- The wikilink summary should be concise (under 120 chars) but include key metrics when available

## Step 5: Re-index & Report

### Re-index Vault

```bash
qmd update && qmd embed
```

### Summary Report

Present a summary table:

```
## Digest Complete: {DATE}

| # | Type | Note Created | Status |
|---|------|-------------|--------|
| 1 | X tweet | [[note-name]] | Created |
| 2 | Loose idea | [[note-name]] | Created (res-deep quick) |
| 3 | GitHub | [[note-name]] | Created |
| 4 | Web URL | — | Failed (403) |

Notes created: 3
Items skipped: 2 (already processed)
Items failed: 1
Vault re-indexed: Yes
```

## Modes

### Full (default)

Process all unprocessed items in the daily note.

> "Process my daily note" / "Daily digest"

### Selective

Process only specific items or sections.

> "Process only the links in today's daily note"
> "Digest just the X URLs"

### Date Override

Process a specific date's daily note.

> "Process yesterday's daily note"
> "Digest 2026-02-20"

### Dry Run

Classify and show the table (Step 1) without processing.

> "What's unprocessed in my daily note?"
> "Show me what needs digesting"

## Constraints

**DO:**
- Always run Step 0 (vault path + daily note + xAI check) first
- Present classification table and wait for user approval before processing
- Process items in parallel where independent (multiple WebFetch calls, multiple X URLs in one batch)
- Check for existing notes before creating to avoid duplicates
- Read the daily note before editing — never guess content
- Resolve vault path dynamically via `notesmd-cli print-default --path-only`

**DON'T:**
- Process items the user excluded from the classification table
- Modify already-processed wikilink lines
- Hardcode vault paths
- Skip the classification approval step
- Run res-deep at default/deep depth unless user explicitly requests it — use quick for daily digest
- Create notes without frontmatter
