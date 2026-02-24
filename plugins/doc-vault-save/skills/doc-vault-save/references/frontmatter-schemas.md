# Frontmatter Schemas

Loaded on demand (Level 3), when building a note in Step 4.

## Common Fields

All note types share these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | Yes | `research`, `price-comparison`, `decision`, `note` |
| topic | string | Yes | Human-readable topic description |
| date | string | Yes | ISO date (YYYY-MM-DD) |
| status | string | Yes | `complete` or `draft` |
| tags | array | Yes | 2-5 tags, always includes the type tag |

## res-deep Schema

```yaml
---
type: research
topic: {Topic from header}
date: {YYYY-MM-DD}
sources: {integer}
framework: {comparison|landscape|deep-dive|decision}
depth: {quick|default|deep}
status: complete
tags: [{domain-tags}, research]
---
```

### Field Extraction

The res-deep output starts with a YAML-like header block (NOT actual frontmatter):

```
---
Framework: DECISION
Topic: Agent Swarms Hardware
Depth: deep
Sources: 43 across 5 platforms
Date: 2026-02-23
---
```

Mapping:
- `Framework: DECISION` → `framework: decision` (lowercase)
- `Topic: Agent Swarms Hardware` → `topic: Agent Swarms Hardware`
- `Depth: deep` → `depth: deep`
- `Sources: 43 across 5 platforms` → `sources: 43` (extract integer)
- `Date: 2026-02-23` → `date: 2026-02-23`

### Framework → Type Override

| Framework | type field |
|-----------|-----------|
| COMPARISON | `research` |
| LANDSCAPE | `research` |
| DEEP_DIVE | `research` |
| DECISION | `decision` |

### Tag Generation

1. Always: `research` (or `decision` for DECISION framework)
2. Extract 2-4 domain keywords from Topic:
   - Technology: `ai`, `agents`, `kubernetes`, `terraform`
   - Products: `mac-studio`, `yealink`
   - Domains: `hardware`, `networking`, `security`
3. Search existing vault notes on similar topics via `qmd search` and reuse matching tags for consistency

## res-price-compare Schema

```yaml
---
type: price-comparison
product: {Full product name with model/variant}
date: {YYYY-MM-DD}
buyer_type: {B2B|B2C}
market: pl
status: complete
tags: [{product-category}, price-comparison]
---
```

### Field Extraction

No structured header in res-price-compare output. Extract from content:

- `product`: Product name from first heading or table header (e.g., "Apple Mac Studio M4 Max 128GB")
- `buyer_type`: Detect from warranty/B2B sections. Default: `B2B`
- `market`: Default `pl`. If EU cross-border section present, use `pl` (primary market)

### Category Detection

Use res-price-compare's category patterns:

| Category | Tag | Detection |
|----------|-----|-----------|
| VoIP/Telephony | `voip` | Yealink, Grandstream, Fanvil, SIP, DECT |
| IT/Networking | `networking` | MikroTik, Ubiquiti, switch, router, AP |
| Electronics | `electronics` | monitor, laptop, computer, printer |
| Office | `office` | chair, desk, shredder, projector |
| Apple | `apple` | Mac, MacBook, iPad, iPhone |
| General | `general` | (no match) |

### Tag Generation

1. Always: `price-comparison`
2. Product category tag from table above
3. Brand tag: `apple`, `yealink`, `mikrotik`, etc.

## Generic Note Schema

```yaml
---
type: note
topic: {From heading, user instruction, or summary}
date: {YYYY-MM-DD}
status: draft
tags: [{user-specified or auto-derived}]
---
```

### Field Derivation

- `topic`: First `# heading` in content, OR user's description ("save this as X"), OR auto-summarize first paragraph
- `tags`: User-specified if provided. Otherwise derive 2-3 from content keywords
- `status`: Default `draft`. User can override to `complete`

## Setting Frontmatter

### At Creation (in --content)

```bash
notesmd-cli create "research/topic-name" --content "---
type: research
topic: Topic Name
date: 2026-02-24
sources: 43
framework: decision
depth: deep
status: complete
tags: [ai, agents, hardware, decision]
---

Related: [[note-a]] | [[note-b]]

# Content starts here..."
```

### Updating Individual Fields

```bash
notesmd-cli fm "research/topic-name" --edit --key "status" --value "complete"
notesmd-cli fm "research/topic-name" --edit --key "date" --value "2026-02-24"
notesmd-cli fm "research/topic-name" --edit --key "tags" --value "[ai, agents, hardware]"
```

## Validation Checklist

Before saving, verify:
- All required fields present (type, topic/product, date, status, tags)
- `type` is one of: `research`, `price-comparison`, `decision`, `note`
- `date` is valid ISO format (YYYY-MM-DD)
- `tags` is a non-empty array
- `status` is `complete` or `draft`
- No duplicate keys
