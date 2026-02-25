# _index.md Template

Use this template when scaffolding a new project. Replace `{placeholders}` with actual values.

```markdown
---
type: project
topic: "{Project Name}"
status: researching
components: 0
date: "{YYYY-MM-DD}"
updated: "{YYYY-MM-DD}"
tags:
    - project
    - {tag-1}
    - {tag-2}
---

# {Project Name}

{One-paragraph project description: what we're building and why.}

## Status

| Phase | Components | Complete |
|-------|-----------|----------|
| Concept | 0 | 0 |
| Research | 0 | 0 |
| Design | 0 | 0 |
| Implementation | 0 | 0 |

## Concept

{No components yet.}

## Research

### Project Research

{No components yet.}

### Linked Research

{Existing vault research notes relevant to this project.}

## Design

{No components yet.}

## Implementation

{No components yet.}
```

## Status Table Update Rules

After adding or completing a component, update the status table in `_index.md`:

1. Count notes per phase directory
2. Count notes with `status: complete` per phase
3. Update totals
4. Update `components:` in frontmatter to total count
5. Update `updated:` to today's date

## Linked Research Section

When linking existing `research/` notes (via `link` command), add them under `### Linked Research`:

```markdown
### Linked Research

- [[existing-research-note]] — brief relevance description
- [[another-research-note]] — brief relevance description
```

These are wikilinks to notes that stay in `research/`. They are not moved into the project.
