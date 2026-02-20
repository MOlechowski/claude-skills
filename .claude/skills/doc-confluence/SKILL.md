---
name: doc-confluence
description: "Create and update Confluence Data Center pages from Markdown. Use for: (1) creating documentation pages from README or specs, (2) updating existing wiki pages, (3) publishing code docs to Confluence, (4) embedding draw.io diagrams. Triggers: confluence, wiki page, create page, update docs, publish to confluence."
---

# Confluence Writer

Create and update Confluence Data Center pages from Markdown content with draw.io diagram support.

## Quick Start

### Setup Credentials (One-Time)

```bash
# Store Confluence URL and Personal Access Token
uv run ~/.claude/skills/confluence-writer/scripts/setup_credentials.py \
  --url https://confluence.company.com \
  --token YOUR_PERSONAL_ACCESS_TOKEN

# Verify credentials
uv run ~/.claude/skills/confluence-writer/scripts/setup_credentials.py --verify
```

### Create a Page

```bash
# Create new page from Markdown file
uv run ~/.claude/skills/confluence-writer/scripts/write_page.py \
  --space DEV --title "API Documentation" --file README.md

# Create child page under existing page
uv run ~/.claude/skills/confluence-writer/scripts/write_page.py \
  --space DEV --title "Authentication" --parent 12345 --file auth.md
```

### Update a Page

```bash
# Update existing page (auto-increments version)
uv run ~/.claude/skills/confluence-writer/scripts/write_page.py \
  --page-id 67890 --file updated.md
```

### Upload Attachments

```bash
# Upload draw.io diagram
uv run ~/.claude/skills/confluence-writer/scripts/upload_attachment.py \
  --page-id 12345 --file architecture.drawio

# Upload multiple files
uv run ~/.claude/skills/confluence-writer/scripts/upload_attachment.py \
  --page-id 12345 --files diagram.drawio screenshot.png
```

## Markdown Features

The converter supports standard Markdown plus Confluence extensions.

### Standard Markdown

- **Headings**: `# H1` through `###### H6`
- **Formatting**: `**bold**`, `*italic*`, `` `code` ``
- **Lists**: Ordered (`1.`) and unordered (`-`)
- **Links**: `[text](url)`
- **Images**: `![alt](image.png)` (attached images)
- **Tables**: GitHub-flavored Markdown tables
- **Code blocks**: Fenced with language (` ```python `)

### Confluence Extensions

**Panels** via directive blocks:

```markdown
:::info
Important information here
:::

:::warning
Warning message
:::

:::note
Note content
:::

:::tip
Helpful tip
:::
```

**Draw.io diagrams** via image syntax:

```markdown
![Architecture](architecture.drawio)
```

This embeds the diagram macro. Upload the `.drawio` file as attachment first.

## Workflow: Create Documentation Page

1. **Write content** in Markdown
2. **Create page**: `uv run write_page.py --space KEY --title "Title" --file doc.md`
3. **Upload attachments** (if any draw.io diagrams): `uv run upload_attachment.py --page-id ID --file diagram.drawio`
4. **Verify** in Confluence

## Workflow: Update Existing Page

1. **Get page ID** from Confluence URL (`/pages/viewpage.action?pageId=12345`)
2. **Edit Markdown** locally
3. **Update page**: `uv run write_page.py --page-id 12345 --file updated.md`

## Scripts Reference

| Script | Purpose |
|--------|---------|
| `write_page.py` | Create or update pages |
| `upload_attachment.py` | Upload files (draw.io, images) |
| `markdown_to_storage.py` | Convert Markdown to storage format |
| `setup_credentials.py` | Store Confluence credentials |

## Storage Format Reference

For advanced formatting, see [references/storage-format.md](references/storage-format.md) for:
- Code block syntax highlighting options
- Panel macro variants
- Draw.io macro parameters
- Table formatting
