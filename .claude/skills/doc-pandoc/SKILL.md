---
name: doc-pandoc
description: "Universal document conversion with pandoc. Use for: (1) converting between formats (Markdown, HTML, DOCX, EPUB, LaTeX, RST, JATS, ODT, RTF, etc.), (2) batch converting multiple files, (3) generating standalone HTML with embedded CSS, (4) extracting text/markdown from DOCX/ODT/EPUB, (5) format-aware transformations with metadata, templates, and Lua filters. Triggers: pandoc, convert document, markdown to docx, docx to markdown, convert to html, convert to epub, document format."
---

# doc-pandoc

Universal document converter. 51 input formats, 75 output formats.

## Command Structure

```bash
pandoc [OPTIONS] INPUT -o OUTPUT
pandoc [OPTIONS] INPUT -t FORMAT     # stdout
pandoc INPUT -f FORMAT -t FORMAT     # explicit formats
```

Pandoc infers formats from file extensions. Use `-f` / `-t` to override.

## Common Conversions

### Markdown to DOCX

```bash
# Basic
pandoc input.md -o output.docx

# With metadata
pandoc input.md --metadata title="My Document" -o output.docx

# With custom reference style
pandoc input.md --reference-doc=template.docx -o output.docx
```

### Markdown to HTML

```bash
# Fragment (body only)
pandoc input.md -o output.html

# Standalone page with embedded styles
pandoc input.md -s -o output.html

# With custom CSS
pandoc input.md -s --css=style.css -o output.html

# Self-contained (images base64-encoded, CSS inlined)
pandoc input.md -s --embed-resources --standalone -o output.html
```

### Markdown to PDF

Requires a PDF engine. Check availability and install one:

| Engine | Install (macOS) | Flag |
|--------|----------------|------|
| `tectonic` | `brew install tectonic` | `--pdf-engine=tectonic` |
| `xelatex` | `brew install --cask mactex` | `--pdf-engine=xelatex` |
| `typst` | `brew install typst` | `--pdf-engine=typst -t typst` |
| `weasyprint` | `pip install weasyprint` | `--pdf-engine=weasyprint -t html` |

```bash
# Via LaTeX (best typography)
pandoc input.md -o output.pdf --pdf-engine=tectonic

# Via HTML (CSS-based styling)
pandoc input.md -o output.pdf --pdf-engine=weasyprint -t html

# Via Typst (modern alternative)
pandoc input.md -o output.pdf -t typst --pdf-engine=typst
```

### Markdown to EPUB

```bash
# Basic
pandoc input.md -o output.epub

# With cover image and metadata
pandoc input.md -o output.epub \
  --metadata title="Book Title" \
  --metadata author="Author Name" \
  --epub-cover-image=cover.jpg

# Multi-file book
pandoc ch1.md ch2.md ch3.md -o book.epub --toc
```

### DOCX to Markdown

```bash
# Basic extraction
pandoc input.docx -o output.md

# Extract and save media files
pandoc input.docx -o output.md --extract-media=./media

# With ATX-style headers
pandoc input.docx -o output.md --atx-headers --wrap=none
```

### HTML to Markdown

```bash
pandoc input.html -o output.md
pandoc input.html -t gfm -o output.md   # GitHub-flavored Markdown
```

### LaTeX to DOCX

```bash
pandoc input.tex -o output.docx
```

### RST to Markdown

```bash
pandoc input.rst -t gfm -o output.md
```

## Key Options

### Output Control

```
-s, --standalone         Full document (not fragment)
-o FILE                  Output file (infers format from extension)
-t FORMAT                Output format explicitly
-f FORMAT                Input format explicitly
--wrap=none              No line wrapping (useful for Markdown output)
--columns=N              Line wrap width (default 72)
```

### Metadata

```bash
# Via command line
pandoc input.md --metadata title="Title" --metadata date="2025-01-01" -o out.docx

# Via YAML file
pandoc input.md --metadata-file=meta.yaml -o out.docx
```

YAML frontmatter in Markdown is read automatically:

```yaml
---
title: My Document
author: Jane Doe
date: 2025-01-01
lang: en
---
```

### Table of Contents

```bash
pandoc input.md -s --toc --toc-depth=3 -o output.html
```

### Templates

```bash
# Print default template for a format
pandoc --print-default-template=html > custom.html

# Use custom template
pandoc input.md --template=custom.html -o output.html

# Pass variables to template
pandoc input.md --template=custom.html -V key=value -o output.html
```

### Resource Handling

```bash
# Embed all resources (images, CSS, fonts) into output
pandoc input.md -s --embed-resources --standalone -o output.html

# Specify resource search path
pandoc input.md --resource-path=.:images:assets -o output.html

# Extract media from binary formats
pandoc input.docx -o output.md --extract-media=./media
```

## Batch Conversion

```bash
# Convert all .md files to .html
for f in *.md; do pandoc "$f" -s -o "${f%.md}.html"; done

# Convert all .docx to .md with media extraction
for f in *.docx; do pandoc "$f" -o "${f%.docx}.md" --extract-media="./media/${f%.docx}"; done

# Combine multiple Markdown files into one DOCX
pandoc *.md -o combined.docx --toc
```

## Markdown Flavors

Pandoc defaults to its own extended Markdown. Specify others with `-f`:

| Flavor | Flag |
|--------|------|
| Pandoc Markdown | `-f markdown` (default) |
| GitHub-Flavored | `-f gfm` |
| CommonMark | `-f commonmark_x` |
| PHP Markdown Extra | `-f markdown_phpextra` |
| Strict Markdown | `-f markdown_strict` |

Toggle individual extensions:

```bash
# Disable smart quotes, enable hard line breaks
pandoc -f markdown-smart+hard_line_breaks input.md -o output.html
```

## Lua Filters

Lightweight transformations without external dependencies.

```bash
pandoc input.md --lua-filter=filter.lua -o output.html
```

Example filter — convert all headings up one level:

```lua
-- promote-headings.lua
function Header(el)
  if el.level > 1 then
    el.level = el.level - 1
  end
  return el
end
```

Example filter — remove all images:

```lua
-- strip-images.lua
function Image(el)
  return {}
end
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Images missing in DOCX/EPUB | Use `--resource-path` to specify image directories |
| PDF fails | Install a PDF engine (`tectonic`, `xelatex`, `weasyprint`, `typst`) |
| Encoding issues | Add `--from=markdown` explicitly, ensure UTF-8 input |
| Bad line wrapping in Markdown output | Add `--wrap=none` |
| DOCX formatting lost | Create `--reference-doc` template with desired styles |
| Smart quotes unwanted | Use `-f markdown-smart` |

## Format Reference

For the full list of supported formats, run:

```bash
pandoc --list-input-formats
pandoc --list-output-formats
```

For available extensions on a format:

```bash
pandoc --list-extensions=markdown
pandoc --list-extensions=gfm
```
