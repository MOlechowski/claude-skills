---
name: doc-extract
description: "Document intelligence: extract structured text from PDFs, images, and documents using tiered OCR/extraction engines (MonkeyOCR MLX, Granite-Docling MLX, Docling, PyMuPDF4LLM, ocrmypdf, Tesseract, pypdf). Use for: (1) extracting text/markdown from PDFs (digital and scanned), (2) OCR on scanned PDFs and images (PNG, JPG, TIFF), (3) extracting content from DOCX, PPTX, HTML, (4) detecting available extraction engines, (5) document metadata and scanned-PDF detection. Triggers: extract text, OCR, pdf to markdown, extract from pdf, document extraction, scanned pdf, image to text, read document, doc-extract."
---

# doc-extract

Extract structured text from PDFs, images, and documents using the best available engine.

## Architecture

Seven extraction engines, auto-selected by availability and document type:

| Tier | Engine | Strengths | Install |
|------|--------|-----------|---------|
| 1 | MonkeyOCR (MLX) | Best accuracy, Apple Silicon 3x speedup | `pip install mlx-vlm` + model download |
| 2 | Granite-Docling-258M (MLX) | Smallest/fastest VLM, Apache 2.0 | `pip install mlx-vlm` + model download |
| 3 | Docling (Python) | Good quality, MIT, 16+ formats | `pip install docling` |
| 4 | PyMuPDF4LLM | Heading hierarchy via font-size detection, fast | `pip install pymupdf4llm` |
| 5 | ocrmypdf | CPU fallback for scanned PDFs | `brew install ocrmypdf` |
| 6 | Tesseract | Basic fallback for images | `brew install tesseract` |
| 7 | pypdf | Lightweight, digital PDFs only (no OCR) | Always available (bundled) |

Engine selection is automatic. The script detects what is installed and uses the highest-tier engine that supports the input format.

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| uv | Python package manager (runs the script) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

All other dependencies are optional. The script always works with at least pypdf (bundled via PEP 723).

## Workflow

| Step | Action | Purpose |
|------|--------|---------|
| 1 | Detect engines | Run `engines` to see what is available |
| 2 | Check document | Run `info <file>` for metadata and format detection |
| 3 | Extract or OCR | Run `extract <file>` or `ocr <file>` for content |
| 4 | Use output | Parse JSON output or read markdown directly |

## Commands

### engines -- Detect Available Engines

```bash
uv run scripts/extract.py engines
uv run scripts/extract.py engines --json
```

Reports which engines are installed, their versions, capabilities, and model status. Run this first to understand what extraction quality is available.

### info -- Document Metadata

```bash
uv run scripts/extract.py info document.pdf
uv run scripts/extract.py info document.pdf --json
```

Reports: format, page count, has extractable text (for PDFs), estimated word count, file size, and recommended engine.

For PDFs, samples up to 3 pages to detect whether text is extractable (digital) or requires OCR (scanned).

### extract -- Extract Text/Markdown

```bash
uv run scripts/extract.py extract document.pdf
uv run scripts/extract.py extract document.pdf --engine docling
uv run scripts/extract.py extract document.pdf --format markdown
uv run scripts/extract.py extract document.pdf --format text
uv run scripts/extract.py extract document.pdf --format json
uv run scripts/extract.py extract document.pdf --pages 1-5
uv run scripts/extract.py extract document.pdf --output extracted.md
uv run scripts/extract.py extract image.png
uv run scripts/extract.py extract document.docx
```

Extracts content using the best available engine. Defaults to markdown output on stdout.

| Flag | Purpose | Default |
|------|---------|---------|
| `--engine` | Force a specific engine | auto-detect |
| `--format` | Output format: `markdown`, `text`, `json` | `markdown` |
| `--pages` | Page range (e.g., `1-5`, `3`, `10-20`) | all pages |
| `--output` | Write to file instead of stdout | stdout |

### ocr -- OCR a Scanned Document

```bash
uv run scripts/extract.py ocr scanned.pdf
uv run scripts/extract.py ocr photo.png
uv run scripts/extract.py ocr scanned.pdf --engine tesseract
uv run scripts/extract.py ocr scanned.pdf --format json
```

Forces OCR processing regardless of whether text is already extractable. Same options as `extract`, but skips the digital-text shortcut and always runs OCR.

## Engine Selection Logic

```
1. If --engine specified: use that engine (fail if unavailable)
2. For PDF with extractable text: pypdf (fast, no external deps)
3. For scanned PDF / image:
   a. MonkeyOCR if installed + model downloaded
   b. Granite-Docling-258M (MLX) if installed + model downloaded
   c. Docling if installed
   d. ocrmypdf if installed (PDF only)
   e. Tesseract if installed (images only)
   f. FAIL with install instructions
4. For DOCX/PPTX/HTML:
   a. Docling if installed
   b. FAIL with install instructions
```

For the `ocr` subcommand, pypdf is never selected (it cannot OCR).

## Output Formats

### Markdown (default)

Preserves document structure: headings, tables, lists, code blocks, emphasis.

### Text

Plain text with minimal formatting. Paragraphs separated by blank lines.

### JSON

Structured metadata plus content:

```json
{
  "file": "/path/to/document.pdf",
  "format": "pdf",
  "engine": "docling",
  "engine_version": "2.71.0",
  "pages": 42,
  "has_text": true,
  "word_count": 15230,
  "extraction_time_seconds": 3.2,
  "content": "# Document Title\n\nExtracted markdown...",
  "metadata": {
    "title": "Document Title",
    "author": "Author Name",
    "created": "2025-01-15"
  }
}
```

## Scanned PDF Detection

Samples up to 3 evenly-spaced pages with pypdf and checks for extractable text:

- If **all sampled pages** have extractable text (>10 words each): digital PDF, use pypdf
- If **any sampled page** lacks text: scanned PDF, use OCR engine
- Sample positions: page 0, page N/2, page N-1

## First-Run Experience

### MLX Models (MonkeyOCR, Granite-Docling)

First run downloads the model (~500MB for Granite-Docling, ~2.5GB for MonkeyOCR). Run `engines` to check model download status.

To pre-download Granite-Docling:

```bash
python -m mlx_vlm.generate --model ibm-granite/granite-docling-258M-mlx \
  --max-tokens 1 --prompt "test" --image /dev/null 2>/dev/null || true
```

### Docling

First `pip install docling` is ~200MB. No additional model downloads needed for basic usage.

## Constraints

**DO:**
- Run `engines` before first use to understand available quality
- Use `info` to check document type before extraction
- Use `--json` for programmatic consumption
- Use `--pages` for large documents to extract specific sections
- Prefer `extract` for digital PDFs (faster, uses pypdf)
- Prefer `ocr` for scanned documents (forces OCR pipeline)

**DON'T:**
- Force an engine that is not installed
- Use `ocr` on digital PDFs unless the text layer is known to be unreliable
- Extract entire large PDFs when only specific pages are needed
- Expect OCR engines to be available without explicit installation

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `engines` shows nothing installed | Install at least one engine (see `references/engines.md`) |
| Scanned PDF returns empty text | No OCR engine installed. Install docling or tesseract |
| MLX model not found | Run model download command (see First-Run Experience) |
| DOCX/PPTX extraction fails | Install docling: `pip install docling` |
| Slow extraction on large PDF | Use `--pages` to limit scope |
| Wrong engine selected | Use `--engine` to force a specific engine |
| pypdf returns garbled text | PDF may be scanned despite text layer. Use `ocr` subcommand |

## References

- `references/engines.md` -- Engine comparison, installation guides, capabilities matrix
