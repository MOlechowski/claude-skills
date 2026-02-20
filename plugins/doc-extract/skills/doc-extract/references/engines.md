# Extraction Engines Reference

Detailed comparison, installation, and capabilities for each supported engine.

## Engine Comparison

| Engine | Type | Quality | Speed | Formats | License | Size | GPU |
|--------|------|---------|-------|---------|---------|------|-----|
| MonkeyOCR (MLX) | VLM | Excellent | Fast (MLX) | PDF, images | Apache 2.0 | ~2.5GB model | Apple Silicon (MLX) |
| Granite-Docling-258M (MLX) | VLM | Very Good | Fastest (MLX) | PDF, images | Apache 2.0 | ~500MB model | Apple Silicon (MLX) |
| Docling | Pipeline | Good | Medium | PDF, DOCX, PPTX, HTML, images | MIT | ~200MB install | Optional (MPS) |
| ocrmypdf | OCR wrapper | Good | Slow | PDF only | MPL-2.0 | ~50MB + Tesseract | No |
| Tesseract | OCR | Basic | Slow | Images only | Apache 2.0 | ~30MB + data | No |
| pypdf | Text extract | N/A (no OCR) | Instant | Digital PDF only | BSD-3 | ~2MB (bundled) | No |

## Capabilities Matrix

| Capability | MonkeyOCR | Granite-Docling | Docling | ocrmypdf | Tesseract | pypdf |
|------------|-----------|-----------------|---------|----------|-----------|-------|
| Digital PDF text | Yes | Yes | Yes | No | No | Yes |
| Scanned PDF OCR | Yes | Yes | Yes | Yes | No* | No |
| Image OCR (PNG/JPG/TIFF) | Yes | Yes | Yes | No | Yes | No |
| DOCX extraction | No | No | Yes | No | No | No |
| PPTX extraction | No | No | Yes | No | No | No |
| HTML extraction | No | No | Yes | No | No | No |
| Table structure | Yes | Yes | Yes | No | No | No |
| Heading detection | Yes | Yes | Yes | No | No | No |
| Math/equations | Yes | Yes | Yes | No | No | No |
| Markdown output | Yes | Yes | Yes | No | No | No |
| Reading order | Yes | Yes | Yes | No | No | No |

\* Tesseract processes images, not PDFs directly. The script converts PDF pages to images first when using VLM engines.

## Installation Guides

### Tier 1: MonkeyOCR (MLX) -- Best Accuracy

MonkeyOCR is a lightweight LMM-based document parser. The Apple Silicon variant uses MLX-VLM for 3x faster processing on M-series chips.

**Prerequisites:** macOS with Apple Silicon (M1/M2/M3/M4), Python 3.10+

```bash
pip install mlx-vlm
git clone https://github.com/Yuliang-Liu/MonkeyOCR.git ~/MonkeyOCR
cd ~/MonkeyOCR && pip install -e .
python tools/download_model.py -n MonkeyOCR-pro-1.2B
```

**Verify:**
```bash
python -c "import mlx_vlm; print('mlx-vlm OK')"
python -c "from monkeyocr import MonkeyOCRModel; print('MonkeyOCR OK')"
```

**Model sizes:**
- MonkeyOCR-pro-1.2B: ~2.5GB (recommended)
- MonkeyOCR-pro-3B: ~6GB (highest accuracy, slower)

### Tier 2: Granite-Docling-258M (MLX) -- Smallest/Fastest

IBM's ultra-compact document understanding VLM. Official MLX variant runs at 200-300 tokens/sec on Apple Silicon.

**Prerequisites:** macOS with Apple Silicon, Python 3.12+

```bash
pip install mlx-vlm
```

**Verify:**
```bash
python -m mlx_vlm.generate \
  --model ibm-granite/granite-docling-258M-mlx \
  --max-tokens 10 \
  --temperature 0.0 \
  --prompt "Convert this page to docling." \
  --image /path/to/test-image.png
```

The model auto-downloads on first use (~500MB).

### Tier 3: Docling (Python) -- Best Format Coverage

IBM's document conversion pipeline. Supports 16+ formats with table and layout detection.

**Prerequisites:** Python 3.10+

```bash
pip install docling
```

**Verify:**
```bash
docling --help
```

**Key CLI options:**
- `--to md` / `--to json` / `--to text` -- output format
- `--ocr` / `--no-ocr` -- enable/disable OCR for bitmap content
- `--pipeline vlm` -- use VLM pipeline for better accuracy
- `--device mps` -- Apple Silicon GPU acceleration

### Tier 4: ocrmypdf -- CPU Fallback for Scanned PDFs

Adds OCR text layer to scanned PDFs using Tesseract underneath.

```bash
brew install ocrmypdf
```

**Verify:**
```bash
ocrmypdf --version
```

**Limitations:** PDF input only, no structure preservation, plain text output via `--sidecar`.

### Tier 5: Tesseract -- Basic Image OCR

Open-source OCR engine for images.

```bash
brew install tesseract
brew install tesseract-lang  # optional: additional languages
```

**Verify:**
```bash
tesseract --version
```

**Limitations:** Images only (not PDFs), no structure preservation, no table detection.

### Tier 6: pypdf -- Digital PDF Text Extraction

Bundled as a PEP 723 dependency. Always available, no installation needed.

**Capabilities:** Extracts text from digital PDFs, reads PDF metadata. No OCR, no structure preservation. Instant speed.

## Engine Detection

The script detects engines by checking:

| Engine | Detection Method |
|--------|-----------------|
| MonkeyOCR | `python -c "from monkeyocr import MonkeyOCRModel"` + model directory exists |
| Granite-Docling (MLX) | `python -c "import mlx_vlm"` + model cached in HuggingFace hub |
| Docling | `which docling` finds CLI on PATH |
| ocrmypdf | `which ocrmypdf` finds CLI on PATH |
| Tesseract | `which tesseract` finds CLI on PATH |
| pypdf | Always available (bundled PEP 723 dep) |

## Recommended Setup

For a MacBook Pro M1 Max with 64GB RAM:

1. **Start with pypdf** (already bundled) -- handles digital PDFs immediately
2. **Install Docling** (`pip install docling`) -- adds DOCX/PPTX/HTML support + basic OCR
3. **Install Granite-Docling MLX** (`pip install mlx-vlm`) -- adds fast, high-quality OCR
4. **Optional: Install MonkeyOCR** -- adds highest accuracy for complex documents
