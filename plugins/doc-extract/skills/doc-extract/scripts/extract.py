#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pypdf>=4.0.0",
#     "pymupdf4llm>=0.3.0",
# ]
# ///
"""
Document extraction script for doc-extract skill.

Extracts structured text from PDFs, images, and documents using
the best available engine from a tiered priority system.

Usage:
    uv run extract.py engines                              # Detect engines
    uv run extract.py engines --json                       # JSON output
    uv run extract.py info document.pdf                    # Document metadata
    uv run extract.py info document.pdf --json             # JSON output
    uv run extract.py extract document.pdf                 # Extract to markdown
    uv run extract.py extract document.pdf --format json   # Structured JSON
    uv run extract.py extract document.pdf --pages 1-5     # Specific pages
    uv run extract.py extract document.pdf --engine docling # Force engine
    uv run extract.py extract document.pdf --output out.md # Write to file
    uv run extract.py extract image.png                    # OCR an image
    uv run extract.py ocr scanned.pdf                      # Force OCR
    uv run extract.py ocr photo.png --format json          # OCR with JSON

Dependencies are managed via PEP 723 (only pypdf is bundled).
Heavy engines (docling, mlx-vlm, ocrmypdf, tesseract) are called
via their CLIs, not imported.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from pypdf import PdfReader

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_PDF = {".pdf"}
SUPPORTED_IMAGE = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".webp"}
SUPPORTED_OFFICE = {".docx", ".pptx", ".html", ".htm", ".xlsx"}
SUPPORTED_ALL = SUPPORTED_PDF | SUPPORTED_IMAGE | SUPPORTED_OFFICE

ENGINE_PRIORITY = [
    "monkeyocr",
    "granite-docling-mlx",
    "docling",
    "pymupdf4llm",
    "ocrmypdf",
    "tesseract",
    "pypdf",
]

GRANITE_MODEL = "ibm-granite/granite-docling-258M-mlx"
GRANITE_CACHE_DIR = os.path.expanduser(
    "~/.cache/huggingface/hub/models--ibm-granite--granite-docling-258M-mlx"
)
MONKEYOCR_DIR = os.path.expanduser("~/MonkeyOCR")

SCANNED_TEXT_THRESHOLD = 10  # minimum words per page to consider "has text"


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def run_cmd(cmd, timeout=300, cwd=None):
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", "command not found"
    except Exception as e:
        return -1, "", str(e)


def get_version(cmd):
    """Get version string from a CLI tool."""
    rc, out, err = run_cmd(cmd, timeout=10)
    if rc == 0:
        return (out.strip() or err.strip()).split("\n")[0]
    return None


def file_extension(path):
    """Return lowercase file extension including the dot."""
    return Path(path).suffix.lower()


def resolve_pages(pages_str, total_pages):
    """Parse page range string like '1-5' or '3' into 0-based indices."""
    if not pages_str:
        return list(range(total_pages))
    parts = pages_str.split("-")
    if len(parts) == 1:
        page = int(parts[0]) - 1
        return [page] if 0 <= page < total_pages else []
    start = int(parts[0]) - 1
    end = int(parts[1])  # 1-based inclusive end
    return [i for i in range(max(0, start), min(end, total_pages))]


def error_exit(message, code=1):
    """Print error to stderr and exit."""
    print(json.dumps({"error": message}), file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Engine detection
# ---------------------------------------------------------------------------


def detect_monkeyocr():
    """Check if MonkeyOCR is available."""
    rc, _, _ = run_cmd(
        [sys.executable, "-c", "from monkeyocr import MonkeyOCRModel"], timeout=10
    )
    importable = rc == 0
    model_exists = os.path.isdir(MONKEYOCR_DIR) and any(
        f.endswith(".py") for f in os.listdir(MONKEYOCR_DIR)
    )
    weights_dir = os.path.join(MONKEYOCR_DIR, "models")
    has_weights = os.path.isdir(weights_dir) and len(os.listdir(weights_dir)) > 0
    return {
        "name": "monkeyocr",
        "display_name": "MonkeyOCR (MLX)",
        "available": importable and model_exists and has_weights,
        "importable": importable,
        "model_downloaded": has_weights,
        "install_dir": MONKEYOCR_DIR if model_exists else None,
        "version": get_version(
            [
                sys.executable,
                "-c",
                "import monkeyocr; print(getattr(monkeyocr, '__version__', 'unknown'))",
            ]
        )
        if importable
        else None,
        "formats": sorted(SUPPORTED_PDF | SUPPORTED_IMAGE),
        "capabilities": [
            "ocr",
            "tables",
            "headings",
            "math",
            "reading_order",
            "markdown",
        ],
        "install_cmd": (
            "pip install mlx-vlm && "
            "git clone https://github.com/Yuliang-Liu/MonkeyOCR.git ~/MonkeyOCR && "
            "cd ~/MonkeyOCR && pip install -e . && "
            "python tools/download_model.py -n MonkeyOCR-pro-1.2B"
        ),
    }


def detect_granite_docling():
    """Check if Granite-Docling-258M MLX is available."""
    rc, _, _ = run_cmd([sys.executable, "-c", "import mlx_vlm"], timeout=10)
    importable = rc == 0
    model_cached = os.path.isdir(GRANITE_CACHE_DIR)
    return {
        "name": "granite-docling-mlx",
        "display_name": "Granite-Docling-258M (MLX)",
        "available": importable and model_cached,
        "importable": importable,
        "model_downloaded": model_cached,
        "version": get_version(
            [sys.executable, "-c", "import mlx_vlm; print(mlx_vlm.__version__)"]
        )
        if importable
        else None,
        "formats": sorted(SUPPORTED_PDF | SUPPORTED_IMAGE),
        "capabilities": [
            "ocr",
            "tables",
            "headings",
            "math",
            "reading_order",
            "markdown",
        ],
        "install_cmd": "pip install mlx-vlm",
        "model_download_cmd": (
            f"python -m mlx_vlm.generate --model {GRANITE_MODEL} "
            '--max-tokens 1 --prompt "test" --image /dev/null 2>/dev/null || true'
        ),
    }


def detect_docling():
    """Check if Docling CLI is available."""
    path = shutil.which("docling")
    version = get_version(["docling", "--version"]) if path else None
    return {
        "name": "docling",
        "display_name": "Docling",
        "available": path is not None,
        "path": path,
        "version": version,
        "formats": sorted(SUPPORTED_PDF | SUPPORTED_IMAGE | SUPPORTED_OFFICE),
        "capabilities": [
            "ocr",
            "tables",
            "headings",
            "math",
            "reading_order",
            "markdown",
        ],
        "install_cmd": "pip install docling",
    }


def detect_pymupdf4llm():
    """Check if pymupdf4llm is available."""
    rc, _, _ = run_cmd(
        [sys.executable, "-c", "import pymupdf4llm"], timeout=10
    )
    importable = rc == 0
    version = None
    if importable:
        version = get_version(
            [sys.executable, "-c",
             "import sys, io; sys.stdout = io.StringIO(); import pymupdf4llm; v = pymupdf4llm.__version__; sys.stdout = sys.__stdout__; print(v)"]
        )
    return {
        "name": "pymupdf4llm",
        "display_name": "PyMuPDF4LLM",
        "available": importable,
        "version": version,
        "formats": [".pdf"],
        "capabilities": ["text_extraction", "headings", "tables", "markdown"],
        "install_cmd": "pip install pymupdf4llm",
    }


def detect_ocrmypdf():
    """Check if ocrmypdf CLI is available."""
    path = shutil.which("ocrmypdf")
    version = get_version(["ocrmypdf", "--version"]) if path else None
    return {
        "name": "ocrmypdf",
        "display_name": "ocrmypdf",
        "available": path is not None,
        "path": path,
        "version": version,
        "formats": [".pdf"],
        "capabilities": ["ocr"],
        "install_cmd": "brew install ocrmypdf",
    }


def detect_tesseract():
    """Check if Tesseract CLI is available."""
    path = shutil.which("tesseract")
    version = get_version(["tesseract", "--version"]) if path else None
    return {
        "name": "tesseract",
        "display_name": "Tesseract",
        "available": path is not None,
        "path": path,
        "version": version,
        "formats": sorted(SUPPORTED_IMAGE),
        "capabilities": ["ocr"],
        "install_cmd": "brew install tesseract",
    }


def detect_pypdf():
    """pypdf is always available (bundled dependency)."""
    import pypdf as _pypdf

    return {
        "name": "pypdf",
        "display_name": "pypdf",
        "available": True,
        "version": _pypdf.__version__,
        "formats": [".pdf"],
        "capabilities": ["text_extraction"],
        "install_cmd": None,
    }


def detect_all_engines():
    """Detect all engines and return list of info dicts."""
    return [
        detect_monkeyocr(),
        detect_granite_docling(),
        detect_docling(),
        detect_pymupdf4llm(),
        detect_ocrmypdf(),
        detect_tesseract(),
        detect_pypdf(),
    ]


def select_engine(engines, ext, force_ocr=False, forced_engine=None):
    """Select the best available engine for the given file extension."""
    engine_map = {e["name"]: e for e in engines}

    if forced_engine:
        eng = engine_map.get(forced_engine)
        if not eng or not eng["available"] or ext not in eng["formats"]:
            return None
        return eng

    for name in ENGINE_PRIORITY:
        eng = engine_map.get(name)
        if not eng or not eng["available"]:
            continue
        if ext not in eng["formats"]:
            continue
        if force_ocr and name == "pypdf":
            continue
        return eng

    return None


# ---------------------------------------------------------------------------
# PDF analysis
# ---------------------------------------------------------------------------


def analyze_pdf(path):
    """Analyze a PDF file and return metadata."""
    reader = PdfReader(path)
    total_pages = len(reader.pages)
    meta = reader.metadata or {}

    if total_pages == 0:
        sample_indices = []
    elif total_pages == 1:
        sample_indices = [0]
    elif total_pages == 2:
        sample_indices = [0, 1]
    else:
        sample_indices = [0, total_pages // 2, total_pages - 1]

    sample_word_counts = []
    total_words = 0
    for idx in range(total_pages):
        text = reader.pages[idx].extract_text() or ""
        words = len(text.split())
        total_words += words
        if idx in sample_indices:
            sample_word_counts.append(words)

    has_text = (
        all(wc >= SCANNED_TEXT_THRESHOLD for wc in sample_word_counts)
        if sample_word_counts
        else False
    )

    return {
        "format": "pdf",
        "pages": total_pages,
        "has_text": has_text,
        "estimated_words": total_words,
        "sampled_pages": len(sample_indices),
        "sample_word_counts": sample_word_counts,
        "metadata": {
            "title": str(meta.get("/Title", "")) or None,
            "author": str(meta.get("/Author", "")) or None,
            "subject": str(meta.get("/Subject", "")) or None,
            "creator": str(meta.get("/Creator", "")) or None,
            "created": str(meta.get("/CreationDate", "")) or None,
        },
    }


def analyze_image(path):
    """Analyze an image file and return basic metadata."""
    stat = os.stat(path)
    return {
        "format": file_extension(path).lstrip("."),
        "pages": 1,
        "has_text": False,
        "estimated_words": 0,
        "metadata": {},
        "file_size": stat.st_size,
    }


def analyze_office(path):
    """Analyze an office document and return basic metadata."""
    stat = os.stat(path)
    ext = file_extension(path).lstrip(".")
    return {
        "format": ext,
        "pages": None,
        "has_text": True,
        "estimated_words": None,
        "metadata": {},
        "file_size": stat.st_size,
    }


def analyze_file(path):
    """Analyze any supported file and return metadata."""
    ext = file_extension(path)
    if ext in SUPPORTED_PDF:
        return analyze_pdf(path)
    elif ext in SUPPORTED_IMAGE:
        return analyze_image(path)
    elif ext in SUPPORTED_OFFICE:
        return analyze_office(path)
    else:
        error_exit(f"Unsupported format: {ext}. Supported: {sorted(SUPPORTED_ALL)}")


# ---------------------------------------------------------------------------
# Extraction via each engine
# ---------------------------------------------------------------------------


def extract_pypdf(path, pages=None):
    """Extract text from a digital PDF using pypdf."""
    reader = PdfReader(path)
    total = len(reader.pages)
    page_indices = pages if pages is not None else list(range(total))
    parts = []
    for idx in page_indices:
        if 0 <= idx < total:
            text = reader.pages[idx].extract_text() or ""
            parts.append(text)
    return "\n\n".join(parts)


def extract_docling(path, output_format="md"):
    """Extract content using Docling CLI."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = ["docling", str(path), "--to", output_format, "--output", tmpdir]
        rc, out, err = run_cmd(cmd, timeout=600)
        if rc != 0:
            error_exit(f"Docling failed: {err}")

        ext_map = {"md": ".md", "text": ".txt", "json": ".json"}
        out_ext = ext_map.get(output_format, ".md")
        candidates = list(Path(tmpdir).rglob(f"*{out_ext}"))
        if not candidates:
            candidates = [c for c in Path(tmpdir).rglob("*") if c.is_file()]
        if not candidates:
            error_exit("Docling produced no output files")
        return candidates[0].read_text(encoding="utf-8", errors="replace")


def extract_pymupdf4llm(path, pages=None):
    """Extract structured markdown with heading hierarchy using PyMuPDF4LLM.

    Uses font-size analysis to infer heading levels (# , ## , ### ).
    Falls back to PDF TOC/bookmarks when available.
    """
    page_arg = "None" if pages is None else repr(pages)
    script = f"""
import sys, io
sys.stdout = io.StringIO()
import pymupdf4llm
sys.stdout = sys.__stdout__
md = pymupdf4llm.to_markdown({repr(str(path))}, pages={page_arg})
sys.stdout.write(md)
"""
    rc, out, err = run_cmd([sys.executable, "-c", script], timeout=300)
    if rc != 0:
        error_exit(f"pymupdf4llm failed: {err}")
    return out


def extract_ocrmypdf(path, force_ocr=False):
    """Extract text from a scanned PDF using ocrmypdf."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sidecar_path = os.path.join(tmpdir, "output.txt")
        output_pdf = os.path.join(tmpdir, "output.pdf")
        cmd = ["ocrmypdf", "--sidecar", sidecar_path]
        if force_ocr:
            cmd.append("--force-ocr")
        else:
            cmd.append("--skip-text")
        cmd.extend([str(path), output_pdf])
        rc, out, err = run_cmd(cmd, timeout=600)
        if rc != 0:
            error_exit(f"ocrmypdf failed: {err}")
        if os.path.exists(sidecar_path):
            return Path(sidecar_path).read_text(encoding="utf-8", errors="replace")
        return ""


def extract_tesseract(path):
    """Extract text from an image using Tesseract."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_base = os.path.join(tmpdir, "output")
        cmd = ["tesseract", str(path), output_base, "-l", "eng"]
        rc, out, err = run_cmd(cmd, timeout=120)
        if rc != 0:
            error_exit(f"Tesseract failed: {err}")
        output_file = output_base + ".txt"
        if os.path.exists(output_file):
            return Path(output_file).read_text(encoding="utf-8", errors="replace")
        return ""


def extract_granite_docling(path, pages=None):
    """Extract content using Granite-Docling-258M via mlx-vlm."""
    ext = file_extension(path)
    if ext in SUPPORTED_PDF:
        return _extract_vlm_from_pdf(path, "granite", pages)
    else:
        return _extract_vlm_from_image(path, "granite")


def extract_monkeyocr(path):
    """Extract content using MonkeyOCR."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            sys.executable,
            os.path.join(MONKEYOCR_DIR, "parse.py"),
            str(path),
            "-o",
            tmpdir,
        ]
        rc, out, err = run_cmd(cmd, timeout=600, cwd=MONKEYOCR_DIR)
        if rc != 0:
            error_exit(f"MonkeyOCR failed: {err}")
        md_files = sorted(Path(tmpdir).rglob("*.md"))
        if md_files:
            return "\n\n".join(
                f.read_text(encoding="utf-8", errors="replace") for f in md_files
            )
        txt_files = sorted(Path(tmpdir).rglob("*.txt"))
        if txt_files:
            return "\n\n".join(
                f.read_text(encoding="utf-8", errors="replace") for f in txt_files
            )
        return out


def _pdf_page_to_image(pdf_path, page_idx, output_dir):
    """Convert a single PDF page to a PNG image.

    Uses macOS sips (built-in, zero extra deps) with ImageMagick fallback.
    """
    from pypdf import PdfReader as _Reader, PdfWriter as _Writer

    reader = _Reader(pdf_path)
    writer = _Writer()
    writer.add_page(reader.pages[page_idx])
    single_pdf = os.path.join(output_dir, f"page_{page_idx}.pdf")
    with open(single_pdf, "wb") as f:
        writer.write(f)

    img_path = os.path.join(output_dir, f"page_{page_idx}.png")
    rc, _, _ = run_cmd(
        ["sips", "-s", "format", "png", single_pdf, "--out", img_path], timeout=30
    )
    if rc != 0:
        rc, _, _ = run_cmd(
            ["convert", "-density", "200", single_pdf, img_path], timeout=30
        )
        if rc != 0:
            return None
    return img_path


def _extract_vlm_from_image(image_path, engine_type):
    """Run a VLM engine on a single image and return text."""
    if engine_type == "granite":
        cmd = [
            sys.executable,
            "-m",
            "mlx_vlm.generate",
            "--model",
            GRANITE_MODEL,
            "--max-tokens",
            "4096",
            "--temperature",
            "0.0",
            "--prompt",
            "Convert this page to docling.",
            "--image",
            str(image_path),
        ]
    else:
        error_exit(f"Unknown VLM engine type: {engine_type}")

    rc, out, err = run_cmd(cmd, timeout=300)
    if rc != 0:
        error_exit(f"VLM extraction failed: {err}")
    return _doctags_to_markdown(out) if engine_type == "granite" else out


def _extract_vlm_from_pdf(pdf_path, engine_type, pages=None):
    """Convert PDF pages to images and run VLM on each."""
    reader = PdfReader(pdf_path)
    total = len(reader.pages)
    page_indices = pages if pages is not None else list(range(total))
    parts = []

    with tempfile.TemporaryDirectory() as tmpdir:
        for idx in page_indices:
            if idx < 0 or idx >= total:
                continue
            img_path = _pdf_page_to_image(pdf_path, idx, tmpdir)
            if img_path and os.path.exists(img_path):
                text = _extract_vlm_from_image(img_path, engine_type)
                parts.append(text)
            else:
                parts.append(f"[Page {idx + 1}: could not convert to image]")

    return "\n\n".join(parts)


def _doctags_to_markdown(doctags_text):
    """Convert DocTags format to markdown.

    DocTags uses XML-like tags: <heading>, <table>, <paragraph>, etc.
    Best-effort conversion to markdown.
    """
    text = doctags_text.strip()

    if "<doctag>" in text:
        start = text.index("<doctag>")
        text = text[start:]
    if "</doctag>" in text:
        end = text.index("</doctag>") + len("</doctag>")
        text = text[:end]

    replacements = [
        (r"<doctag>", ""),
        (r"</doctag>", ""),
        (r"<page_break/>", "\n---\n"),
        (r'<heading level="1">(.*?)</heading>', r"# \1"),
        (r'<heading level="2">(.*?)</heading>', r"## \1"),
        (r'<heading level="3">(.*?)</heading>', r"### \1"),
        (r'<heading level="4">(.*?)</heading>', r"#### \1"),
        (r"<heading>(.*?)</heading>", r"## \1"),
        (r"<paragraph>(.*?)</paragraph>", r"\1\n"),
        (r"<caption>(.*?)</caption>", r"*\1*\n"),
        (r"<formula>(.*?)</formula>", r"$\1$"),
        (r"<code>(.*?)</code>", r"`\1`"),
        (r"<list_item>(.*?)</list_item>", r"- \1"),
        (r"<footnote>(.*?)</footnote>", r"[^]: \1"),
    ]

    for pattern, repl in replacements:
        text = re.sub(pattern, repl, text, flags=re.DOTALL)

    # Clean remaining tags
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


# ---------------------------------------------------------------------------
# Main extraction dispatcher
# ---------------------------------------------------------------------------


def do_extract(path, engines, output_format="markdown", force_ocr=False,
               forced_engine=None, pages_str=None):
    """Extract content from a file. Returns result dict."""
    ext = file_extension(path)
    if ext not in SUPPORTED_ALL:
        error_exit(f"Unsupported format: {ext}. Supported: {sorted(SUPPORTED_ALL)}")

    needs_ocr = force_ocr
    pdf_info = None
    if ext in SUPPORTED_PDF:
        pdf_info = analyze_pdf(path)
        if not pdf_info["has_text"]:
            needs_ocr = True
    elif ext in SUPPORTED_IMAGE:
        needs_ocr = True

    engine = select_engine(
        engines, ext, force_ocr=needs_ocr or force_ocr, forced_engine=forced_engine
    )
    if not engine:
        install_hints = []
        for e in engines:
            if not e["available"] and ext in e.get("formats", []):
                cmd = e.get("install_cmd")
                if cmd:
                    install_hints.append(f"  {e['display_name']}: {cmd}")
        msg = f"No engine available for {ext} files"
        if needs_ocr:
            msg += " (OCR required)"
        if install_hints:
            msg += ". Install one of:\n" + "\n".join(install_hints)
        error_exit(msg)

    pages = None
    if pages_str and pdf_info:
        pages = resolve_pages(pages_str, pdf_info["pages"])

    start_time = time.time()
    engine_name = engine["name"]

    if engine_name == "pypdf":
        content = extract_pypdf(path, pages)
    elif engine_name == "docling":
        fmt_map = {"markdown": "md", "text": "text", "json": "json"}
        content = extract_docling(path, fmt_map.get(output_format, "md"))
    elif engine_name == "pymupdf4llm":
        content = extract_pymupdf4llm(path, pages)
    elif engine_name == "ocrmypdf":
        content = extract_ocrmypdf(path, force_ocr=force_ocr)
    elif engine_name == "tesseract":
        content = extract_tesseract(path)
    elif engine_name == "granite-docling-mlx":
        content = extract_granite_docling(path, pages)
    elif engine_name == "monkeyocr":
        content = extract_monkeyocr(path)
    else:
        error_exit(f"Unknown engine: {engine_name}")

    elapsed = time.time() - start_time
    word_count = len(content.split()) if content else 0

    return {
        "file": str(Path(path).resolve()),
        "format": ext.lstrip("."),
        "engine": engine_name,
        "engine_version": engine.get("version"),
        "pages": pdf_info["pages"] if pdf_info else (1 if ext in SUPPORTED_IMAGE else None),
        "has_text": pdf_info["has_text"] if pdf_info else (ext not in SUPPORTED_IMAGE),
        "word_count": word_count,
        "extraction_time_seconds": round(elapsed, 2),
        "content": content,
        "metadata": pdf_info.get("metadata", {}) if pdf_info else {},
    }


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_engines(args):
    """Detect and report available engines."""
    engines = detect_all_engines()
    if args.json:
        recommended = next((e["name"] for e in engines if e["available"]), None)
        print(json.dumps({"engines": engines, "recommended": recommended}, indent=2))
    else:
        print("Extraction Engines")
        print("=" * 60)
        recommended = None
        for e in engines:
            status = "AVAILABLE" if e["available"] else "NOT INSTALLED"
            marker = ""
            if e["available"] and recommended is None:
                recommended = e["name"]
                marker = " [RECOMMENDED]"
            print(f"\n{e['display_name']}{marker}")
            print(f"  Status: {status}")
            if e.get("version"):
                print(f"  Version: {e['version']}")
            print(f"  Formats: {', '.join(e.get('formats', []))}")
            print(f"  Capabilities: {', '.join(e.get('capabilities', []))}")
            if not e["available"]:
                if e.get("importable") is False and e.get("install_cmd"):
                    print(f"  Install: {e['install_cmd']}")
                elif e.get("importable") and not e.get("model_downloaded"):
                    cmd = e.get("model_download_cmd", e.get("install_cmd", ""))
                    print(f"  Model needed: {cmd}")
                elif e.get("install_cmd"):
                    print(f"  Install: {e['install_cmd']}")
        print(f"\n{'=' * 60}")
        if recommended:
            print(f"Best available: {recommended}")
        else:
            print("No OCR engines installed. pypdf handles digital PDFs only.")


def cmd_info(args):
    """Show document metadata."""
    path = args.file
    if not os.path.exists(path):
        error_exit(f"File not found: {path}")

    info = analyze_file(path)
    info["file"] = str(Path(path).resolve())
    info["file_size"] = os.path.getsize(path)

    engines = detect_all_engines()
    ext = file_extension(path)
    needs_ocr = not info.get("has_text", True)
    engine = select_engine(engines, ext, force_ocr=needs_ocr)
    info["recommended_engine"] = engine["name"] if engine else None

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"File: {info['file']}")
        print(f"Format: {info['format']}")
        print(f"Size: {info['file_size']:,} bytes")
        if info.get("pages") is not None:
            print(f"Pages: {info['pages']}")
        if info.get("has_text") is not None:
            status = "Yes" if info["has_text"] else "No (scanned/image)"
            print(f"Has text: {status}")
        if info.get("estimated_words") is not None:
            print(f"Estimated words: {info['estimated_words']:,}")
        meta = info.get("metadata", {})
        if meta:
            for key, val in meta.items():
                if val:
                    print(f"  {key}: {val}")
        if info.get("recommended_engine"):
            print(f"Recommended engine: {info['recommended_engine']}")


def cmd_extract(args):
    """Extract text/markdown from a document."""
    path = args.file
    if not os.path.exists(path):
        error_exit(f"File not found: {path}")

    engines = detect_all_engines()
    result = do_extract(
        path, engines,
        output_format=args.format,
        force_ocr=False,
        forced_engine=args.engine,
        pages_str=args.pages,
    )

    if args.format == "json":
        output = json.dumps(result, indent=2)
    else:
        output = result["content"]

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Written to: {args.output}", file=sys.stderr)
    else:
        print(output)


def cmd_ocr(args):
    """Force OCR on a document."""
    path = args.file
    if not os.path.exists(path):
        error_exit(f"File not found: {path}")

    engines = detect_all_engines()
    result = do_extract(
        path, engines,
        output_format=args.format,
        force_ocr=True,
        forced_engine=args.engine,
        pages_str=args.pages,
    )

    if args.format == "json":
        output = json.dumps(result, indent=2)
    else:
        output = result["content"]

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Written to: {args.output}", file=sys.stderr)
    else:
        print(output)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description="Extract structured text from documents using tiered engines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  uv run extract.py engines                              # Detect engines
  uv run extract.py info document.pdf                    # Document metadata
  uv run extract.py extract document.pdf                 # Extract to markdown
  uv run extract.py extract document.pdf --format json   # Structured JSON
  uv run extract.py extract document.pdf --pages 1-5     # Specific pages
  uv run extract.py extract image.png                    # OCR an image
  uv run extract.py ocr scanned.pdf                      # Force OCR
""",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_engines = subparsers.add_parser(
        "engines", help="Detect available extraction engines"
    )
    p_engines.add_argument("--json", action="store_true", help="Output as JSON")

    p_info = subparsers.add_parser("info", help="Show document metadata")
    p_info.add_argument("file", help="Path to document")
    p_info.add_argument("--json", action="store_true", help="Output as JSON")

    p_extract = subparsers.add_parser(
        "extract", help="Extract text/markdown from document"
    )
    p_extract.add_argument("file", help="Path to document")
    p_extract.add_argument(
        "--engine", choices=ENGINE_PRIORITY, help="Force a specific engine"
    )
    p_extract.add_argument(
        "--format",
        choices=["markdown", "text", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    p_extract.add_argument("--pages", help="Page range (e.g., 1-5, 3)")
    p_extract.add_argument(
        "--output", "-o", help="Write to file instead of stdout"
    )

    ocr_engine_choices = [e for e in ENGINE_PRIORITY if e != "pypdf"]
    p_ocr = subparsers.add_parser("ocr", help="Force OCR on a scanned document")
    p_ocr.add_argument("file", help="Path to document")
    p_ocr.add_argument(
        "--engine", choices=ocr_engine_choices, help="Force a specific OCR engine"
    )
    p_ocr.add_argument(
        "--format",
        choices=["markdown", "text", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    p_ocr.add_argument("--pages", help="Page range (e.g., 1-5, 3)")
    p_ocr.add_argument(
        "--output", "-o", help="Write to file instead of stdout"
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = build_parser()
    args = parser.parse_args()
    dispatch = {
        "engines": cmd_engines,
        "info": cmd_info,
        "extract": cmd_extract,
        "ocr": cmd_ocr,
    }
    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
