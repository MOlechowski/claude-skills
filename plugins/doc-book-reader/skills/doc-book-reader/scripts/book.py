#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pypdf>=4.0.0",
# ]
# ///
"""
Book reader orchestration script for doc-book-reader skill.

Detects book format, extracts text via doc-extract/pandoc, splits into
chapter-aware chunks, and merges agent summaries for synthesis.

Usage:
    uv run book.py detect <file>
    uv run book.py chunk <file> [--strategy S] [--max-words N] [--max-pages N]
    uv run book.py merge <session_dir>

Dependencies are managed via PEP 723 (only pypdf is bundled).
doc-extract and pandoc are called via subprocess when available.
"""

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from pypdf import PdfReader

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_WORDS = 15000
DEFAULT_MAX_PAGES = 30
WORDS_PER_PAGE_ESTIMATE = 300

CHAPTER_PATTERNS = [
    re.compile(r"^chapter\s+\d+", re.IGNORECASE),
    re.compile(r"^chapter\s+[IVXLCDM]+", re.IGNORECASE),
    re.compile(r"^CHAPTER\s+\d+"),
    re.compile(r"^CHAPTER\s+[IVXLCDM]+"),
    re.compile(r"^part\s+\d+", re.IGNORECASE),
    re.compile(r"^part\s+[IVXLCDM]+", re.IGNORECASE),
    re.compile(r"^PART\s+\d+"),
    re.compile(r"^PART\s+[IVXLCDM]+"),
    re.compile(r"^section\s+\d+", re.IGNORECASE),
    re.compile(r"^\d+\.\s+[A-Z]"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def word_count(text: str) -> int:
    """Count words in text."""
    return len(text.split())


def find_extract_script() -> Path | None:
    """Locate doc-extract's extract.py relative to this script."""
    this_dir = Path(__file__).resolve().parent
    # Installed plugin layout: plugins/doc-book-reader/skills/doc-book-reader/scripts/book.py
    # Sibling plugin:          plugins/doc-extract/skills/doc-extract/scripts/extract.py
    candidates = [
        this_dir / ".." / ".." / ".." / ".." / "doc-extract" / "skills" / "doc-extract" / "scripts" / "extract.py",
        Path.home() / ".claude" / "skills" / "doc-extract" / "scripts" / "extract.py",
    ]
    for c in candidates:
        resolved = c.resolve()
        if resolved.is_file():
            return resolved
    return None


def find_pandoc() -> str | None:
    """Check if pandoc is available."""
    try:
        subprocess.run(
            ["pandoc", "--version"],
            capture_output=True,
            timeout=10,
        )
        return "pandoc"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def detect_format(filepath: Path) -> str:
    """Detect book format from extension."""
    ext = filepath.suffix.lower()
    fmt_map = {
        ".pdf": "pdf",
        ".epub": "epub",
        ".docx": "docx",
        ".doc": "docx",
        ".txt": "txt",
        ".md": "markdown",
        ".markdown": "markdown",
        ".html": "html",
        ".htm": "html",
        ".odt": "odt",
        ".rtf": "rtf",
    }
    return fmt_map.get(ext, "unknown")


# ---------------------------------------------------------------------------
# PDF helpers
# ---------------------------------------------------------------------------


def pdf_metadata(reader: PdfReader, filepath: Path) -> dict:
    """Extract metadata from a PDF."""
    meta = reader.metadata or {}
    pages = len(reader.pages)

    # Estimate words from first few pages
    sample_pages = min(5, pages)
    sample_words = 0
    for i in range(sample_pages):
        text = reader.pages[i].extract_text() or ""
        sample_words += word_count(text)

    avg_words_per_page = sample_words / max(sample_pages, 1)
    estimated_words = int(avg_words_per_page * pages)

    # Check if text is extractable
    has_text = avg_words_per_page > 10

    return {
        "title": str(meta.get("/Title", filepath.stem)),
        "author": str(meta.get("/Author", "Unknown")),
        "pages": pages,
        "estimated_words": estimated_words,
        "has_text": has_text,
    }


def pdf_detect_chapters(reader: PdfReader) -> list[dict]:
    """Detect chapter boundaries in a PDF by scanning page text for heading patterns."""
    chapters = []
    pages = len(reader.pages)

    for i in range(pages):
        text = (reader.pages[i].extract_text() or "").strip()
        if not text:
            continue

        # Check first few lines of each page for chapter headings
        lines = text.split("\n")[:5]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            for pattern in CHAPTER_PATTERNS:
                if pattern.match(line):
                    # Clean up the title
                    title = line[:120].strip()
                    chapters.append({
                        "title": title,
                        "start_page": i + 1,  # 1-indexed
                    })
                    break
            else:
                continue
            break  # Found a chapter on this page, move to next page

    # Compute end pages
    for idx in range(len(chapters)):
        if idx + 1 < len(chapters):
            chapters[idx]["end_page"] = chapters[idx + 1]["start_page"] - 1
        else:
            chapters[idx]["end_page"] = pages

    return chapters


def pdf_extract_pages_pypdf(reader: PdfReader, start: int, end: int) -> str:
    """Extract text from a range of pages using pypdf (0-indexed start, inclusive end)."""
    parts = []
    for i in range(start, min(end + 1, len(reader.pages))):
        text = reader.pages[i].extract_text() or ""
        if text.strip():
            parts.append(text)
    return "\n\n".join(parts)


def pdf_extract_pages_docextract(
    extract_script: Path, filepath: Path, start_page: int, end_page: int, output: Path
) -> bool:
    """Extract pages using doc-extract's extract.py. Pages are 1-indexed."""
    try:
        result = subprocess.run(
            [
                "uv", "run", str(extract_script),
                "extract", str(filepath),
                "--pages", f"{start_page}-{end_page}",
                "--output", str(output),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0 and output.is_file()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Text/Markdown helpers
# ---------------------------------------------------------------------------


def text_detect_chapters(text: str) -> list[dict]:
    """Detect chapters in plain text / markdown by heading patterns."""
    chapters = []
    lines = text.split("\n")

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        # Markdown headings
        if stripped.startswith("# ") and not stripped.startswith("## "):
            chapters.append({
                "title": stripped.lstrip("# ").strip()[:120],
                "line_start": i,
            })
            continue

        # Plain text chapter patterns
        for pattern in CHAPTER_PATTERNS:
            if pattern.match(stripped):
                chapters.append({
                    "title": stripped[:120],
                    "line_start": i,
                })
                break

    # Compute line ranges
    for idx in range(len(chapters)):
        if idx + 1 < len(chapters):
            chapters[idx]["line_end"] = chapters[idx + 1]["line_start"] - 1
        else:
            chapters[idx]["line_end"] = len(lines) - 1

    return chapters


def epub_to_markdown(filepath: Path) -> str | None:
    """Convert EPUB/DOCX to markdown via pandoc."""
    if not find_pandoc():
        return None
    try:
        result = subprocess.run(
            ["pandoc", str(filepath), "-t", "markdown", "--wrap=none"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


# ---------------------------------------------------------------------------
# Strategy selection
# ---------------------------------------------------------------------------


def recommend_strategy(pages: int, words: int) -> str:
    """Recommend processing strategy based on document size."""
    if pages <= 10 or words <= 5000:
        return "direct"
    if pages <= 50 or words <= 25000:
        return "sequential"
    if pages <= 450 or words <= 225000:
        return "map-reduce"
    return "two-tier"


# ---------------------------------------------------------------------------
# Subcommand: detect
# ---------------------------------------------------------------------------


def cmd_detect(args: argparse.Namespace) -> None:
    """Detect format, metadata, chapters, and recommended strategy."""
    filepath = Path(args.file).resolve()
    if not filepath.is_file():
        print(json.dumps({"error": f"File not found: {filepath}"}))
        sys.exit(1)

    fmt = detect_format(filepath)

    if fmt == "pdf":
        reader = PdfReader(str(filepath))
        meta = pdf_metadata(reader, filepath)
        chapters = pdf_detect_chapters(reader)
        strategy = recommend_strategy(meta["pages"], meta["estimated_words"])

        result = {
            "file": str(filepath),
            "format": fmt,
            "title": meta["title"],
            "author": meta["author"],
            "pages": meta["pages"],
            "estimated_words": meta["estimated_words"],
            "has_text": meta["has_text"],
            "chapters": chapters,
            "chapter_count": len(chapters),
            "recommended_strategy": strategy,
            "extract_script_available": find_extract_script() is not None,
            "pandoc_available": find_pandoc() is not None,
        }

    elif fmt in ("epub", "docx", "odt", "rtf", "html"):
        text = epub_to_markdown(filepath)
        if text is None:
            print(json.dumps({
                "error": f"pandoc required for {fmt} format but not found. Install: brew install pandoc",
                "file": str(filepath),
                "format": fmt,
            }))
            sys.exit(1)

        words = word_count(text)
        chapters = text_detect_chapters(text)
        # Estimate pages from word count
        est_pages = max(1, words // WORDS_PER_PAGE_ESTIMATE)
        strategy = recommend_strategy(est_pages, words)

        result = {
            "file": str(filepath),
            "format": fmt,
            "title": filepath.stem,
            "author": "Unknown",
            "pages": est_pages,
            "estimated_words": words,
            "has_text": True,
            "chapters": chapters,
            "chapter_count": len(chapters),
            "recommended_strategy": strategy,
            "extract_script_available": find_extract_script() is not None,
            "pandoc_available": True,
        }

    elif fmt in ("txt", "markdown"):
        text = filepath.read_text(encoding="utf-8", errors="replace")
        words = word_count(text)
        chapters = text_detect_chapters(text)
        est_pages = max(1, words // WORDS_PER_PAGE_ESTIMATE)
        strategy = recommend_strategy(est_pages, words)

        result = {
            "file": str(filepath),
            "format": fmt,
            "title": filepath.stem,
            "author": "Unknown",
            "pages": est_pages,
            "estimated_words": words,
            "has_text": True,
            "chapters": chapters,
            "chapter_count": len(chapters),
            "recommended_strategy": strategy,
            "extract_script_available": find_extract_script() is not None,
            "pandoc_available": find_pandoc() is not None,
        }

    else:
        print(json.dumps({
            "error": f"Unsupported format: {fmt} ({filepath.suffix})",
            "file": str(filepath),
            "format": fmt,
        }))
        sys.exit(1)

    print(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Subcommand: chunk
# ---------------------------------------------------------------------------


def split_text_by_chapters(
    text: str, chapters: list[dict], max_words: int
) -> list[dict]:
    """Split text into chunks following chapter boundaries."""
    lines = text.split("\n")
    chunks = []

    if not chapters:
        # No chapters detected — split by word count
        return split_text_by_words(text, max_words)

    for ch in chapters:
        start = ch.get("line_start", 0)
        end = ch.get("line_end", len(lines) - 1)
        chunk_text = "\n".join(lines[start : end + 1])
        chunk_words = word_count(chunk_text)

        if chunk_words > max_words:
            # Oversized chapter — sub-split
            sub_chunks = split_text_by_words(chunk_text, max_words)
            for i, sc in enumerate(sub_chunks):
                sc["label"] = f"{ch['title']} (part {i + 1}/{len(sub_chunks)})"
            chunks.extend(sub_chunks)
        else:
            chunks.append({
                "label": ch["title"],
                "text": chunk_text,
                "word_count": chunk_words,
            })

    return chunks


def split_text_by_words(text: str, max_words: int) -> list[dict]:
    """Split text into fixed-size word-count chunks."""
    words = text.split()
    chunks = []
    idx = 0

    while idx < len(words):
        chunk_words = words[idx : idx + max_words]
        chunk_text = " ".join(chunk_words)
        chunks.append({
            "label": f"Chunk {len(chunks) + 1}",
            "text": chunk_text,
            "word_count": len(chunk_words),
        })
        idx += max_words

    return chunks


def cmd_chunk(args: argparse.Namespace) -> None:
    """Extract text and create chunk manifest."""
    filepath = Path(args.file).resolve()
    if not filepath.is_file():
        print(json.dumps({"error": f"File not found: {filepath}"}))
        sys.exit(1)

    max_words = args.max_words
    max_pages = args.max_pages
    fmt = detect_format(filepath)

    # Create session directory
    session_id = secrets.token_hex(4)
    session_dir = Path(f"/tmp/book_reader_{session_id}")
    session_dir.mkdir(parents=True, exist_ok=True)

    # Detect first
    if fmt == "pdf":
        reader = PdfReader(str(filepath))
        meta = pdf_metadata(reader, filepath)
        chapters = pdf_detect_chapters(reader)
        pages = meta["pages"]
        estimated_words = meta["estimated_words"]
    elif fmt in ("epub", "docx", "odt", "rtf", "html"):
        text = epub_to_markdown(filepath)
        if text is None:
            print(json.dumps({
                "error": f"pandoc required for {fmt} but not found",
                "session_dir": str(session_dir),
            }))
            sys.exit(1)
        estimated_words = word_count(text)
        pages = max(1, estimated_words // WORDS_PER_PAGE_ESTIMATE)
        chapters = text_detect_chapters(text)
        meta = {"title": filepath.stem, "author": "Unknown", "pages": pages, "estimated_words": estimated_words, "has_text": True}
    elif fmt in ("txt", "markdown"):
        text = filepath.read_text(encoding="utf-8", errors="replace")
        estimated_words = word_count(text)
        pages = max(1, estimated_words // WORDS_PER_PAGE_ESTIMATE)
        chapters = text_detect_chapters(text)
        meta = {"title": filepath.stem, "author": "Unknown", "pages": pages, "estimated_words": estimated_words, "has_text": True}
    else:
        print(json.dumps({"error": f"Unsupported format: {fmt}"}))
        sys.exit(1)

    # Determine strategy
    strategy = args.strategy or recommend_strategy(pages, estimated_words)

    # Extract and chunk
    chunk_manifests = []
    extract_script = find_extract_script()

    if fmt == "pdf":
        if chapters and strategy != "direct":
            # Chapter-based chunking for PDFs
            for i, ch in enumerate(chapters):
                start_page = ch["start_page"]
                end_page = ch["end_page"]

                # Sub-split oversized chapters by max_pages
                page_ranges = []
                if end_page - start_page + 1 > max_pages:
                    p = start_page
                    while p <= end_page:
                        range_end = min(p + max_pages - 1, end_page)
                        page_ranges.append((p, range_end))
                        p = range_end + 1
                else:
                    page_ranges.append((start_page, end_page))

                for ri, (ps, pe) in enumerate(page_ranges):
                    chunk_idx = len(chunk_manifests)
                    chunk_file = session_dir / f"chunk_{chunk_idx}.md"

                    success = False
                    if extract_script:
                        success = pdf_extract_pages_docextract(
                            extract_script, filepath, ps, pe, chunk_file
                        )

                    if not success:
                        # Fallback to pypdf (0-indexed)
                        chunk_text = pdf_extract_pages_pypdf(reader, ps - 1, pe - 1)
                        chunk_file.write_text(chunk_text, encoding="utf-8")

                    chunk_text_content = chunk_file.read_text(encoding="utf-8", errors="replace")
                    label = ch["title"]
                    if len(page_ranges) > 1:
                        label = f"{ch['title']} (part {ri + 1}/{len(page_ranges)})"

                    chunk_manifests.append({
                        "id": chunk_idx,
                        "label": label,
                        "file": str(chunk_file),
                        "start_page": ps,
                        "end_page": pe,
                        "word_count": word_count(chunk_text_content),
                    })
        else:
            # No chapters or direct strategy — split by page ranges
            p = 1
            while p <= pages:
                chunk_idx = len(chunk_manifests)
                pe = min(p + max_pages - 1, pages)
                chunk_file = session_dir / f"chunk_{chunk_idx}.md"

                success = False
                if extract_script:
                    success = pdf_extract_pages_docextract(
                        extract_script, filepath, p, pe, chunk_file
                    )

                if not success:
                    chunk_text = pdf_extract_pages_pypdf(reader, p - 1, pe - 1)
                    chunk_file.write_text(chunk_text, encoding="utf-8")

                chunk_text_content = chunk_file.read_text(encoding="utf-8", errors="replace")
                chunk_manifests.append({
                    "id": chunk_idx,
                    "label": f"Pages {p}-{pe}",
                    "file": str(chunk_file),
                    "start_page": p,
                    "end_page": pe,
                    "word_count": word_count(chunk_text_content),
                })
                p = pe + 1

    else:
        # Text-based formats (already have full text)
        if fmt in ("epub", "docx", "odt", "rtf", "html"):
            # text already set from pandoc above
            pass
        # For txt/markdown, text already set

        if chapters and strategy != "direct":
            raw_chunks = split_text_by_chapters(text, chapters, max_words)
        else:
            raw_chunks = split_text_by_words(text, max_words)

        for i, chunk in enumerate(raw_chunks):
            chunk_file = session_dir / f"chunk_{i}.md"
            chunk_file.write_text(chunk["text"], encoding="utf-8")
            chunk_manifests.append({
                "id": i,
                "label": chunk["label"],
                "file": str(chunk_file),
                "word_count": chunk["word_count"],
            })

    # For two-tier strategy, compute tier2 groups
    tier2_groups = None
    if strategy == "two-tier" and len(chunk_manifests) > 5:
        # Balance chunks into 3-5 groups by total word count
        total_words = sum(c["word_count"] for c in chunk_manifests)
        num_groups = min(5, max(3, len(chunk_manifests) // 5))
        target_per_group = total_words / num_groups

        groups = []
        current_group: list[int] = []
        current_words = 0

        for chunk in chunk_manifests:
            current_group.append(chunk["id"])
            current_words += chunk["word_count"]

            if current_words >= target_per_group and len(groups) < num_groups - 1:
                groups.append({
                    "group_id": len(groups),
                    "chunk_ids": current_group[:],
                    "total_words": current_words,
                })
                current_group = []
                current_words = 0

        # Last group gets remaining chunks
        if current_group:
            groups.append({
                "group_id": len(groups),
                "chunk_ids": current_group[:],
                "total_words": current_words,
            })

        tier2_groups = groups

    # Write manifest
    manifest = {
        "session_dir": str(session_dir),
        "file": str(filepath),
        "format": fmt,
        "title": meta.get("title", filepath.stem),
        "author": meta.get("author", "Unknown"),
        "pages": pages,
        "estimated_words": estimated_words,
        "has_text": meta.get("has_text", True),
        "strategy": strategy,
        "chapter_count": len(chapters),
        "chunk_count": len(chunk_manifests),
        "chunks": chunk_manifests,
    }

    if tier2_groups is not None:
        manifest["tier2_groups"] = tier2_groups

    manifest_path = session_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(json.dumps(manifest, indent=2))


# ---------------------------------------------------------------------------
# Subcommand: merge
# ---------------------------------------------------------------------------


def cmd_merge(args: argparse.Namespace) -> None:
    """Merge chunk/group summary JSONs into synthesis input."""
    session_dir = Path(args.session_dir).resolve()
    if not session_dir.is_dir():
        print(json.dumps({"error": f"Session directory not found: {session_dir}"}))
        sys.exit(1)

    # Load manifest
    manifest_path = session_dir / "manifest.json"
    if not manifest_path.is_file():
        print(json.dumps({"error": "manifest.json not found in session directory"}))
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    strategy = manifest.get("strategy", "map-reduce")

    # Collect summary files
    summaries = []
    missing = []
    malformed = []

    if strategy == "two-tier":
        # Look for group_G.json files
        groups = manifest.get("tier2_groups", [])
        for group in groups:
            gid = group["group_id"]
            group_file = session_dir / f"group_{gid}.json"
            if not group_file.is_file():
                missing.append(f"group_{gid}.json")
                continue
            try:
                data = json.loads(group_file.read_text(encoding="utf-8"))
                summaries.append(data)
            except (json.JSONDecodeError, KeyError) as e:
                malformed.append({"file": f"group_{gid}.json", "error": str(e)})
    else:
        # Look for summary_N.json files
        chunk_count = manifest.get("chunk_count", 0)
        for i in range(chunk_count):
            summary_file = session_dir / f"summary_{i}.json"
            if not summary_file.is_file():
                missing.append(f"summary_{i}.json")
                continue
            try:
                data = json.loads(summary_file.read_text(encoding="utf-8"))
                summaries.append(data)
            except (json.JSONDecodeError, KeyError) as e:
                malformed.append({"file": f"summary_{i}.json", "error": str(e)})

    # Deduplicate themes across all summaries
    all_themes = []
    seen_themes: set[str] = set()
    all_quotes = []
    all_arguments = []
    chapter_summaries = []

    for s in summaries:
        # Collect themes
        for theme in s.get("key_themes", []):
            theme_lower = theme.lower().strip()
            if theme_lower not in seen_themes:
                seen_themes.add(theme_lower)
                all_themes.append(theme)

        # Collect quotes
        for quote in s.get("notable_quotes", []):
            all_quotes.append(quote)

        # Collect arguments
        for arg in s.get("key_arguments", []):
            all_arguments.append(arg)

        # Collect summaries
        chapter_summaries.append({
            "id": s.get("id"),
            "label": s.get("label", f"Section {s.get('id', '?')}"),
            "summary": s.get("summary", ""),
            "word_count": s.get("word_count", 0),
        })

    merged = {
        "session_dir": str(session_dir),
        "strategy": strategy,
        "total_summaries": len(summaries),
        "missing_files": missing,
        "malformed_files": malformed,
        "chapter_summaries": chapter_summaries,
        "all_themes": all_themes,
        "all_quotes": all_quotes,
        "all_arguments": all_arguments,
        "manifest": {
            "title": manifest.get("title", "Unknown"),
            "author": manifest.get("author", "Unknown"),
            "format": manifest.get("format", "unknown"),
            "pages": manifest.get("pages", 0),
            "estimated_words": manifest.get("estimated_words", 0),
            "chunk_count": manifest.get("chunk_count", 0),
        },
    }

    merged_path = session_dir / "merged.json"
    merged_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")

    print(json.dumps(merged, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Book reader: detect, chunk, and merge book content",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            subcommands:
              detect   Identify format, metadata, chapters, recommended strategy
              chunk    Extract text and create chunk manifest
              merge    Combine agent summary JSONs into synthesis input
        """),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # detect
    p_detect = subparsers.add_parser("detect", help="Detect book format and metadata")
    p_detect.add_argument("file", help="Path to book file")

    # chunk
    p_chunk = subparsers.add_parser("chunk", help="Extract text and create chunks")
    p_chunk.add_argument("file", help="Path to book file")
    p_chunk.add_argument(
        "--strategy",
        choices=["direct", "sequential", "map-reduce", "two-tier"],
        default=None,
        help="Processing strategy (default: auto-detect)",
    )
    p_chunk.add_argument(
        "--max-words",
        type=int,
        default=DEFAULT_MAX_WORDS,
        help=f"Max words per chunk (default: {DEFAULT_MAX_WORDS})",
    )
    p_chunk.add_argument(
        "--max-pages",
        type=int,
        default=DEFAULT_MAX_PAGES,
        help=f"Max pages per chunk for PDFs (default: {DEFAULT_MAX_PAGES})",
    )

    # merge
    p_merge = subparsers.add_parser("merge", help="Merge agent summaries")
    p_merge.add_argument("session_dir", help="Path to session directory")

    args = parser.parse_args()

    if args.command == "detect":
        cmd_detect(args)
    elif args.command == "chunk":
        cmd_chunk(args)
    elif args.command == "merge":
        cmd_merge(args)


if __name__ == "__main__":
    main()
