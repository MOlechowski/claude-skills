#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pypdf>=4.0.0",
# ]
# ///
"""
Book reader: extract and split books into markdown.

Uses doc-extract for structured extraction (heading hierarchy preserved),
falls back to pypdf + pattern matching when doc-extract is unavailable.

Usage:
    uv run book.py extract <file> --output book.md
    uv run book.py extract <file> --split --output-dir ./chapters/
    uv run book.py chunk <file> [--max-words N]
"""

import argparse
import json
import re
import secrets
import subprocess
import sys
import textwrap
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_WORDS = 15000

HEADING_MAX_LEN = 80
NUMBERED_HEADING_MAX_LEN = 60

# Explicit chapter/part/section patterns — high confidence
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
    re.compile(r"^appendix\s+[A-Z]", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def word_count(text: str) -> int:
    """Count words in text."""
    return len(text.split())


def _slugify(text: str) -> str:
    """Convert a chapter title to a filename-safe slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")[:80]


def _match_heading(line: str) -> bool:
    """Check if a line matches any chapter heading pattern."""
    if len(line) <= HEADING_MAX_LEN:
        for pattern in CHAPTER_PATTERNS:
            if pattern.match(line):
                return True
    return False


def find_extract_script() -> Path | None:
    """Locate doc-extract's extract.py relative to this script."""
    this_dir = Path(__file__).resolve().parent
    candidates = [
        this_dir / ".." / ".." / ".." / ".." / "doc-extract" / "skills" / "doc-extract" / "scripts" / "extract.py",
        Path.home() / ".claude" / "skills" / "doc-extract" / "scripts" / "extract.py",
    ]
    for c in candidates:
        resolved = c.resolve()
        if resolved.is_file():
            return resolved
    return None


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract_via_doc_extract(filepath: Path) -> tuple[str, str]:
    """Extract markdown from a file using doc-extract.

    Returns (markdown_text, engine_name).
    Raises RuntimeError if doc-extract is not available or fails.
    """
    extract_script = find_extract_script()
    if not extract_script:
        raise RuntimeError("doc-extract not found")

    result = subprocess.run(
        ["uv", "run", str(extract_script), "extract", str(filepath), "--format", "json"],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(f"doc-extract failed: {result.stderr}")

    data = json.loads(result.stdout)
    return data.get("content", ""), data.get("engine", "unknown")


def extract_via_pypdf(filepath: Path) -> str:
    """Extract flat text from a PDF using pypdf (no heading hierarchy)."""
    from pypdf import PdfReader

    reader = PdfReader(str(filepath))
    parts = []
    for page in reader.pages:
        text = page.extract_text() or ""
        if text.strip():
            parts.append(text)
    return "\n\n".join(parts)


def extract_text(filepath: Path) -> tuple[str, str, bool]:
    """Extract text from any supported file.

    Returns (text, engine, structured) where structured=True means
    the output has reliable heading hierarchy.
    """
    try:
        text, engine = extract_via_doc_extract(filepath)
        structured = engine != "pypdf"
        return text, engine, structured
    except (RuntimeError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: pypdf for PDFs, raw read for text files
    ext = filepath.suffix.lower()
    if ext == ".pdf":
        return extract_via_pypdf(filepath), "pypdf", False
    elif ext in (".txt", ".md", ".markdown"):
        text = filepath.read_text(encoding="utf-8", errors="replace")
        return text, "native", True
    else:
        raise RuntimeError(f"Unsupported format: {ext}. Install doc-extract for EPUB/DOCX support.")


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


def split_by_h1(text: str) -> list[dict]:
    """Split markdown text on H1 headings.

    Returns list of {"title": str, "text": str, "words": int}.
    """
    parts = re.split(r"^(# .+)$", text, flags=re.MULTILINE)
    # parts = [preamble, "# Title1", content1, "# Title2", content2, ...]
    chapters = []
    i = 1
    while i < len(parts) - 1:
        title = parts[i].lstrip("# ").strip()
        content = parts[i] + parts[i + 1]
        chapters.append({
            "title": title,
            "text": content.strip(),
            "words": word_count(content),
        })
        i += 2
    return chapters


def split_by_patterns(text: str) -> list[dict]:
    """Split text on Chapter/Part/Section/Appendix pattern matches.

    Fallback for flat text without heading hierarchy (pypdf output).
    Returns list of {"title": str, "text": str, "words": int}.
    """
    lines = text.split("\n")
    boundaries = []

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and _match_heading(stripped):
            boundaries.append({"title": stripped[:120], "line": i})

    if not boundaries:
        return []

    chapters = []
    for idx, b in enumerate(boundaries):
        start = b["line"]
        end = boundaries[idx + 1]["line"] if idx + 1 < len(boundaries) else len(lines)
        chunk = "\n".join(lines[start:end])
        chapters.append({
            "title": b["title"],
            "text": chunk.strip(),
            "words": word_count(chunk),
        })
    return chapters


def split_chapters(text: str, structured: bool) -> list[dict]:
    """Split text into chapters using the best available method.

    If structured=True (doc-extract with heading-aware engine), split on H1.
    If structured=False (pypdf flat text), split on Chapter/Part patterns.
    """
    if structured:
        chapters = split_by_h1(text)
        if chapters:
            return chapters

    # Fallback to pattern matching
    chapters = split_by_patterns(text)
    if chapters:
        return chapters

    # Last resort: try H1 split even on unstructured text
    if not structured:
        chapters = split_by_h1(text)
        if chapters:
            return chapters

    return []


def chunk_by_word_limit(text: str, chapters: list[dict], max_words: int) -> list[dict]:
    """Split text into chunks respecting chapter boundaries and word limits.

    Returns list of {"id": int, "label": str, "text": str, "word_count": int}.
    """
    if not chapters:
        # No chapters — split by word count
        return _split_by_words(text, max_words)

    chunks = []
    for ch in chapters:
        if ch["words"] <= max_words:
            chunks.append({
                "id": len(chunks),
                "label": ch["title"],
                "text": ch["text"],
                "word_count": ch["words"],
            })
        else:
            # Oversized chapter — sub-split
            sub = _split_by_words(ch["text"], max_words)
            for i, s in enumerate(sub):
                s["label"] = f"{ch['title']} (part {i + 1}/{len(sub)})"
                s["id"] = len(chunks)
                chunks.append(s)
    return chunks


def _split_by_words(text: str, max_words: int) -> list[dict]:
    """Split text into fixed-size word-count chunks."""
    words = text.split()
    chunks = []
    idx = 0
    while idx < len(words):
        chunk_words = words[idx : idx + max_words]
        chunks.append({
            "id": len(chunks),
            "label": f"Chunk {len(chunks) + 1}",
            "text": " ".join(chunk_words),
            "word_count": len(chunk_words),
        })
        idx += max_words
    return chunks


# ---------------------------------------------------------------------------
# Subcommand: extract
# ---------------------------------------------------------------------------


def cmd_extract(args: argparse.Namespace) -> None:
    """Extract book text to markdown file(s)."""
    filepath = Path(args.file).resolve()
    if not filepath.is_file():
        print(json.dumps({"error": f"File not found: {filepath}"}))
        sys.exit(1)

    text, engine, structured = extract_text(filepath)

    if args.split:
        chapters = split_chapters(text, structured)

        if not chapters:
            print(json.dumps({
                "error": "No chapters detected. Use without --split for single file output.",
                "engine": engine,
                "structured": structured,
            }))
            sys.exit(1)

        output_dir = Path(args.output_dir) if args.output_dir else Path.cwd()
        output_dir.mkdir(parents=True, exist_ok=True)

        files_written = []
        for i, ch in enumerate(chapters):
            slug = _slugify(ch["title"]) or f"chapter-{i + 1}"
            filename = f"{i + 1:02d}-{slug}.md"
            out_path = output_dir / filename

            content = f"# {ch['title']}\n\n{ch['text']}" if not ch["text"].startswith("# ") else ch["text"]
            out_path.write_text(content, encoding="utf-8")
            files_written.append({
                "file": str(out_path),
                "title": ch["title"],
                "words": ch["words"],
            })

        result = {
            "mode": "split-chapters",
            "output_dir": str(output_dir),
            "chapters": len(files_written),
            "total_words": sum(f["words"] for f in files_written),
            "engine": engine,
            "structured": structured,
            "files": files_written,
        }
        print(json.dumps(result, indent=2))

    else:
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
            return

        result = {
            "mode": "single-file",
            "output": str(out_path),
            "words": word_count(text),
            "engine": engine,
            "structured": structured,
        }
        print(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Subcommand: chunk
# ---------------------------------------------------------------------------


def cmd_chunk(args: argparse.Namespace) -> None:
    """Extract text and create chunk manifest for agent summarization."""
    filepath = Path(args.file).resolve()
    if not filepath.is_file():
        print(json.dumps({"error": f"File not found: {filepath}"}))
        sys.exit(1)

    max_words = args.max_words
    text, engine, structured = extract_text(filepath)
    chapters = split_chapters(text, structured)

    session_id = secrets.token_hex(4)
    session_dir = Path(f"/tmp/book_reader_{session_id}")
    session_dir.mkdir(parents=True, exist_ok=True)

    chunks = chunk_by_word_limit(text, chapters, max_words)

    chunk_manifests = []
    for chunk in chunks:
        chunk_file = session_dir / f"chunk_{chunk['id']}.md"
        chunk_file.write_text(chunk["text"], encoding="utf-8")
        chunk_manifests.append({
            "id": chunk["id"],
            "label": chunk["label"],
            "file": str(chunk_file),
            "word_count": chunk["word_count"],
        })

    manifest = {
        "session_dir": str(session_dir),
        "file": str(filepath),
        "engine": engine,
        "structured": structured,
        "estimated_words": word_count(text),
        "chapter_count": len(chapters),
        "chunk_count": len(chunk_manifests),
        "chunks": chunk_manifests,
    }

    manifest_path = session_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(json.dumps(manifest, indent=2))


# ---------------------------------------------------------------------------
# Subcommand: merge
# ---------------------------------------------------------------------------


def cmd_merge(args: argparse.Namespace) -> None:
    """Merge chunk summary JSONs into synthesis input."""
    session_dir = Path(args.session_dir).resolve()
    if not session_dir.is_dir():
        print(json.dumps({"error": f"Session directory not found: {session_dir}"}))
        sys.exit(1)

    manifest_path = session_dir / "manifest.json"
    if not manifest_path.is_file():
        print(json.dumps({"error": "manifest.json not found in session directory"}))
        sys.exit(1)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    summaries = []
    missing = []
    chunk_count = manifest.get("chunk_count", 0)
    for i in range(chunk_count):
        summary_file = session_dir / f"summary_{i}.json"
        if not summary_file.is_file():
            missing.append(f"summary_{i}.json")
            continue
        try:
            summaries.append(json.loads(summary_file.read_text(encoding="utf-8")))
        except json.JSONDecodeError as e:
            missing.append(f"summary_{i}.json (malformed: {e})")

    all_themes: list[str] = []
    seen_themes: set[str] = set()
    all_quotes: list[dict] = []
    all_arguments: list[str] = []
    chapter_summaries: list[dict] = []

    for s in summaries:
        for theme in s.get("key_themes", []):
            if theme.lower().strip() not in seen_themes:
                seen_themes.add(theme.lower().strip())
                all_themes.append(theme)
        all_quotes.extend(s.get("notable_quotes", []))
        all_arguments.extend(s.get("key_arguments", []))
        chapter_summaries.append({
            "id": s.get("id"),
            "label": s.get("label", f"Section {s.get('id', '?')}"),
            "summary": s.get("summary", ""),
        })

    merged = {
        "session_dir": str(session_dir),
        "total_summaries": len(summaries),
        "missing_files": missing,
        "chapter_summaries": chapter_summaries,
        "all_themes": all_themes,
        "all_quotes": all_quotes,
        "all_arguments": all_arguments,
        "manifest": manifest,
    }

    merged_path = session_dir / "merged.json"
    merged_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    print(json.dumps(merged, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Book reader: extract, split, and chunk books",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            subcommands:
              extract   Extract book text to markdown (single file or split by chapter)
              chunk     Create chunks for agent summarization
              merge     Combine agent summary JSONs into synthesis input
        """),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_extract = subparsers.add_parser("extract", help="Extract book text to markdown")
    p_extract.add_argument("file", help="Path to book file")
    p_extract.add_argument("--output", "-o", default=None, help="Output file path (default: stdout)")
    p_extract.add_argument("--split", action="store_true", default=False, help="Split into one file per chapter")
    p_extract.add_argument("--output-dir", default=None, help="Output directory for --split")

    p_chunk = subparsers.add_parser("chunk", help="Create chunks for agent summarization")
    p_chunk.add_argument("file", help="Path to book file")
    p_chunk.add_argument("--max-words", type=int, default=DEFAULT_MAX_WORDS, help=f"Max words per chunk (default: {DEFAULT_MAX_WORDS})")

    p_merge = subparsers.add_parser("merge", help="Merge agent summaries")
    p_merge.add_argument("session_dir", help="Path to session directory")

    args = parser.parse_args()

    if args.command == "extract":
        cmd_extract(args)
    elif args.command == "chunk":
        cmd_chunk(args)
    elif args.command == "merge":
        cmd_merge(args)


if __name__ == "__main__":
    main()
