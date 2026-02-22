#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pytest>=8.0.0",
#     "pypdf>=4.0.0",
# ]
# ///
"""Tests for book.py — split, chunk, and extraction logic."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Import book.py functions directly
sys.path.insert(0, str(Path(__file__).parent))
from book import (
    _match_heading,
    _slugify,
    _split_by_heading,
    _split_by_words,
    chunk_by_word_limit,
    split_by_headings,
    split_by_patterns,
    split_chapters,
    word_count,
)


# ---------------------------------------------------------------------------
# word_count
# ---------------------------------------------------------------------------


class TestWordCount:
    def test_simple_sentence(self):
        assert word_count("hello world foo") == 3, "Expected 3 words in 'hello world foo'"

    def test_empty_string(self):
        assert word_count("") == 0, "Expected 0 words in empty string"

    def test_whitespace_only(self):
        assert word_count("   \n\t  ") == 0, "Expected 0 words in whitespace-only string"

    def test_single_word(self):
        assert word_count("hello") == 1, "Expected 1 word"

    def test_multiline(self):
        text = "line one\nline two\nline three"
        assert word_count(text) == 6, "Expected 6 words across 3 lines"


# ---------------------------------------------------------------------------
# _slugify
# ---------------------------------------------------------------------------


class TestSlugify:
    def test_simple_title(self):
        assert _slugify("Chapter 1: Introduction") == "chapter-1-introduction", (
            "Expected lowercase hyphenated slug"
        )

    def test_special_characters(self):
        assert _slugify("Part III — The End!") == "part-iii-the-end", (
            "Expected special chars stripped"
        )

    def test_long_title_truncated(self):
        long_title = "a" * 200
        result = _slugify(long_title)
        assert len(result) <= 80, f"Expected slug truncated to 80 chars, got {len(result)}"

    def test_empty_string(self):
        assert _slugify("") == "", "Expected empty string for empty input"

    def test_whitespace_normalization(self):
        assert _slugify("hello   world") == "hello-world", (
            "Expected multiple spaces collapsed to single hyphen"
        )

    def test_leading_trailing_hyphens_stripped(self):
        assert _slugify("---hello---") == "hello", (
            "Expected leading/trailing hyphens stripped"
        )


# ---------------------------------------------------------------------------
# _match_heading
# ---------------------------------------------------------------------------


class TestMatchHeading:
    def test_chapter_arabic(self):
        assert _match_heading("Chapter 1") is True, "Expected 'Chapter 1' to match"

    def test_chapter_roman(self):
        assert _match_heading("Chapter IV") is True, "Expected 'Chapter IV' to match"

    def test_chapter_case_insensitive(self):
        assert _match_heading("chapter 3") is True, "Expected lowercase 'chapter 3' to match"

    def test_chapter_uppercase(self):
        assert _match_heading("CHAPTER 5") is True, "Expected uppercase 'CHAPTER 5' to match"

    def test_chapter_with_title(self):
        assert _match_heading("Chapter 1 A Pragmatic Philosophy") is True, (
            "Expected chapter heading with title to match"
        )

    def test_part_arabic(self):
        assert _match_heading("Part 2") is True, "Expected 'Part 2' to match"

    def test_part_roman(self):
        assert _match_heading("Part III") is True, "Expected 'Part III' to match"

    def test_section_arabic(self):
        assert _match_heading("Section 4") is True, "Expected 'Section 4' to match"

    def test_appendix(self):
        assert _match_heading("Appendix A") is True, "Expected 'Appendix A' to match"

    def test_appendix_lowercase(self):
        assert _match_heading("appendix B") is True, "Expected lowercase 'appendix B' to match"

    def test_not_a_heading(self):
        assert _match_heading("This is normal text") is False, (
            "Expected normal text to not match"
        )

    def test_too_long(self):
        long = "Chapter 1 " + "x" * 100
        assert _match_heading(long) is False, "Expected line exceeding max length to not match"

    def test_code_comment_not_matched(self):
        assert _match_heading("# Add a product") is False, (
            "Expected code comment to not match"
        )

    def test_empty_string(self):
        assert _match_heading("") is False, "Expected empty string to not match"


# ---------------------------------------------------------------------------
# split_by_h1
# ---------------------------------------------------------------------------


class TestSplitByHeading:
    def test_h1_two_chapters(self):
        text = "preamble\n\n# Chapter One\n\nContent one.\n\n# Chapter Two\n\nContent two."
        chapters = _split_by_heading(text, r"^(# [^#].*)$")
        assert len(chapters) == 2, f"Expected 2 chapters, got {len(chapters)}"
        assert chapters[0]["title"] == "Chapter One", (
            f"Expected first chapter title 'Chapter One', got '{chapters[0]['title']}'"
        )
        assert chapters[1]["title"] == "Chapter Two", (
            f"Expected second chapter title 'Chapter Two', got '{chapters[1]['title']}'"
        )

    def test_preamble_excluded(self):
        text = "This is preamble text.\n\n# First\n\nBody text."
        chapters = _split_by_heading(text, r"^(# [^#].*)$")
        assert len(chapters) == 1, f"Expected 1 chapter, got {len(chapters)}"
        assert "preamble" not in chapters[0]["text"], "Expected preamble excluded from chapter text"

    def test_no_headings(self):
        text = "Just plain text with no headings at all."
        chapters = _split_by_heading(text, r"^(# [^#].*)$")
        assert chapters == [], f"Expected empty list, got {chapters}"

    def test_content_preserved(self):
        text = "# Title\n\nParagraph one.\n\nParagraph two."
        chapters = _split_by_heading(text, r"^(# [^#].*)$")
        assert len(chapters) == 1, f"Expected 1 chapter, got {len(chapters)}"
        assert "Paragraph one." in chapters[0]["text"], "Expected paragraph one in content"
        assert "Paragraph two." in chapters[0]["text"], "Expected paragraph two in content"

    def test_heading_included_in_text(self):
        text = "# My Chapter\n\nSome content here."
        chapters = _split_by_heading(text, r"^(# [^#].*)$")
        assert chapters[0]["text"].startswith("# My Chapter"), (
            "Expected chapter text to start with H1 heading"
        )

    def test_word_count_included(self):
        text = "# Title\n\nOne two three four five."
        chapters = _split_by_heading(text, r"^(# [^#].*)$")
        assert chapters[0]["words"] > 0, "Expected positive word count"

    def test_h2_not_split_by_h1_pattern(self):
        text = "# Main\n\n## Sub\n\nSub content.\n\n## Sub 2\n\nMore content."
        chapters = _split_by_heading(text, r"^(# [^#].*)$")
        assert len(chapters) == 1, (
            f"Expected 1 chapter (H2 should not split on H1 pattern), got {len(chapters)}"
        )
        assert "Sub content." in chapters[0]["text"], "Expected H2 content within chapter"

    def test_three_chapters_order(self):
        text = "# A\n\nA text.\n\n# B\n\nB text.\n\n# C\n\nC text."
        chapters = _split_by_heading(text, r"^(# [^#].*)$")
        titles = [c["title"] for c in chapters]
        assert titles == ["A", "B", "C"], f"Expected titles in order ['A', 'B', 'C'], got {titles}"

    def test_h2_split(self):
        text = "## Ch A\n\nContent A.\n\n## Ch B\n\nContent B.\n\n## Ch C\n\nContent C."
        chapters = _split_by_heading(text, r"^(## [^#].*)$")
        assert len(chapters) == 3, f"Expected 3 chapters from H2 split, got {len(chapters)}"
        titles = [c["title"] for c in chapters]
        assert titles == ["Ch A", "Ch B", "Ch C"], f"Expected H2 titles, got {titles}"


class TestSplitByHeadings:
    """Tests for the auto-level heading splitter."""

    def test_h1_used_when_enough(self):
        text = "# A\n\nA.\n\n# B\n\nB.\n\n# C\n\nC.\n\n# D\n\nD."
        chapters = split_by_headings(text)
        assert len(chapters) == 4, f"Expected 4 H1 chapters, got {len(chapters)}"
        assert chapters[0]["title"] == "A", f"Expected 'A', got '{chapters[0]['title']}'"

    def test_h2_fallback_when_few_h1(self):
        text = (
            "# Book Title\n\nPreamble.\n\n"
            "## Ch 1\n\nContent 1.\n\n"
            "## Ch 2\n\nContent 2.\n\n"
            "## Ch 3\n\nContent 3.\n\n"
            "## Ch 4\n\nContent 4."
        )
        chapters = split_by_headings(text)
        assert len(chapters) == 4, f"Expected 4 H2 chapters, got {len(chapters)}"
        assert chapters[0]["title"] == "Ch 1", f"Expected 'Ch 1', got '{chapters[0]['title']}'"

    def test_h2_fallback_with_two_h1(self):
        text = (
            "# Title Page\n\nFront matter.\n\n"
            "# Main Title\n\n"
            "## Foreword\n\nForeword text.\n\n"
            "## Chapter 1\n\nCh1 text.\n\n"
            "## Chapter 2\n\nCh2 text.\n\n"
            "## Chapter 3\n\nCh3 text."
        )
        chapters = split_by_headings(text)
        assert len(chapters) == 4, f"Expected 4 H2 chapters (2 H1 is too few), got {len(chapters)}"

    def test_no_headings_returns_empty(self):
        text = "Plain text without any markdown headings."
        chapters = split_by_headings(text)
        assert chapters == [], f"Expected empty list, got {chapters}"

    def test_single_h1_single_h2_returns_h1(self):
        text = "# Only One\n\nContent.\n\n## Sub\n\nSub content."
        chapters = split_by_headings(text)
        # Both H1 and H2 give <3 results, returns H1 (or H2, either is valid)
        assert len(chapters) >= 1, f"Expected at least 1 chapter, got {len(chapters)}"


# ---------------------------------------------------------------------------
# split_by_patterns
# ---------------------------------------------------------------------------


class TestSplitByPatterns:
    def test_chapter_pattern(self):
        text = "Chapter 1 Introduction\n\nContent.\n\nChapter 2 Methods\n\nMore content."
        chapters = split_by_patterns(text)
        assert len(chapters) == 2, f"Expected 2 chapters, got {len(chapters)}"
        assert chapters[0]["title"] == "Chapter 1 Introduction", (
            f"Expected 'Chapter 1 Introduction', got '{chapters[0]['title']}'"
        )
        assert chapters[1]["title"] == "Chapter 2 Methods", (
            f"Expected 'Chapter 2 Methods', got '{chapters[1]['title']}'"
        )

    def test_no_patterns_returns_empty(self):
        text = "Just regular text.\nNothing special here.\nMore text."
        chapters = split_by_patterns(text)
        assert chapters == [], f"Expected empty list, got {chapters}"

    def test_part_pattern(self):
        text = "Part I The Beginning\n\nContent.\n\nPart II The Middle\n\nMore content."
        chapters = split_by_patterns(text)
        assert len(chapters) == 2, f"Expected 2 chapters from part patterns, got {len(chapters)}"

    def test_appendix_pattern(self):
        text = "Chapter 1 Main\n\nContent.\n\nAppendix A Resources\n\nResources content."
        chapters = split_by_patterns(text)
        assert len(chapters) == 2, f"Expected 2 sections (chapter + appendix), got {len(chapters)}"
        assert chapters[1]["title"] == "Appendix A Resources", (
            f"Expected 'Appendix A Resources', got '{chapters[1]['title']}'"
        )

    def test_content_boundaries(self):
        lines = [
            "Chapter 1 First",
            "Content of first chapter.",
            "More first content.",
            "Chapter 2 Second",
            "Content of second chapter.",
        ]
        text = "\n".join(lines)
        chapters = split_by_patterns(text)
        assert "Content of first chapter." in chapters[0]["text"], (
            "Expected first chapter content in first chapter"
        )
        assert "Content of second chapter." in chapters[1]["text"], (
            "Expected second chapter content in second chapter"
        )
        assert "Content of second chapter." not in chapters[0]["text"], (
            "Expected second chapter content NOT in first chapter"
        )


# ---------------------------------------------------------------------------
# split_chapters
# ---------------------------------------------------------------------------


class TestSplitChapters:
    def test_structured_uses_h1(self):
        text = "# First\n\nContent 1.\n\n# Second\n\nContent 2."
        chapters = split_chapters(text, structured=True)
        assert len(chapters) == 2, f"Expected 2 chapters from H1 split, got {len(chapters)}"
        assert chapters[0]["title"] == "First", (
            f"Expected 'First' from H1 split, got '{chapters[0]['title']}'"
        )

    def test_unstructured_uses_patterns(self):
        text = "Chapter 1 Intro\n\nContent.\n\nChapter 2 Methods\n\nMore content."
        chapters = split_chapters(text, structured=False)
        assert len(chapters) == 2, f"Expected 2 chapters from pattern split, got {len(chapters)}"
        assert "Chapter 1" in chapters[0]["title"], (
            f"Expected 'Chapter 1' in title, got '{chapters[0]['title']}'"
        )

    def test_structured_fallback_to_patterns(self):
        # Structured text with no H1 but with Chapter patterns → falls back to patterns
        text = "Chapter 1 Intro\n\nContent.\n\nChapter 2 Methods\n\nMore content."
        chapters = split_chapters(text, structured=True)
        assert len(chapters) == 2, (
            f"Expected 2 chapters from pattern fallback, got {len(chapters)}"
        )

    def test_unstructured_fallback_to_headings(self):
        # Unstructured text with H1 headings but no Chapter patterns → tries headings as last resort
        text = "# A\n\nA.\n\n# B\n\nB.\n\n# C\n\nC."
        chapters = split_chapters(text, structured=False)
        assert len(chapters) == 3, (
            f"Expected 3 chapters from heading fallback, got {len(chapters)}"
        )

    def test_no_splits_found(self):
        text = "Plain text without any chapter markers or headings."
        chapters = split_chapters(text, structured=True)
        assert chapters == [], f"Expected empty list, got {chapters}"

    def test_no_splits_unstructured(self):
        text = "Plain text without any chapter markers or headings."
        chapters = split_chapters(text, structured=False)
        assert chapters == [], f"Expected empty list, got {chapters}"


# ---------------------------------------------------------------------------
# chunk_by_word_limit
# ---------------------------------------------------------------------------


class TestChunkByWordLimit:
    def test_small_chapters_single_chunks(self):
        chapters = [
            {"title": "Ch 1", "text": "word " * 100, "words": 100},
            {"title": "Ch 2", "text": "word " * 200, "words": 200},
        ]
        chunks = chunk_by_word_limit("", chapters, max_words=500)
        assert len(chunks) == 2, f"Expected 2 chunks (1 per chapter), got {len(chunks)}"
        assert chunks[0]["label"] == "Ch 1", f"Expected label 'Ch 1', got '{chunks[0]['label']}'"
        assert chunks[1]["label"] == "Ch 2", f"Expected label 'Ch 2', got '{chunks[1]['label']}'"

    def test_oversized_chapter_split(self):
        chapters = [
            {"title": "Big Chapter", "text": "word " * 300, "words": 300},
        ]
        chunks = chunk_by_word_limit("", chapters, max_words=100)
        assert len(chunks) == 3, f"Expected 3 sub-chunks from 300 words at 100 max, got {len(chunks)}"
        assert "part 1/3" in chunks[0]["label"], (
            f"Expected 'part 1/3' in label, got '{chunks[0]['label']}'"
        )
        assert "part 3/3" in chunks[2]["label"], (
            f"Expected 'part 3/3' in label, got '{chunks[2]['label']}'"
        )

    def test_no_chapters_falls_back_to_word_split(self):
        text = "word " * 250
        chunks = chunk_by_word_limit(text, [], max_words=100)
        assert len(chunks) == 3, f"Expected 3 chunks from 250 words at 100 max, got {len(chunks)}"

    def test_ids_sequential(self):
        chapters = [
            {"title": "A", "text": "word " * 50, "words": 50},
            {"title": "B", "text": "word " * 200, "words": 200},
        ]
        chunks = chunk_by_word_limit("", chapters, max_words=100)
        ids = [c["id"] for c in chunks]
        assert ids == list(range(len(chunks))), (
            f"Expected sequential IDs {list(range(len(chunks)))}, got {ids}"
        )

    def test_word_counts_present(self):
        chapters = [
            {"title": "Ch 1", "text": "hello world", "words": 2},
        ]
        chunks = chunk_by_word_limit("", chapters, max_words=100)
        assert chunks[0]["word_count"] == 2, (
            f"Expected word_count 2, got {chunks[0]['word_count']}"
        )


# ---------------------------------------------------------------------------
# _split_by_words
# ---------------------------------------------------------------------------


class TestSplitByWords:
    def test_exact_division(self):
        text = "word " * 100
        chunks = _split_by_words(text.strip(), 50)
        assert len(chunks) == 2, f"Expected 2 chunks from 100 words at 50 max, got {len(chunks)}"
        assert chunks[0]["word_count"] == 50, (
            f"Expected 50 words in first chunk, got {chunks[0]['word_count']}"
        )

    def test_remainder(self):
        text = "word " * 75
        chunks = _split_by_words(text.strip(), 50)
        assert len(chunks) == 2, f"Expected 2 chunks from 75 words at 50 max, got {len(chunks)}"
        assert chunks[1]["word_count"] == 25, (
            f"Expected 25 words in last chunk, got {chunks[1]['word_count']}"
        )

    def test_single_chunk(self):
        text = "word " * 10
        chunks = _split_by_words(text.strip(), 100)
        assert len(chunks) == 1, f"Expected 1 chunk from 10 words at 100 max, got {len(chunks)}"

    def test_labels_numbered(self):
        text = "word " * 150
        chunks = _split_by_words(text.strip(), 50)
        labels = [c["label"] for c in chunks]
        assert labels == ["Chunk 1", "Chunk 2", "Chunk 3"], (
            f"Expected numbered labels, got {labels}"
        )

    def test_empty_text(self):
        chunks = _split_by_words("", 50)
        assert chunks == [], f"Expected empty list for empty text, got {chunks}"


# ---------------------------------------------------------------------------
# CLI integration (subprocess)
# ---------------------------------------------------------------------------


class TestCLI:
    """Test book.py CLI via subprocess."""

    book_py = str(Path(__file__).parent / "book.py")

    def test_extract_missing_file(self):
        result = subprocess.run(
            ["uv", "run", self.book_py, "extract", "/nonexistent/file.pdf"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1, f"Expected exit code 1, got {result.returncode}"
        output = json.loads(result.stdout)
        assert "error" in output, f"Expected 'error' key in output, got {output}"

    def test_chunk_missing_file(self):
        result = subprocess.run(
            ["uv", "run", self.book_py, "chunk", "/nonexistent/file.pdf"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1, f"Expected exit code 1, got {result.returncode}"
        output = json.loads(result.stdout)
        assert "error" in output, f"Expected 'error' key in output, got {output}"

    def test_merge_missing_dir(self):
        result = subprocess.run(
            ["uv", "run", self.book_py, "merge", "/nonexistent/session"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1, f"Expected exit code 1, got {result.returncode}"
        output = json.loads(result.stdout)
        assert "error" in output, f"Expected 'error' key in output, got {output}"

    def test_extract_txt_file(self, tmp_path):
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("# Chapter A\n\nHello world.\n\n# Chapter B\n\nGoodbye world.")
        result = subprocess.run(
            ["uv", "run", self.book_py, "extract", str(txt_file)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Expected exit code 0, got {result.returncode}. stderr: {result.stderr}"
        assert "Chapter A" in result.stdout, "Expected extracted text to contain 'Chapter A'"

    def test_extract_split_txt(self, tmp_path):
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("# First\n\nContent one.\n\n# Second\n\nContent two.")
        out_dir = tmp_path / "chapters"

        result = subprocess.run(
            ["uv", "run", self.book_py, "extract", str(txt_file), "--split", "--output-dir", str(out_dir)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Expected exit code 0, got {result.returncode}. stderr: {result.stderr}"
        output = json.loads(result.stdout)
        assert output["mode"] == "split-chapters", (
            f"Expected mode 'split-chapters', got '{output['mode']}'"
        )
        assert output["chapters"] == 2, f"Expected 2 chapters, got {output['chapters']}"
        assert out_dir.exists(), "Expected output directory to be created"
        files = list(out_dir.glob("*.md"))
        assert len(files) == 2, f"Expected 2 files in output dir, got {len(files)}"

    def test_extract_output_file(self, tmp_path):
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("Hello world content.")
        out_file = tmp_path / "output.md"

        result = subprocess.run(
            ["uv", "run", self.book_py, "extract", str(txt_file), "--output", str(out_file)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Expected exit code 0, got {result.returncode}. stderr: {result.stderr}"
        output = json.loads(result.stdout)
        assert output["mode"] == "single-file", f"Expected mode 'single-file', got '{output['mode']}'"
        assert out_file.exists(), "Expected output file to be created"
        assert out_file.read_text() == "Hello world content.", (
            "Expected output file content to match input"
        )

    def test_chunk_txt_file(self, tmp_path):
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("# Chapter 1\n\n" + "word " * 100 + "\n\n# Chapter 2\n\n" + "word " * 100)

        result = subprocess.run(
            ["uv", "run", self.book_py, "chunk", str(txt_file)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Expected exit code 0, got {result.returncode}. stderr: {result.stderr}"
        manifest = json.loads(result.stdout)
        assert manifest["chunk_count"] == 2, f"Expected 2 chunks, got {manifest['chunk_count']}"
        assert manifest["engine"] == "native", f"Expected engine 'native', got '{manifest['engine']}'"
        assert manifest["structured"] is True, f"Expected structured=True, got {manifest['structured']}"

        # Verify chunk files exist
        for chunk in manifest["chunks"]:
            assert Path(chunk["file"]).exists(), f"Expected chunk file {chunk['file']} to exist"

        # Clean up session dir
        import shutil
        shutil.rmtree(manifest["session_dir"], ignore_errors=True)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
