#!/usr/bin/env python3
"""
Mermaid Diagram Validator

Validate Mermaid syntax without rendering to an image file.
Uses mermaid-cli's parsing to check for syntax errors.

Usage:
    # Validate .mmd file
    python3 validate.py diagram.mmd

    # Validate inline code
    python3 validate.py --inline "graph LR; A-->B"

    # Validate all diagrams in markdown
    python3 validate.py README.md

Exit codes:
    0 = valid syntax
    1 = syntax errors (error messages printed to stderr)

Prerequisites:
    npm install -g @mermaid-js/mermaid-cli
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def check_mmdc():
    """Check if mermaid-cli (mmdc) is installed."""
    if shutil.which("mmdc") is None:
        print("Error: mermaid-cli (mmdc) not found.", file=sys.stderr)
        print("Install with: npm install -g @mermaid-js/mermaid-cli", file=sys.stderr)
        sys.exit(1)


def extract_mermaid_blocks(content: str) -> list[tuple[str, int, int]]:
    """
    Extract mermaid code blocks from markdown content.

    Returns list of (diagram_code, block_index, line_number) tuples.
    """
    results = []
    pattern = r"```mermaid\s*\n(.*?)```"

    for i, match in enumerate(re.finditer(pattern, content, re.DOTALL)):
        # Calculate line number of the block start
        line_num = content[: match.start()].count("\n") + 1
        results.append((match.group(1).strip(), i, line_num))

    return results


def validate_diagram(content: str, source_info: str = "") -> tuple[bool, str]:
    """
    Validate Mermaid diagram syntax.

    Uses mmdc to parse the diagram without producing output.
    Returns (is_valid, error_message) tuple.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".mmd", delete=False
    ) as input_file:
        input_file.write(content)
        input_path = input_file.name

    with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as output_file:
        output_path = output_file.name

    try:
        # Run mmdc - it will fail if syntax is invalid
        result = subprocess.run(
            ["mmdc", "-i", input_path, "-o", output_path],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            # Extract useful error info from stderr
            error_msg = result.stderr.strip()
            # Try to parse the error for cleaner output
            if "Error:" in error_msg:
                error_msg = error_msg.split("Error:")[-1].strip()
            elif "error" in error_msg.lower():
                pass  # Keep full message
            else:
                error_msg = result.stderr.strip() or "Unknown parsing error"

            return (False, error_msg)

        return (True, "")

    finally:
        # Cleanup temp files
        os.unlink(input_path)
        if os.path.exists(output_path):
            os.unlink(output_path)


def validate_file(path: str) -> tuple[int, int]:
    """
    Validate a .mmd or .md file.

    For .mmd files, validates the entire file as a single diagram.
    For .md files, extracts and validates all mermaid blocks.

    Returns (valid_count, total_count) tuple.
    """
    with open(path, "r") as f:
        content = f.read()

    if path.endswith(".md"):
        # Markdown file - extract and validate all blocks
        blocks = extract_mermaid_blocks(content)
        if not blocks:
            print(f"No mermaid diagrams found in {path}")
            return (0, 0)

        valid_count = 0
        for diagram, index, line_num in blocks:
            is_valid, error = validate_diagram(diagram, f"block {index + 1}")
            if is_valid:
                print(f"[VALID] Block {index + 1} (line {line_num})")
                valid_count += 1
            else:
                print(f"[ERROR] Block {index + 1} (line {line_num}): {error}")

        return (valid_count, len(blocks))
    else:
        # .mmd file or other - validate entire content
        is_valid, error = validate_diagram(content)
        if is_valid:
            print(f"[VALID] {path}")
            return (1, 1)
        else:
            print(f"[ERROR] {path}: {error}")
            return (0, 1)


def main():
    parser = argparse.ArgumentParser(
        description="Validate Mermaid diagram syntax",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s diagram.mmd           # Validate a .mmd file
  %(prog)s --inline "graph LR; A-->B"  # Validate inline code
  %(prog)s README.md             # Validate all diagrams in markdown

Exit codes:
  0 = all diagrams valid
  1 = one or more syntax errors
        """,
    )

    # Input sources
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "input", nargs="?", help="Input .mmd or .md file to validate"
    )
    input_group.add_argument("--inline", help="Inline mermaid code to validate")

    # Options
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet mode - only show errors"
    )

    args = parser.parse_args()

    # Check prerequisites
    check_mmdc()

    if args.inline:
        # Validate inline code
        is_valid, error = validate_diagram(args.inline)
        if is_valid:
            if not args.quiet:
                print("[VALID] Inline diagram")
            sys.exit(0)
        else:
            print(f"[ERROR] {error}")
            sys.exit(1)

    elif args.input:
        if not os.path.exists(args.input):
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)

        valid, total = validate_file(args.input)

        if total == 0:
            sys.exit(1)  # No diagrams found

        if not args.quiet:
            print(f"\nValidation: {valid}/{total} diagrams valid")

        sys.exit(0 if valid == total else 1)


if __name__ == "__main__":
    main()
