#!/usr/bin/env python3
"""
Mermaid Diagram Renderer

Wrapper for mermaid-cli (mmdc) to render Mermaid diagrams to PNG, SVG, or PDF.

Usage:
    # From .mmd file
    python3 render.py diagram.mmd -o output.png

    # From inline code
    python3 render.py --inline "graph LR; A-->B" -o output.png

    # From stdin
    echo "graph LR; A-->B" | python3 render.py --stdin -o output.png

    # Batch mode: extract and render all diagrams from markdown
    python3 render.py README.md --batch -o diagrams/

Prerequisites:
    npm install -g @mermaid-js/mermaid-cli
"""

import argparse
import json
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


def extract_mermaid_blocks(content: str) -> list[tuple[str, int]]:
    """
    Extract mermaid code blocks from markdown content.

    Returns list of (diagram_code, block_index) tuples.
    """
    pattern = r"```mermaid\s*\n(.*?)```"
    matches = re.findall(pattern, content, re.DOTALL)
    return [(m.strip(), i) for i, m in enumerate(matches)]


def create_config(theme: str | None, background: str | None) -> dict:
    """Create mermaid config dictionary."""
    config = {}
    if theme:
        config["theme"] = theme
    if background:
        config["backgroundColor"] = background
    return config


def render_diagram(
    input_content: str,
    output_path: str,
    format: str = "png",
    theme: str | None = None,
    width: int | None = None,
    height: int | None = None,
    background: str | None = None,
    config_file: str | None = None,
) -> bool:
    """
    Render a Mermaid diagram to an image file.

    Args:
        input_content: Mermaid diagram code
        output_path: Output file path
        format: Output format (png, svg, pdf)
        theme: Mermaid theme (default, dark, forest, neutral)
        width: Output width in pixels
        height: Output height in pixels
        background: Background color
        config_file: Path to custom mermaid config JSON

    Returns:
        True if successful, False otherwise
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".mmd", delete=False
    ) as input_file:
        input_file.write(input_content)
        input_path = input_file.name

    try:
        cmd = ["mmdc", "-i", input_path, "-o", output_path]

        # Add format if not png (mmdc infers from extension but explicit is clearer)
        if format != "png":
            cmd.extend(["-e", format])

        # Add dimensions
        if width:
            cmd.extend(["-w", str(width)])
        if height:
            cmd.extend(["-H", str(height)])

        # Handle config: either use provided file or create temp one
        temp_config = None
        if config_file:
            cmd.extend(["-c", config_file])
        elif theme or background:
            config = create_config(theme, background)
            if config:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                ) as cf:
                    json.dump(config, cf)
                    temp_config = cf.name
                cmd.extend(["-c", temp_config])

        # Run mmdc
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Error rendering diagram: {result.stderr}", file=sys.stderr)
            return False

        return True

    finally:
        # Cleanup temp files
        os.unlink(input_path)
        if temp_config:
            os.unlink(temp_config)


def render_batch(
    markdown_path: str,
    output_dir: str,
    format: str = "png",
    theme: str | None = None,
    width: int | None = None,
    height: int | None = None,
    background: str | None = None,
    config_file: str | None = None,
) -> tuple[int, int]:
    """
    Extract and render all mermaid diagrams from a markdown file.

    Args:
        markdown_path: Path to markdown file
        output_dir: Directory to save rendered diagrams
        format: Output format
        theme: Mermaid theme
        width: Output width
        height: Output height
        background: Background color
        config_file: Path to custom config

    Returns:
        Tuple of (success_count, total_count)
    """
    with open(markdown_path, "r") as f:
        content = f.read()

    blocks = extract_mermaid_blocks(content)
    if not blocks:
        print(f"No mermaid diagrams found in {markdown_path}")
        return (0, 0)

    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    base_name = Path(markdown_path).stem
    success_count = 0

    for diagram, index in blocks:
        output_path = os.path.join(output_dir, f"{base_name}_{index + 1}.{format}")
        print(f"Rendering diagram {index + 1}/{len(blocks)} -> {output_path}")

        if render_diagram(
            diagram, output_path, format, theme, width, height, background, config_file
        ):
            success_count += 1

    return (success_count, len(blocks))


def main():
    parser = argparse.ArgumentParser(
        description="Render Mermaid diagrams to images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s diagram.mmd -o output.png
  %(prog)s --inline "graph LR; A-->B" -o output.png
  %(prog)s README.md --batch -o diagrams/
  %(prog)s diagram.mmd -o out.svg --format svg --theme dark
        """,
    )

    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("input", nargs="?", help="Input .mmd or .md file")
    input_group.add_argument("--inline", help="Inline mermaid code")
    input_group.add_argument(
        "--stdin", action="store_true", help="Read mermaid code from stdin"
    )

    # Output
    parser.add_argument("-o", "--output", required=True, help="Output file or directory")
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Batch mode: extract all diagrams from markdown",
    )

    # Rendering options
    parser.add_argument(
        "--format",
        "-f",
        choices=["png", "svg", "pdf"],
        default="png",
        help="Output format (default: png)",
    )
    parser.add_argument(
        "--theme",
        "-t",
        choices=["default", "dark", "forest", "neutral"],
        help="Mermaid theme",
    )
    parser.add_argument("--width", "-w", type=int, help="Output width in pixels")
    parser.add_argument("--height", "-H", type=int, help="Output height in pixels")
    parser.add_argument(
        "--background", "-b", help='Background color (e.g., "#ffffff" or "transparent")'
    )
    parser.add_argument("--config", "-c", help="Path to custom mermaid config JSON")

    args = parser.parse_args()

    # Check prerequisites
    check_mmdc()

    # Determine input content
    if args.stdin:
        content = sys.stdin.read()
    elif args.inline:
        content = args.inline
    elif args.input:
        if not os.path.exists(args.input):
            print(f"Error: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)

        if args.batch:
            # Batch mode for markdown files
            success, total = render_batch(
                args.input,
                args.output,
                args.format,
                args.theme,
                args.width,
                args.height,
                args.background,
                args.config,
            )
            print(f"Rendered {success}/{total} diagrams")
            sys.exit(0 if success == total else 1)
        else:
            with open(args.input, "r") as f:
                content = f.read()

            # If it's a markdown file, try to extract first mermaid block
            if args.input.endswith(".md"):
                blocks = extract_mermaid_blocks(content)
                if blocks:
                    content = blocks[0][0]
                    if len(blocks) > 1:
                        print(
                            f"Note: Found {len(blocks)} diagrams, rendering first one. "
                            "Use --batch for all.",
                            file=sys.stderr,
                        )
                else:
                    print(
                        f"Error: No mermaid diagrams found in {args.input}",
                        file=sys.stderr,
                    )
                    sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    # Render single diagram
    if render_diagram(
        content,
        args.output,
        args.format,
        args.theme,
        args.width,
        args.height,
        args.background,
        args.config,
    ):
        print(f"Rendered: {args.output}")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
