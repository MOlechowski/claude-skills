#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "mistune>=3.0.0",
# ]
# ///
"""
Markdown to Confluence Storage Format Converter

Converts Markdown to Confluence XHTML storage format with support for:
- Headings, paragraphs, lists
- Code blocks with syntax highlighting
- Tables
- Links and images
- Info/warning/note panels via :::info, :::warning, :::note blocks
- draw.io diagrams via ![name](file.drawio) syntax

Usage:
    uv run markdown_to_storage.py input.md
    uv run markdown_to_storage.py input.md --output output.xml
    cat input.md | uv run markdown_to_storage.py -

Dependencies are managed automatically via uv (PEP 723).
"""

import sys
import argparse
import re
import html
from typing import Any

import mistune


# Language aliases for Confluence code macro
LANGUAGE_MAP = {
    "python": "python",
    "py": "python",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "javascript",
    "ts": "javascript",
    "java": "java",
    "bash": "bash",
    "sh": "bash",
    "shell": "bash",
    "zsh": "bash",
    "sql": "sql",
    "json": "javascript",
    "xml": "xml",
    "html": "xml",
    "css": "css",
    "yaml": "yaml",
    "yml": "yaml",
    "ruby": "ruby",
    "rb": "ruby",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    "rs": "rust",
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "csharp": "csharp",
    "cs": "csharp",
    "php": "php",
    "scala": "scala",
    "kotlin": "kotlin",
    "swift": "swift",
    "r": "r",
    "perl": "perl",
    "groovy": "groovy",
    "powershell": "powershell",
    "ps1": "powershell",
    "dockerfile": "bash",
    "makefile": "bash",
    "": "none",
}


class ConfluenceRenderer(mistune.HTMLRenderer):
    """Custom renderer for Confluence storage format."""

    def __init__(self):
        super().__init__()
        self.drawio_files = []  # Track draw.io files for upload

    def heading(self, text: str, level: int, **attrs) -> str:
        """Render heading."""
        return f"<h{level}>{text}</h{level}>\n"

    def paragraph(self, text: str) -> str:
        """Render paragraph."""
        return f"<p>{text}</p>\n"

    def list(self, body: str, ordered: bool, **attrs) -> str:
        """Render list."""
        tag = "ol" if ordered else "ul"
        return f"<{tag}>{body}</{tag}>\n"

    def list_item(self, text: str, **attrs) -> str:
        """Render list item."""
        return f"<li>{text}</li>\n"

    def block_code(self, code: str, info: str | None = None, **attrs) -> str:
        """Render code block as Confluence code macro."""
        lang = info.strip() if info else ""
        confluence_lang = LANGUAGE_MAP.get(lang.lower(), lang.lower() or "none")

        # Escape CDATA end sequences
        escaped_code = code.replace("]]>", "]]]]><![CDATA[>")

        return f'''<ac:structured-macro ac:name="code">
<ac:parameter ac:name="language">{confluence_lang}</ac:parameter>
<ac:plain-text-body><![CDATA[{escaped_code}]]></ac:plain-text-body>
</ac:structured-macro>
'''

    def block_quote(self, text: str) -> str:
        """Render blockquote as Confluence quote macro."""
        return f'''<ac:structured-macro ac:name="quote">
<ac:rich-text-body>{text}</ac:rich-text-body>
</ac:structured-macro>
'''

    def codespan(self, text: str) -> str:
        """Render inline code."""
        return f"<code>{html.escape(text)}</code>"

    def emphasis(self, text: str) -> str:
        """Render italic text."""
        return f"<em>{text}</em>"

    def strong(self, text: str) -> str:
        """Render bold text."""
        return f"<strong>{text}</strong>"

    def strikethrough(self, text: str) -> str:
        """Render strikethrough text."""
        return f"<span style=\"text-decoration: line-through;\">{text}</span>"

    def link(self, text: str, url: str, title: str | None = None) -> str:
        """Render link."""
        if url.startswith("#"):
            # Anchor link
            return f'<ac:link ac:anchor="{url[1:]}"><ac:plain-text-link-body><![CDATA[{text}]]></ac:plain-text-link-body></ac:link>'
        else:
            # External link
            return f'<a href="{html.escape(url)}">{text}</a>'

    def image(self, alt: str, url: str, title: str | None = None) -> str:
        """Render image or draw.io diagram."""
        # Check if it's a draw.io file
        if url.endswith(".drawio") or url.endswith(".drawio.xml"):
            self.drawio_files.append(url)
            diagram_name = url.split("/")[-1]  # Get filename
            return f'''<ac:structured-macro ac:name="drawio">
<ac:parameter ac:name="diagramName">{html.escape(diagram_name)}</ac:parameter>
</ac:structured-macro>
'''
        elif url.startswith("http://") or url.startswith("https://"):
            # External image
            return f'<ac:image><ri:url ri:value="{html.escape(url)}" /></ac:image>'
        else:
            # Attached image
            return f'<ac:image><ri:attachment ri:filename="{html.escape(url)}" /></ac:image>'

    def thematic_break(self) -> str:
        """Render horizontal rule."""
        return "<hr />\n"

    def linebreak(self) -> str:
        """Render line break."""
        return "<br />\n"

    def table(self, header: str, body: str) -> str:
        """Render table."""
        return f"<table><tbody>{header}{body}</tbody></table>\n"

    def table_head(self, text: str) -> str:
        """Render table header row."""
        return f"<tr>{text}</tr>\n"

    def table_body(self, text: str) -> str:
        """Render table body."""
        return text

    def table_row(self, text: str) -> str:
        """Render table row."""
        return f"<tr>{text}</tr>\n"

    def table_cell(self, text: str, align: str | None = None, head: bool = False) -> str:
        """Render table cell."""
        tag = "th" if head else "td"
        style = f' style="text-align: {align}"' if align else ""
        return f"<{tag}{style}>{text}</{tag}>"


def extract_admonitions(text: str) -> tuple[str, dict[str, str]]:
    """
    Extract admonition blocks and replace with placeholders.

    Format:
        :::info
        Content here
        :::

    Returns:
        tuple: (text_with_placeholders, dict_of_placeholder_to_xml)
    """
    pattern = r"^:::(info|warning|note|tip)\n(.*?)\n:::[ \t]*$"
    placeholders = {}
    counter = [0]  # Use list to allow mutation in closure

    def replace_with_placeholder(match):
        admon_type = match.group(1)
        content = match.group(2).strip()
        placeholder = f"CONFLUENCEADMONITION{counter[0]}PLACEHOLDER"
        counter[0] += 1

        xml = f'''<ac:structured-macro ac:name="{admon_type}">
<ac:rich-text-body><p>{html.escape(content)}</p></ac:rich-text-body>
</ac:structured-macro>'''
        placeholders[placeholder] = xml
        return placeholder

    processed = re.sub(pattern, replace_with_placeholder, text, flags=re.MULTILINE | re.DOTALL)
    return processed, placeholders


def restore_admonitions(text: str, placeholders: dict[str, str]) -> str:
    """Replace placeholders with actual XML."""
    for placeholder, xml in placeholders.items():
        # The placeholder might be wrapped in <p> tags, remove them
        text = text.replace(f"<p>{placeholder}</p>", xml)
        text = text.replace(placeholder, xml)
    return text


def markdown_to_confluence(markdown_text: str) -> tuple[str, list[str]]:
    """
    Convert Markdown to Confluence storage format.

    Returns:
        tuple: (storage_format_xml, list_of_drawio_files)
    """
    # Extract admonitions and replace with placeholders
    processed, admonition_placeholders = extract_admonitions(markdown_text)

    # Create renderer and parser
    renderer = ConfluenceRenderer()
    md = mistune.create_markdown(
        renderer=renderer,
        plugins=["strikethrough", "table", "url"],
    )

    # Convert Markdown
    storage_format = md(processed)

    # Restore admonitions
    storage_format = restore_admonitions(storage_format, admonition_placeholders)

    return storage_format, renderer.drawio_files


def main():
    parser = argparse.ArgumentParser(
        description="Convert Markdown to Confluence storage format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Convert file
    uv run markdown_to_storage.py README.md

    # Convert file to output file
    uv run markdown_to_storage.py README.md --output page.xml

    # Convert from stdin
    echo "# Hello" | uv run markdown_to_storage.py -

    # Show draw.io files that need upload
    uv run markdown_to_storage.py README.md --list-attachments
        """
    )

    parser.add_argument("input", help="Input Markdown file (use - for stdin)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--list-attachments", action="store_true",
                        help="List draw.io files that need to be uploaded")

    args = parser.parse_args()

    # Read input
    if args.input == "-":
        markdown_text = sys.stdin.read()
    else:
        try:
            with open(args.input, "r", encoding="utf-8") as f:
                markdown_text = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)

    # Convert
    storage_format, drawio_files = markdown_to_confluence(markdown_text)

    # Output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(storage_format)
        print(f"Wrote: {args.output}", file=sys.stderr)
    else:
        print(storage_format)

    # List attachments if requested
    if args.list_attachments and drawio_files:
        print("\nDraw.io files to upload:", file=sys.stderr)
        for f in drawio_files:
            print(f"  - {f}", file=sys.stderr)


if __name__ == "__main__":
    main()
