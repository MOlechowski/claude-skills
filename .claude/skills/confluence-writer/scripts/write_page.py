#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "httpx>=0.25.0",
#     "mistune>=3.0.0",
# ]
# ///
"""
Confluence Page Writer

Creates or updates Confluence pages from Markdown or storage format content.
Automatically converts Markdown to Confluence storage format.

Usage:
    # Create new page in space
    uv run write_page.py --space DEV --title "API Docs" --file README.md

    # Create child page
    uv run write_page.py --space DEV --title "Auth" --parent 12345 --file auth.md

    # Update existing page
    uv run write_page.py --page-id 67890 --file updated.md

    # Create from stdin
    echo "# Hello" | uv run write_page.py --space DEV --title "Test" -

Dependencies are managed automatically via uv (PEP 723).
"""

import subprocess
import sys
import os
import argparse
import json
from pathlib import Path

import httpx

# Import the markdown converter
# We'll inline the core conversion logic to keep the script self-contained
import re
import html
import mistune


KEYCHAIN_PATH = os.path.expanduser("~/Library/Keychains/claude-keys.keychain-db")


# Language aliases for Confluence code macro
LANGUAGE_MAP = {
    "python": "python", "py": "python",
    "javascript": "javascript", "js": "javascript", "typescript": "javascript", "ts": "javascript",
    "java": "java", "bash": "bash", "sh": "bash", "shell": "bash", "zsh": "bash",
    "sql": "sql", "json": "javascript", "xml": "xml", "html": "xml", "css": "css",
    "yaml": "yaml", "yml": "yaml", "ruby": "ruby", "rb": "ruby",
    "go": "go", "golang": "go", "rust": "rust", "rs": "rust",
    "c": "c", "cpp": "cpp", "c++": "cpp", "csharp": "csharp", "cs": "csharp",
    "php": "php", "scala": "scala", "kotlin": "kotlin", "swift": "swift",
    "r": "r", "perl": "perl", "groovy": "groovy",
    "powershell": "powershell", "ps1": "powershell",
    "dockerfile": "bash", "makefile": "bash", "": "none",
}


class ConfluenceRenderer(mistune.HTMLRenderer):
    """Custom renderer for Confluence storage format."""

    def __init__(self):
        super().__init__()
        self.drawio_files = []

    def heading(self, text: str, level: int, **attrs) -> str:
        return f"<h{level}>{text}</h{level}>\n"

    def paragraph(self, text: str) -> str:
        return f"<p>{text}</p>\n"

    def list(self, body: str, ordered: bool, **attrs) -> str:
        tag = "ol" if ordered else "ul"
        return f"<{tag}>{body}</{tag}>\n"

    def list_item(self, text: str, **attrs) -> str:
        return f"<li>{text}</li>\n"

    def block_code(self, code: str, info: str | None = None, **attrs) -> str:
        lang = info.strip() if info else ""
        confluence_lang = LANGUAGE_MAP.get(lang.lower(), lang.lower() or "none")
        escaped_code = code.replace("]]>", "]]]]><![CDATA[>")
        return f'''<ac:structured-macro ac:name="code">
<ac:parameter ac:name="language">{confluence_lang}</ac:parameter>
<ac:plain-text-body><![CDATA[{escaped_code}]]></ac:plain-text-body>
</ac:structured-macro>
'''

    def block_quote(self, text: str) -> str:
        return f'''<ac:structured-macro ac:name="quote">
<ac:rich-text-body>{text}</ac:rich-text-body>
</ac:structured-macro>
'''

    def codespan(self, text: str) -> str:
        return f"<code>{html.escape(text)}</code>"

    def emphasis(self, text: str) -> str:
        return f"<em>{text}</em>"

    def strong(self, text: str) -> str:
        return f"<strong>{text}</strong>"

    def link(self, text: str, url: str, title: str | None = None) -> str:
        if url.startswith("#"):
            return f'<ac:link ac:anchor="{url[1:]}"><ac:plain-text-link-body><![CDATA[{text}]]></ac:plain-text-link-body></ac:link>'
        return f'<a href="{html.escape(url)}">{text}</a>'

    def image(self, alt: str, url: str, title: str | None = None) -> str:
        if url.endswith(".drawio") or url.endswith(".drawio.xml"):
            self.drawio_files.append(url)
            diagram_name = url.split("/")[-1]
            return f'''<ac:structured-macro ac:name="drawio">
<ac:parameter ac:name="diagramName">{html.escape(diagram_name)}</ac:parameter>
</ac:structured-macro>
'''
        elif url.startswith("http://") or url.startswith("https://"):
            return f'<ac:image><ri:url ri:value="{html.escape(url)}" /></ac:image>'
        return f'<ac:image><ri:attachment ri:filename="{html.escape(url)}" /></ac:image>'

    def thematic_break(self) -> str:
        return "<hr />\n"

    def table(self, header: str, body: str) -> str:
        return f"<table><tbody>{header}{body}</tbody></table>\n"

    def table_head(self, text: str) -> str:
        return f"<tr>{text}</tr>\n"

    def table_body(self, text: str) -> str:
        return text

    def table_row(self, text: str) -> str:
        return f"<tr>{text}</tr>\n"

    def table_cell(self, text: str, align: str | None = None, head: bool = False) -> str:
        tag = "th" if head else "td"
        style = f' style="text-align: {align}"' if align else ""
        return f"<{tag}{style}>{text}</{tag}>"


def extract_admonitions(text: str) -> tuple[str, dict[str, str]]:
    """Extract admonition blocks and replace with placeholders."""
    pattern = r"^:::(info|warning|note|tip)\n(.*?)\n:::[ \t]*$"
    placeholders = {}
    counter = [0]

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
        text = text.replace(f"<p>{placeholder}</p>", xml)
        text = text.replace(placeholder, xml)
    return text


def markdown_to_confluence(markdown_text: str) -> tuple[str, list[str]]:
    """Convert Markdown to Confluence storage format."""
    processed, admonition_placeholders = extract_admonitions(markdown_text)
    renderer = ConfluenceRenderer()
    md = mistune.create_markdown(renderer=renderer, plugins=["strikethrough", "table", "url"])
    storage_format = md(processed)
    storage_format = restore_admonitions(storage_format, admonition_placeholders)
    return storage_format, renderer.drawio_files


def get_credential(service: str) -> str | None:
    """Retrieve a credential from the keychain."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-w", KEYCHAIN_PATH],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if "could not be found" in e.stderr:
            return None
        elif "User interaction is not allowed" in e.stderr:
            print("Error: Keychain is locked.", file=sys.stderr)
            print("Unlock with: security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db", file=sys.stderr)
            sys.exit(1)
        print(f"Error accessing keychain: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def get_confluence_credentials() -> tuple[str, str]:
    """Get Confluence URL and token from keychain."""
    url = get_credential("confluence-url")
    token = get_credential("confluence-token")

    if not url or not token:
        print("Error: Confluence credentials not found.", file=sys.stderr)
        print("\nSetup credentials with:", file=sys.stderr)
        print("  uv run setup_credentials.py --url https://confluence.company.com --token YOUR_TOKEN", file=sys.stderr)
        sys.exit(1)

    return url, token


def get_page(base_url: str, token: str, page_id: str) -> dict | None:
    """Get page details including current version."""
    url = f"{base_url}/rest/api/content/{page_id}?expand=version,space"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    with httpx.Client(timeout=30) as client:
        response = client.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return None
        else:
            print(f"Error getting page: {response.status_code} - {response.text}", file=sys.stderr)
            sys.exit(1)


def create_page(
    base_url: str,
    token: str,
    space_key: str,
    title: str,
    content: str,
    parent_id: str | None = None,
) -> dict:
    """Create a new Confluence page."""
    url = f"{base_url}/rest/api/content"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    payload = {
        "type": "page",
        "title": title,
        "space": {"key": space_key},
        "body": {
            "storage": {
                "value": content,
                "representation": "storage"
            }
        }
    }

    if parent_id:
        payload["ancestors"] = [{"id": parent_id}]

    with httpx.Client(timeout=60) as client:
        response = client.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 400:
            error = response.json()
            msg = error.get("message", response.text)
            print(f"Error creating page: {msg}", file=sys.stderr)
            sys.exit(1)
        elif response.status_code == 403:
            print("Error: Permission denied. Check your token has write access to the space.", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Error: {response.status_code} - {response.text}", file=sys.stderr)
            sys.exit(1)


def update_page(
    base_url: str,
    token: str,
    page_id: str,
    title: str,
    content: str,
    current_version: int,
) -> dict:
    """Update an existing Confluence page."""
    url = f"{base_url}/rest/api/content/{page_id}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    payload = {
        "type": "page",
        "title": title,
        "version": {"number": current_version + 1},
        "body": {
            "storage": {
                "value": content,
                "representation": "storage"
            }
        }
    }

    with httpx.Client(timeout=60) as client:
        response = client.put(url, headers=headers, json=payload)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 409:
            print("Error: Version conflict. Page was modified by someone else.", file=sys.stderr)
            sys.exit(1)
        elif response.status_code == 403:
            print("Error: Permission denied.", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Error: {response.status_code} - {response.text}", file=sys.stderr)
            sys.exit(1)


def is_storage_format(content: str) -> bool:
    """Check if content appears to be Confluence storage format (XML)."""
    content = content.strip()
    return content.startswith("<") and ("ac:structured-macro" in content or "<p>" in content or "<h" in content)


def main():
    parser = argparse.ArgumentParser(
        description="Create or update Confluence pages from Markdown",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Create new page in space
    uv run write_page.py --space DEV --title "API Docs" --file README.md

    # Create child page
    uv run write_page.py --space DEV --title "Auth" --parent 12345 --file auth.md

    # Update existing page
    uv run write_page.py --page-id 67890 --file updated.md

    # Create from stdin
    echo "# Hello" | uv run write_page.py --space DEV --title "Test" -

    # Use raw storage format (no conversion)
    uv run write_page.py --space DEV --title "Test" --file page.xml --raw
        """
    )

    # Input source
    parser.add_argument("input", nargs="?", help="Input file (use - for stdin)")
    parser.add_argument("--file", "-f", help="Input file (alternative to positional)")

    # Create mode
    parser.add_argument("--space", "-s", help="Space key for new page")
    parser.add_argument("--title", "-t", help="Page title")
    parser.add_argument("--parent", "-p", help="Parent page ID for child page")

    # Update mode
    parser.add_argument("--page-id", help="Existing page ID to update")

    # Options
    parser.add_argument("--raw", action="store_true",
                        help="Treat input as raw storage format (skip Markdown conversion)")

    args = parser.parse_args()

    # Determine input source
    input_file = args.input or args.file
    if not input_file:
        parser.print_help()
        print("\nError: Specify input file or use - for stdin.", file=sys.stderr)
        sys.exit(1)

    # Read input
    if input_file == "-":
        content = sys.stdin.read()
    else:
        input_path = Path(input_file)
        if not input_path.exists():
            print(f"Error: File not found: {input_file}", file=sys.stderr)
            sys.exit(1)
        content = input_path.read_text(encoding="utf-8")

    # Get credentials
    base_url, token = get_confluence_credentials()

    # Convert content if needed
    drawio_files = []
    if args.raw or is_storage_format(content):
        storage_content = content
        print("Using raw storage format", file=sys.stderr)
    else:
        storage_content, drawio_files = markdown_to_confluence(content)
        print("Converted Markdown to storage format", file=sys.stderr)

    # Determine mode: create or update
    if args.page_id:
        # Update existing page
        page = get_page(base_url, token, args.page_id)
        if not page:
            print(f"Error: Page {args.page_id} not found.", file=sys.stderr)
            sys.exit(1)

        title = args.title or page["title"]
        current_version = page["version"]["number"]

        print(f"Updating page: {title} (version {current_version} -> {current_version + 1})", file=sys.stderr)

        result = update_page(base_url, token, args.page_id, title, storage_content, current_version)

    else:
        # Create new page
        if not args.space:
            print("Error: --space is required for creating a new page.", file=sys.stderr)
            sys.exit(1)
        if not args.title:
            print("Error: --title is required for creating a new page.", file=sys.stderr)
            sys.exit(1)

        print(f"Creating page: {args.title} in space {args.space}", file=sys.stderr)
        if args.parent:
            print(f"  Parent page ID: {args.parent}", file=sys.stderr)

        result = create_page(base_url, token, args.space, args.title, storage_content, args.parent)

    # Output result
    page_url = result["_links"]["base"] + result["_links"]["webui"]
    page_id = result["id"]

    print(f"\nSuccess!", file=sys.stderr)
    print(f"  Page ID: {page_id}", file=sys.stderr)
    print(f"  URL: {page_url}", file=sys.stderr)

    # Warn about draw.io files that need upload
    if drawio_files:
        print(f"\nDraw.io files to upload:", file=sys.stderr)
        for f in drawio_files:
            print(f"  uv run upload_attachment.py --page-id {page_id} --file {f}", file=sys.stderr)

    # Output URL for scripts
    print(page_url)


if __name__ == "__main__":
    main()
