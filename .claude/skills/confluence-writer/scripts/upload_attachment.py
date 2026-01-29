#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "httpx>=0.25.0",
# ]
# ///
"""
Confluence Attachment Uploader

Uploads files as attachments to Confluence pages.
Supports draw.io diagrams, images, and other files.

Usage:
    uv run upload_attachment.py --page-id 12345 --file diagram.drawio
    uv run upload_attachment.py --page-id 12345 --file image.png --comment "Screenshot"
    uv run upload_attachment.py --page-id 12345 --files diagram.drawio image.png

Dependencies are managed automatically via uv (PEP 723).
"""

import subprocess
import sys
import os
import argparse
import mimetypes
from pathlib import Path

import httpx


KEYCHAIN_PATH = os.path.expanduser("~/Library/Keychains/claude-keys.keychain-db")


def get_credential(service: str) -> str | None:
    """Retrieve a credential from the keychain."""
    try:
        result = subprocess.run(
            [
                "security", "find-generic-password",
                "-s", service,
                "-w",
                KEYCHAIN_PATH
            ],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if "could not be found" in e.stderr:
            return None
        elif "User interaction is not allowed" in e.stderr:
            print("Error: Keychain is locked.", file=sys.stderr)
            print("Unlock with: security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db", file=sys.stderr)
            sys.exit(1)
        else:
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


def get_mime_type(file_path: Path) -> str:
    """Get MIME type for a file."""
    mime_type, _ = mimetypes.guess_type(str(file_path))

    # Special cases for draw.io files
    if file_path.suffix in (".drawio", ".drawio.xml"):
        return "application/vnd.jgraph.mxfile"

    return mime_type or "application/octet-stream"


def upload_attachment(
    base_url: str,
    token: str,
    page_id: str,
    file_path: Path,
    comment: str | None = None,
    minor_edit: bool = False,
) -> dict:
    """
    Upload a file as an attachment to a Confluence page.

    Args:
        base_url: Confluence base URL
        token: Personal Access Token
        page_id: Page ID to attach to
        file_path: Path to the file
        comment: Optional comment for the attachment
        minor_edit: If True, mark as minor edit

    Returns:
        API response as dict
    """
    url = f"{base_url}/rest/api/content/{page_id}/child/attachment"

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Atlassian-Token": "nocheck",  # Required for multipart uploads
    }

    mime_type = get_mime_type(file_path)

    with open(file_path, "rb") as f:
        files = {
            "file": (file_path.name, f, mime_type),
        }

        data = {}
        if comment:
            data["comment"] = comment
        if minor_edit:
            data["minorEdit"] = "true"

        with httpx.Client(timeout=60) as client:
            response = client.post(url, headers=headers, files=files, data=data)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                print(f"Error: Permission denied. Check your token has write access.", file=sys.stderr)
                sys.exit(1)
            elif response.status_code == 404:
                print(f"Error: Page {page_id} not found.", file=sys.stderr)
                sys.exit(1)
            else:
                print(f"Error: {response.status_code} - {response.text}", file=sys.stderr)
                sys.exit(1)


def update_attachment(
    base_url: str,
    token: str,
    page_id: str,
    attachment_id: str,
    file_path: Path,
    comment: str | None = None,
    minor_edit: bool = False,
) -> dict:
    """
    Update an existing attachment.

    Args:
        base_url: Confluence base URL
        token: Personal Access Token
        page_id: Page ID
        attachment_id: Existing attachment ID
        file_path: Path to the new file
        comment: Optional comment
        minor_edit: If True, mark as minor edit

    Returns:
        API response as dict
    """
    url = f"{base_url}/rest/api/content/{page_id}/child/attachment/{attachment_id}/data"

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Atlassian-Token": "nocheck",
    }

    mime_type = get_mime_type(file_path)

    with open(file_path, "rb") as f:
        files = {
            "file": (file_path.name, f, mime_type),
        }

        data = {}
        if comment:
            data["comment"] = comment
        if minor_edit:
            data["minorEdit"] = "true"

        with httpx.Client(timeout=60) as client:
            response = client.post(url, headers=headers, files=files, data=data)

            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error updating attachment: {response.status_code} - {response.text}", file=sys.stderr)
                sys.exit(1)


def list_attachments(base_url: str, token: str, page_id: str) -> list[dict]:
    """List all attachments on a page."""
    url = f"{base_url}/rest/api/content/{page_id}/child/attachment"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    with httpx.Client(timeout=30) as client:
        response = client.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            return data.get("results", [])
        else:
            print(f"Error listing attachments: {response.status_code}", file=sys.stderr)
            return []


def find_attachment_by_name(attachments: list[dict], filename: str) -> dict | None:
    """Find an attachment by filename."""
    for att in attachments:
        if att.get("title") == filename:
            return att
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Upload files as Confluence page attachments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Upload single file
    uv run upload_attachment.py --page-id 12345 --file diagram.drawio

    # Upload with comment
    uv run upload_attachment.py --page-id 12345 --file screenshot.png --comment "UI mockup"

    # Upload multiple files
    uv run upload_attachment.py --page-id 12345 --files diagram.drawio logo.png spec.pdf

    # List existing attachments
    uv run upload_attachment.py --page-id 12345 --list
        """
    )

    parser.add_argument("--page-id", required=True, help="Confluence page ID")
    parser.add_argument("--file", help="Single file to upload")
    parser.add_argument("--files", nargs="+", help="Multiple files to upload")
    parser.add_argument("--comment", help="Comment for the attachment")
    parser.add_argument("--minor-edit", action="store_true", help="Mark as minor edit")
    parser.add_argument("--list", action="store_true", help="List existing attachments")
    parser.add_argument("--update", action="store_true",
                        help="Update existing attachment if found (default: add new version)")

    args = parser.parse_args()

    # Get credentials
    base_url, token = get_confluence_credentials()

    # List attachments
    if args.list:
        attachments = list_attachments(base_url, token, args.page_id)
        if attachments:
            print(f"Attachments on page {args.page_id}:")
            for att in attachments:
                print(f"  - {att['title']} (id: {att['id']}, size: {att.get('extensions', {}).get('fileSize', 'N/A')})")
        else:
            print(f"No attachments on page {args.page_id}")
        return

    # Collect files to upload
    files_to_upload = []
    if args.file:
        files_to_upload.append(Path(args.file))
    if args.files:
        files_to_upload.extend(Path(f) for f in args.files)

    if not files_to_upload:
        parser.print_help()
        print("\nError: Specify --file or --files to upload.", file=sys.stderr)
        sys.exit(1)

    # Validate files exist
    for file_path in files_to_upload:
        if not file_path.exists():
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            sys.exit(1)

    # Get existing attachments if we might need to update
    existing_attachments = []
    if args.update:
        existing_attachments = list_attachments(base_url, token, args.page_id)

    # Upload files
    for file_path in files_to_upload:
        print(f"Uploading: {file_path.name}...", end=" ")

        # Check if we should update existing
        existing = find_attachment_by_name(existing_attachments, file_path.name) if args.update else None

        if existing:
            result = update_attachment(
                base_url, token, args.page_id,
                existing["id"], file_path,
                comment=args.comment,
                minor_edit=args.minor_edit
            )
            print(f"Updated (id: {existing['id']})")
        else:
            result = upload_attachment(
                base_url, token, args.page_id,
                file_path,
                comment=args.comment,
                minor_edit=args.minor_edit
            )
            # Extract new attachment info
            results = result.get("results", [result])
            if results:
                att = results[0]
                print(f"Uploaded (id: {att.get('id', 'N/A')})")
            else:
                print("Uploaded")

    print(f"\nDone! {len(files_to_upload)} file(s) uploaded to page {args.page_id}")


if __name__ == "__main__":
    main()
