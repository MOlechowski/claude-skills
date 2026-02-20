#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Confluence Credentials Setup

Securely stores Confluence URL and Personal Access Token in macOS Keychain.

Usage:
    uv run setup_credentials.py --url https://confluence.company.com --token YOUR_PAT
    uv run setup_credentials.py --verify

The credentials are stored in ~/Library/Keychains/claude-keys.keychain-db
"""

import subprocess
import sys
import os
import argparse


KEYCHAIN_PATH = os.path.expanduser("~/Library/Keychains/claude-keys.keychain-db")
SERVICE_URL = "confluence-url"
SERVICE_TOKEN = "confluence-token"


def keychain_exists() -> bool:
    """Check if the claude-keys keychain exists."""
    return os.path.exists(KEYCHAIN_PATH)


def create_keychain():
    """Create the claude-keys keychain if it doesn't exist."""
    if keychain_exists():
        print(f"Keychain already exists: {KEYCHAIN_PATH}")
        return True

    print("Creating keychain for Claude credentials...")
    print("You will be prompted to set a password for the keychain.\n")

    try:
        # Create keychain
        subprocess.run(
            ["security", "create-keychain", KEYCHAIN_PATH],
            check=True
        )

        # Add to search list
        result = subprocess.run(
            ["security", "list-keychains", "-d", "user"],
            capture_output=True,
            text=True,
            check=True
        )
        current_keychains = result.stdout.strip().replace('"', '').split('\n')
        current_keychains = [k.strip() for k in current_keychains if k.strip()]

        if KEYCHAIN_PATH not in current_keychains:
            subprocess.run(
                ["security", "list-keychains", "-s", KEYCHAIN_PATH] + current_keychains,
                check=True
            )

        print(f"Created keychain: {KEYCHAIN_PATH}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error creating keychain: {e}")
        return False


def store_credential(service: str, value: str) -> bool:
    """Store a credential in the keychain."""
    user = os.environ.get("USER", "claude")

    try:
        # Try to delete existing entry first
        subprocess.run(
            ["security", "delete-generic-password", "-s", service, KEYCHAIN_PATH],
            capture_output=True
        )
    except subprocess.CalledProcessError:
        pass  # Entry doesn't exist, that's fine

    try:
        subprocess.run(
            [
                "security", "add-generic-password",
                "-s", service,
                "-a", user,
                "-w", value,
                KEYCHAIN_PATH
            ],
            check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error storing {service}: {e}")
        return False


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
    except subprocess.CalledProcessError:
        return None


def verify_credentials() -> bool:
    """Verify that credentials are stored and accessible."""
    url = get_credential(SERVICE_URL)
    token = get_credential(SERVICE_TOKEN)

    if url and token:
        print("Credentials verified:")
        print(f"  URL: {url}")
        print(f"  Token: {'*' * 8}...{token[-4:]}")
        return True
    else:
        missing = []
        if not url:
            missing.append("URL")
        if not token:
            missing.append("Token")
        print(f"Missing credentials: {', '.join(missing)}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Setup Confluence credentials in macOS Keychain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Store credentials
    uv run setup_credentials.py --url https://confluence.company.com --token xyzabc123

    # Verify stored credentials
    uv run setup_credentials.py --verify

    # Unlock keychain (if locked)
    security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db
        """
    )

    parser.add_argument("--url", help="Confluence base URL (e.g., https://confluence.company.com)")
    parser.add_argument("--token", help="Personal Access Token")
    parser.add_argument("--verify", action="store_true", help="Verify stored credentials")

    args = parser.parse_args()

    if args.verify:
        success = verify_credentials()
        sys.exit(0 if success else 1)

    if not args.url or not args.token:
        parser.print_help()
        print("\nError: Both --url and --token are required to store credentials.")
        sys.exit(1)

    # Ensure keychain exists
    if not create_keychain():
        sys.exit(1)

    # Store credentials
    print("\nStoring credentials...")

    url = args.url.rstrip("/")  # Remove trailing slash
    if not store_credential(SERVICE_URL, url):
        print("Failed to store URL")
        sys.exit(1)

    if not store_credential(SERVICE_TOKEN, args.token):
        print("Failed to store token")
        sys.exit(1)

    print("\nCredentials stored successfully!")
    print(f"  URL: {url}")
    print(f"  Token: {'*' * 8}...{args.token[-4:]}")

    print("\nTo verify: uv run setup_credentials.py --verify")


if __name__ == "__main__":
    main()
