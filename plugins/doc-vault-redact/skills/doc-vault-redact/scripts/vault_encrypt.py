#!/usr/bin/env python3
"""Obsidian vault encryption with age + Apple Secure Enclave.

Whole-file encryption using age with dual recipients:
- Primary: Secure Enclave key (Touch ID via age-plugin-se)
- Backup: Regular age identity (for disaster recovery)

Encrypted files stay in-place with stub .md notes preserving
Obsidian wikilinks and tags.
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CONFIG_DIR = ".vault-encrypt"
CONFIG_FILE = "config.json"


def load_config(vault_path: Path) -> dict:
    config_path = vault_path / CONFIG_DIR / CONFIG_FILE
    if not config_path.exists():
        print(f"Error: No config found at {config_path}", file=sys.stderr)
        print("Run 'vault_encrypt.py setup --vault <path>' first.", file=sys.stderr)
        sys.exit(1)
    with open(config_path) as f:
        return json.load(f)


def find_vault() -> Path:
    """Find vault path from config in current directory or parents."""
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        config_path = parent / CONFIG_DIR / CONFIG_FILE
        if config_path.exists():
            with open(config_path) as f:
                cfg = json.load(f)
            return Path(cfg["vault_path"])
    # Try notesmd-cli
    try:
        result = subprocess.run(
            ["notesmd-cli", "print-default", "--path-only"],
            capture_output=True, text=True, check=True,
        )
        vault = Path(result.stdout.strip())
        if (vault / CONFIG_DIR / CONFIG_FILE).exists():
            return vault
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    print("Error: Cannot find vault. Run from vault directory or use --vault.", file=sys.stderr)
    sys.exit(1)


def check_tool(name: str) -> bool:
    try:
        subprocess.run([name, "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def cmd_setup(args):
    vault_path = Path(args.vault).expanduser().resolve()
    if not vault_path.is_dir():
        print(f"Error: Vault directory does not exist: {vault_path}", file=sys.stderr)
        sys.exit(1)

    config_dir = vault_path / CONFIG_DIR
    config_path = config_dir / CONFIG_FILE

    if config_path.exists():
        print(f"Config already exists at {config_path}")
        print("To re-setup, delete .vault-encrypt/ first.")
        sys.exit(1)

    # Check prerequisites
    for tool in ["age", "age-keygen", "age-plugin-se"]:
        if not check_tool(tool):
            print(f"Error: '{tool}' not found. Install with:", file=sys.stderr)
            print("  brew install age remko/tap/age-plugin-se", file=sys.stderr)
            sys.exit(1)

    config_dir.mkdir(parents=True, exist_ok=True)

    # Generate Secure Enclave key
    print("Generating Secure Enclave key (Touch ID will be required for encryption/decryption)...")
    se_result = subprocess.run(
        ["age-plugin-se", "keygen", "--access-control=any-biometry"],
        capture_output=True, text=True,
    )
    if se_result.returncode != 0:
        print(f"Error generating SE key: {se_result.stderr}", file=sys.stderr)
        sys.exit(1)

    se_output = se_result.stdout.strip()
    se_recipient = None
    se_identity = None
    for line in se_output.splitlines():
        if line.startswith("# recipient:"):
            se_recipient = line.split(":", 1)[1].strip()
        elif line.startswith("AGE-PLUGIN-SE-"):
            se_identity = line.strip()

    if not se_recipient or not se_identity:
        print(f"Error: Could not parse SE key output:\n{se_output}", file=sys.stderr)
        sys.exit(1)

    # Save SE identity to file
    se_key_path = config_dir / "se-identity.txt"
    with open(se_key_path, "w") as f:
        f.write(se_output + "\n")
    os.chmod(se_key_path, 0o600)

    # Generate backup key
    print("Generating backup key...")
    backup_result = subprocess.run(
        ["age-keygen"],
        capture_output=True, text=True,
    )
    if backup_result.returncode != 0:
        print(f"Error generating backup key: {backup_result.stderr}", file=sys.stderr)
        sys.exit(1)

    backup_output = backup_result.stdout.strip()
    backup_recipient = None
    backup_secret = None
    for line in backup_output.splitlines():
        if line.startswith("# public key:"):
            backup_recipient = line.split(":", 1)[1].strip()
        elif line.startswith("AGE-SECRET-KEY-"):
            backup_secret = line.strip()

    if not backup_recipient or not backup_secret:
        print(f"Error: Could not parse backup key output:\n{backup_output}", file=sys.stderr)
        sys.exit(1)

    # Save backup identity
    backup_key_path = config_dir / "backup-identity.txt"
    with open(backup_key_path, "w") as f:
        f.write(backup_output + "\n")
    os.chmod(backup_key_path, 0o600)

    # Save config
    config = {
        "vault_path": str(vault_path),
        "se_recipient": se_recipient,
        "se_identity": str(se_key_path),
        "backup_recipient": backup_recipient,
        "backup_identity": str(backup_key_path),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(config_path, 0o600)

    # Add .vault-encrypt to .gitignore if vault has git
    gitignore_path = vault_path / ".gitignore"
    gitignore_entry = ".vault-encrypt/"
    if gitignore_path.exists():
        content = gitignore_path.read_text()
        if gitignore_entry not in content:
            with open(gitignore_path, "a") as f:
                f.write(f"\n{gitignore_entry}\n")
    else:
        gitignore_path.write_text(f"{gitignore_entry}\n")

    print()
    print("=" * 60)
    print("SETUP COMPLETE")
    print("=" * 60)
    print()
    print(f"Vault:            {vault_path}")
    print(f"Config:           {config_dir}")
    print(f"SE recipient:     {se_recipient}")
    print(f"Backup recipient: {backup_recipient}")
    print()
    print("=" * 60)
    print("BACKUP KEY — STORE THIS IN PROTON PASS NOW")
    print("=" * 60)
    print()
    print("Create an SSH key entry in Proton Pass:")
    print(f"  Title:       vault-encrypt-backup")
    print(f"  Public key:  {backup_recipient}")
    print(f"  Private key: {backup_secret}")
    print()
    print("This backup key is your ONLY recovery path if this Mac is lost.")
    print("The Secure Enclave key cannot be extracted from hardware.")
    print()
    print("After storing in Proton Pass, you can optionally delete:")
    print(f"  {backup_key_path}")
    print("(The encrypted files will still be decryptable with the Proton Pass copy)")


def parse_frontmatter(content: str) -> tuple[dict | None, str]:
    """Extract YAML frontmatter and body from markdown content."""
    if not content.startswith("---"):
        return None, content
    end = content.find("\n---", 3)
    if end == -1:
        return None, content
    fm_text = content[3:end].strip()
    body = content[end + 4:].lstrip("\n")

    fm = {}
    current_key = None
    current_list = None
    for line in fm_text.splitlines():
        list_match = re.match(r"^\s+-\s+(.+)$", line)
        if list_match and current_key:
            if current_list is None:
                current_list = []
                fm[current_key] = current_list
            current_list.append(list_match.group(1).strip())
            continue
        kv_match = re.match(r"^(\w[\w-]*):\s*(.*)$", line)
        if kv_match:
            current_key = kv_match.group(1)
            value = kv_match.group(2).strip()
            current_list = None
            if value:
                if value.startswith("[") and value.endswith("]"):
                    fm[current_key] = [v.strip().strip("'\"") for v in value[1:-1].split(",")]
                    current_list = fm[current_key]
                else:
                    fm[current_key] = value.strip("'\"")
            continue
    return fm, body


def extract_title(content: str, filepath: Path) -> str:
    """Extract title from first heading or filename."""
    for line in content.splitlines():
        match = re.match(r"^#\s+(.+)$", line)
        if match:
            return match.group(1).strip()
    return filepath.stem


def build_stub(original_path: Path, tags: list, title: str, age_filename: str) -> str:
    """Build stub markdown for an encrypted file."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = ["---"]
    lines.append("tags:")
    lines.append("  - encrypted")
    for tag in tags:
        if tag != "encrypted":
            lines.append(f"  - {tag}")
    if tags:
        lines.append("original_tags:")
        for tag in tags:
            lines.append(f"  - {tag}")
    lines.append(f"encrypted_at: {now}")
    lines.append(f"encrypted_file: {age_filename}")
    lines.append("---")
    lines.append("")
    lines.append(f"# {title}")
    lines.append("")
    lines.append("This note is encrypted. Decrypt with:")
    lines.append("")
    lines.append("```bash")
    lines.append(f'python3 vault_encrypt.py decrypt "{original_path.parent / age_filename}"')
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def collect_files(vault_path: Path, folder: str | None, note: str | None,
                  pattern: str | None) -> list[Path]:
    """Collect files to encrypt based on scope arguments."""
    files = []

    if note:
        note_path = vault_path / note
        if not note_path.exists():
            print(f"Error: Note not found: {note_path}", file=sys.stderr)
            sys.exit(1)
        files.append(note_path)
    elif folder:
        folder_path = vault_path / folder
        if not folder_path.is_dir():
            print(f"Error: Folder not found: {folder_path}", file=sys.stderr)
            sys.exit(1)
        for f in sorted(folder_path.rglob("*")):
            if f.is_file():
                files.append(f)
    elif pattern:
        for match in sorted(glob.glob(str(vault_path / pattern), recursive=True)):
            p = Path(match)
            if p.is_file():
                files.append(p)
    else:
        print("Error: Specify --folder, --note, or --glob.", file=sys.stderr)
        sys.exit(1)

    # Filter out already-encrypted files, stubs, and config
    filtered = []
    for f in files:
        rel = f.relative_to(vault_path)
        if str(rel).startswith(CONFIG_DIR):
            continue
        if f.suffix == ".age":
            continue
        if f.suffix == ".md":
            try:
                content = f.read_text(encoding="utf-8")
                fm, _ = parse_frontmatter(content)
                if fm and isinstance(fm.get("tags"), list) and "encrypted" in fm["tags"]:
                    continue
            except (UnicodeDecodeError, PermissionError):
                pass
        if any(part.startswith(".") for part in rel.parts):
            continue
        filtered.append(f)

    return filtered


def encrypt_file(filepath: Path, vault_path: Path, config: dict, dry_run: bool) -> bool:
    """Encrypt a single file. Returns True on success."""
    rel = filepath.relative_to(vault_path)
    age_path = filepath.parent / (filepath.name + ".age")

    if age_path.exists():
        print(f"  SKIP (already encrypted): {rel}")
        return False

    if dry_run:
        print(f"  WOULD ENCRYPT: {rel}")
        return True

    # Encrypt with dual recipients
    cmd = [
        "age", "-e",
        "-r", config["se_recipient"],
        "-r", config["backup_recipient"],
        "-o", str(age_path),
        str(filepath),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ERROR encrypting {rel}: {result.stderr}", file=sys.stderr)
        return False

    # Build and write stub
    tags = []
    title = filepath.stem
    if filepath.suffix == ".md":
        try:
            content = filepath.read_text(encoding="utf-8")
            fm, body = parse_frontmatter(content)
            if fm and isinstance(fm.get("tags"), list):
                tags = fm["tags"]
            title = extract_title(content, filepath)
        except (UnicodeDecodeError, PermissionError):
            pass

    stub_content = build_stub(rel, tags, title, age_path.name)
    stub_path = filepath if filepath.suffix == ".md" else filepath.parent / (filepath.stem + ".md")

    if filepath.suffix != ".md":
        filepath.unlink()

    stub_path.write_text(stub_content, encoding="utf-8")

    print(f"  ENCRYPTED: {rel} -> {age_path.name}")
    return True


def cmd_encrypt(args):
    vault_path = Path(args.vault).expanduser().resolve() if args.vault else find_vault()
    config = load_config(vault_path)

    files = collect_files(vault_path, args.folder, args.note, args.glob)

    if not files:
        print("No files to encrypt.")
        return

    print(f"{'DRY RUN — ' if args.dry_run else ''}Encrypting {len(files)} file(s) in {vault_path}:")
    print()

    success = 0
    for f in files:
        if encrypt_file(f, vault_path, config, args.dry_run):
            success += 1

    print()
    if args.dry_run:
        print(f"Would encrypt {success} file(s).")
    else:
        print(f"Encrypted {success} file(s).")


def cmd_decrypt(args):
    age_path = Path(args.path).expanduser().resolve()
    if not age_path.exists():
        print(f"Error: File not found: {age_path}", file=sys.stderr)
        sys.exit(1)
    if age_path.suffix != ".age":
        print(f"Error: Not an .age file: {age_path}", file=sys.stderr)
        sys.exit(1)

    vault_path = Path(args.vault).expanduser().resolve() if args.vault else find_vault()
    config = load_config(vault_path)

    # Determine original filename (strip .age suffix)
    original_name = age_path.stem  # e.g., "note.md" from "note.md.age"
    original_path = age_path.parent / original_name

    # Choose identity
    if args.backup:
        identity_path = Path(args.backup).expanduser().resolve()
        if not identity_path.exists():
            print(f"Error: Backup key not found: {identity_path}", file=sys.stderr)
            sys.exit(1)
    else:
        identity_path = Path(config["se_identity"])

    # Decrypt
    cmd = [
        "age", "-d",
        "-i", str(identity_path),
        "-o", str(original_path),
        str(age_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error decrypting: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Remove .age file
    age_path.unlink()

    # Remove stub if it exists (for PDFs, stub is a .md with same stem)
    if not original_name.endswith(".md"):
        stub_path = age_path.parent / (Path(original_name).stem + ".md")
        if stub_path.exists():
            try:
                content = stub_path.read_text(encoding="utf-8")
                fm, _ = parse_frontmatter(content)
                if fm and isinstance(fm.get("tags"), list) and "encrypted" in fm["tags"]:
                    stub_path.unlink()
                    print(f"Removed stub: {stub_path.name}")
            except (UnicodeDecodeError, PermissionError):
                pass

    rel = original_path.relative_to(vault_path) if original_path.is_relative_to(vault_path) else original_path
    print(f"Decrypted: {rel}")


def cmd_status(args):
    vault_path = Path(args.vault).expanduser().resolve() if args.vault else find_vault()
    config = load_config(vault_path)

    age_files = sorted(vault_path.rglob("*.age"))
    age_files = [f for f in age_files if not str(f.relative_to(vault_path)).startswith(CONFIG_DIR)]

    if not age_files:
        print("No encrypted files in vault.")
        return

    # Group by folder
    folders: dict[str, list[Path]] = {}
    for f in age_files:
        rel = f.relative_to(vault_path)
        folder = str(rel.parent) if str(rel.parent) != "." else "(root)"
        folders.setdefault(folder, []).append(f)

    print(f"Vault: {vault_path}")
    print(f"Total encrypted files: {len(age_files)}")
    print()
    print("By folder:")
    for folder in sorted(folders):
        print(f"  {folder}: {len(folders[folder])} file(s)")

    # Count stubs
    stub_count = 0
    for md_file in vault_path.rglob("*.md"):
        if str(md_file.relative_to(vault_path)).startswith(CONFIG_DIR):
            continue
        try:
            content = md_file.read_text(encoding="utf-8")
            fm, _ = parse_frontmatter(content)
            if fm and isinstance(fm.get("tags"), list) and "encrypted" in fm["tags"]:
                stub_count += 1
        except (UnicodeDecodeError, PermissionError):
            pass

    print(f"\nStubs: {stub_count}")
    print(f"SE recipient: {config['se_recipient'][:20]}...")
    print(f"Backup recipient: {config['backup_recipient'][:20]}...")


def cmd_list(args):
    vault_path = Path(args.vault).expanduser().resolve() if args.vault else find_vault()
    load_config(vault_path)  # Verify setup

    age_files = sorted(vault_path.rglob("*.age"))
    age_files = [f for f in age_files if not str(f.relative_to(vault_path)).startswith(CONFIG_DIR)]

    if not age_files:
        print("No encrypted files in vault.")
        return

    for f in age_files:
        print(f.relative_to(vault_path))


def main():
    parser = argparse.ArgumentParser(
        description="Obsidian vault encryption with age + Secure Enclave",
    )
    parser.add_argument("--vault", help="Path to Obsidian vault (auto-detected if omitted)")
    sub = parser.add_subparsers(dest="command", required=True)

    # setup
    setup_parser = sub.add_parser("setup", help="Initialize encryption for a vault")
    setup_parser.add_argument("--vault", required=True, help="Path to Obsidian vault")

    # encrypt
    enc_parser = sub.add_parser("encrypt", help="Encrypt vault files")
    enc_parser.add_argument("--folder", help="Folder to encrypt (relative to vault)")
    enc_parser.add_argument("--note", help="Single note to encrypt (relative to vault)")
    enc_parser.add_argument("--glob", help="Glob pattern (relative to vault)")
    enc_parser.add_argument("--dry-run", action="store_true", help="Show what would be encrypted")
    enc_parser.add_argument("--vault", help="Path to Obsidian vault")

    # decrypt
    dec_parser = sub.add_parser("decrypt", help="Decrypt an encrypted file")
    dec_parser.add_argument("path", help="Path to .age file")
    dec_parser.add_argument("--backup", help="Path to backup identity file (skip SE)")
    dec_parser.add_argument("--vault", help="Path to Obsidian vault")

    # status
    status_parser = sub.add_parser("status", help="Show encryption status")
    status_parser.add_argument("--vault", help="Path to Obsidian vault")

    # list
    list_parser = sub.add_parser("list", help="List encrypted files")
    list_parser.add_argument("--vault", help="Path to Obsidian vault")

    args = parser.parse_args()

    commands = {
        "setup": cmd_setup,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "status": cmd_status,
        "list": cmd_list,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
