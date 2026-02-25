---
name: doc-vault-redact
description: "Encrypt Obsidian vault files with age + Apple Secure Enclave (Touch ID). Whole-file encryption with stub notes preserving wikilinks and tags. Dual-recipient: SE key for daily use, backup key for disaster recovery. Use when: encrypting vault notes, protecting PII, vault security, encrypt sensitive files. Triggers: encrypt vault, vault encrypt, protect notes, encrypt file, decrypt file, vault security, redact vault."
---

# Vault Encrypt

Whole-file encryption for Obsidian vault notes and PDFs using `age` + `age-plugin-se` (Apple Secure Enclave with Touch ID). Encrypted files stay in-place with stub `.md` notes preserving Obsidian navigation.

## Prerequisites

```bash
brew install age remko/tap/age-plugin-se
```

Requires macOS 14+ with Secure Enclave (Apple Silicon or T2 chip).

## Script

All operations use `vault_encrypt.py`:

```bash
SCRIPT=$(find ~/.claude -path "*/doc-vault-redact/scripts/vault_encrypt.py" -print -quit 2>/dev/null)
```

## Setup

Run once per machine:

```bash
python3 $SCRIPT setup --vault /path/to/obsidian/vault
```

This:
1. Creates `.vault-encrypt/` config directory inside the vault
2. Generates a Secure Enclave key via `age-plugin-se keygen --access-control=any-biometry`
3. Generates a backup key via `age-keygen`
4. Saves config to `.vault-encrypt/config.json`
5. Prints the backup key — user must store it in Proton Pass (SSH key entry)

**Backup key storage:** Create an SSH key entry in Proton Pass:
- Title: `vault-encrypt-backup`
- Public key: the `age1...` recipient
- Private key: the `AGE-SECRET-KEY-...` line

Setup will not proceed until user confirms the backup key is stored.

## Commands

### Encrypt

```bash
# Encrypt entire folder
python3 $SCRIPT encrypt --folder finance/

# Encrypt single note
python3 $SCRIPT encrypt --note finance/credit/alior-bank-mac-studio.md

# Encrypt by glob pattern
python3 $SCRIPT encrypt --glob "finance/**/*.pdf"

# Dry run — show what would be encrypted
python3 $SCRIPT encrypt --folder finance/ --dry-run
```

Each encrypted file:
- Original `note.md` -> `note.md.age` (encrypted, dual-recipient)
- Stub `note.md` created with original tags, title, and decrypt instructions
- PDFs: `file.pdf` -> `file.pdf.age` + stub `file.md` created

### Decrypt

```bash
# Decrypt with Touch ID (Secure Enclave key)
python3 $SCRIPT decrypt finance/credit/alior-bank-mac-studio.md.age

# Decrypt with backup key (disaster recovery, no SE needed)
python3 $SCRIPT decrypt --backup ~/.vault-encrypt/backup.key finance/credit/alior-bank-mac-studio.md.age
```

Decryption restores the original file and removes the stub.

### Status

```bash
python3 $SCRIPT status
```

Shows: total encrypted files, breakdown by folder, stub inventory.

### List

```bash
python3 $SCRIPT list
```

Lists all `.age` files in the vault with paths.

## Scope Control

Two methods to select files for encryption:

1. **Folder paths**: `--folder finance/` encrypts all files in the folder recursively
2. **Frontmatter tags**: Notes with `vault-encrypt: true` in frontmatter are included when encrypting the parent folder

Files already encrypted (`.age` extension) and stubs (with `encrypted` tag) are skipped automatically.

## Stub Format

Stubs preserve Obsidian navigation:

```markdown
---
tags:
  - encrypted
  - {original-tags}
original_tags:
  - {preserved-for-restore}
encrypted_at: {ISO-8601}
encrypted_file: {filename.age}
---

# {note-title}

This note is encrypted. Decrypt with:

python3 vault_encrypt.py decrypt "{path-to-age-file}"
```

Wikilinks resolve to stubs. Tags remain searchable in Obsidian.

## Disaster Recovery

If the Mac is lost/broken (SE key dies with hardware):

1. Install `age` on new machine: `brew install age`
2. Export backup key from Proton Pass -> save to file
3. `python3 $SCRIPT decrypt --backup /path/to/backup.key <encrypted-file>`
4. Run `setup` on new machine for new SE key
5. Re-encrypt with new SE key + same backup key

## Constraints

**DO:**
- Always run `setup` before first use
- Always encrypt to both SE + backup recipients
- Always create stubs when encrypting
- Always restore original + remove stub when decrypting
- Resolve vault path from `.vault-encrypt/config.json`

**DON'T:**
- Auto-detect PII — user decides what to encrypt
- Encrypt stubs or already-encrypted files
- Delete backup key after setup
- Modify files outside the configured vault
