---
name: notesmd-cli
description: "NotesMD CLI (notesmd-cli) for Obsidian vault operations from the terminal. Go-based, works WITHOUT Obsidian running. 12 commands: open, daily, search, search-content, create, move, delete, list, print, frontmatter, set-default, print-default. Features: automatic wikilink/markdown link updates on move/rename, YAML frontmatter CRUD, backlink discovery, daily note templates, content search with snippets. Use for: obsidian vault management, note creation, markdown notes automation, daily journaling, frontmatter editing, vault search, note refactoring. Triggers: notesmd, notesmd-cli, obsidian cli, vault notes, daily notes cli, markdown notes cli, note management."
---

# NotesMD CLI

Go-based CLI for Obsidian vault operations. Filesystem-first -- works without Obsidian running. Reads Obsidian config files for compatibility.

## Setup

### Install

```bash
# macOS / Linux
brew install yakitrak/yakitrak/notesmd-cli

# Windows (Scoop)
scoop bucket add scoop-yakitrak https://github.com/yakitrak/scoop-yakitrak.git
scoop install notesmd-cli

# Arch Linux (AUR)
paru -S notesmd-cli-bin

# From source (Go 1.19+)
go install github.com/Yakitrak/obsidian-cli@latest
```

### Configure Default Vault

```bash
# Set default vault (name only, not path)
notesmd-cli set-default "MyVault"

# Set default open type to $EDITOR instead of Obsidian
notesmd-cli set-default --open-type editor

# Set both
notesmd-cli set-default "MyVault" --open-type editor

# Verify
notesmd-cli print-default
```

Config stored at `~/.config/notesmd-cli/preferences.json`.

## Command Reference

| Command | Alias | Args | Description |
|---------|-------|------|-------------|
| `open` | `o` | `<note>` | Open note in Obsidian or $EDITOR |
| `daily` | `d` | none | Create/open today's daily note |
| `search` | `s` | none | Fuzzy search note names (TUI) |
| `search-content` | `sc` | `<term>` | Full-text content search with snippets |
| `create` | `c` | `<note>` | Create note (with content, append, overwrite) |
| `move` | `m` | `<old> <new>` | Move/rename with automatic link updates |
| `delete` | -- | `<note>` | Delete note permanently (no trash) |
| `list` | `ls` | `[path]` | List files/folders in vault path |
| `print` | `p` | `<note>` | Print note contents to stdout |
| `frontmatter` | `fm` | `<note>` | View/edit/delete YAML frontmatter |
| `set-default` | `sd` | `[vault]` | Set default vault and open type |
| `print-default` | `pd` | none | Print default vault info |

### Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--vault` | `-v` | Vault name (overrides default) |
| `--editor` | `-e` | Open in $EDITOR instead of Obsidian |
| `--help` | `-h` | Help for any command |

`--editor` is supported on: `open`, `daily`, `search`, `search-content`, `create` (with `--open`), `move` (with `--open`).

For detailed flags per command, see `references/commands.md`.

## Common Workflows

### Daily Notes

```bash
# Open/create today's daily note
notesmd-cli daily

# In terminal editor
notesmd-cli daily --editor
```

Reads `.obsidian/daily-notes.json` for folder, date format (Moment.js), and template. If a template is configured, its content is used when creating a new daily note. Existing daily notes are not overwritten.

### Create Notes

```bash
# Empty note
notesmd-cli create "Project Ideas"

# With content (supports \n, \t escape sequences)
notesmd-cli create "meeting-notes/2024-01-15" --content "# Meeting Notes\n\n## Agenda\n"

# Append to existing
notesmd-cli create "inbox" --content "\n- New item" --append

# Overwrite existing
notesmd-cli create "scratch" --content "Fresh start" --overwrite

# Create and open in editor
notesmd-cli create "draft" --content "# Draft" --open --editor
```

Notes without an explicit path are placed in the vault's configured default folder (from `.obsidian/app.json`). Intermediate directories are created automatically.

`--append` and `--overwrite` are mutually exclusive. Without either flag, existing files are left unchanged.

### Search and Navigate

```bash
# Fuzzy search by name (interactive TUI)
notesmd-cli search

# Full-text content search (shows line numbers + snippets)
notesmd-cli search-content "API design"

# List vault contents
notesmd-cli list
notesmd-cli list "Projects/2024"

# Print note to stdout
notesmd-cli print "architecture-decisions"

# Print with backlinks (linked mentions)
notesmd-cli print "architecture-decisions" --mentions

# Open note at specific heading
notesmd-cli open "design-doc" --section "Authentication"
```

### Move/Rename with Link Updates

```bash
# Rename (same directory, new name)
notesmd-cli move "old-name.md" "new-name.md"

# Move to different folder
notesmd-cli move "inbox/idea.md" "projects/idea.md"

# Move and open
notesmd-cli move "drafts/post.md" "published/post.md" --open --editor
```

All wikilinks (`[[old-name]]`) and markdown links (`[text](old-name.md)`) across the vault are updated automatically.

### Frontmatter Management

```bash
# Print frontmatter
notesmd-cli frontmatter "my-note" --print

# Set/update a key (creates frontmatter if none exists)
notesmd-cli frontmatter "my-note" --edit --key "status" --value "done"
notesmd-cli frontmatter "my-note" --edit --key "draft" --value "false"
notesmd-cli frontmatter "my-note" --edit --key "tags" --value "[cli,obsidian,tools]"

# Delete a key
notesmd-cli frontmatter "my-note" --delete --key "draft"
```

Value type inference: `true`/`false` become booleans, `[a,b,c]` becomes an array, everything else is a string. If all frontmatter keys are deleted, the YAML block is removed entirely.

## Editor Integration

The `$EDITOR` environment variable controls which editor opens. Terminal editors (vim, nano, emacs) work directly. GUI editors (VS Code, Sublime Text) get `--wait` added automatically so the CLI blocks until the file is closed.

```bash
export EDITOR="code"    # VS Code
export EDITOR="vim"     # vim
export EDITOR="subl"    # Sublime Text
```

Set editor as permanent default to avoid `--editor` on every command:

```bash
notesmd-cli set-default --open-type editor
```

## Key Behaviors

- **Path resolution**: Note names are relative to vault root. `.md` extension is added automatically if missing.
- **Path traversal protection**: Paths that escape the vault directory (e.g., `../../etc/passwd`) are rejected.
- **Obsidian config**: Reads `.obsidian/daily-notes.json` and `.obsidian/app.json` for daily note and default folder settings.
- **Delete is permanent**: `delete` removes from disk immediately, no trash/recycle bin.
- **Link update scope**: `move` updates both `[[wikilinks]]` and `[markdown](links)` across all vault files.
- **Content escapes**: `--content` flag processes `\n`, `\t`, `\r`, `\\`, `\"`, `\'`.

## Resources

### references/
- `commands.md` -- Exhaustive command reference with all flags, edge cases, and examples
- `automation.md` -- Shell scripting examples, aliases, and workflow patterns
