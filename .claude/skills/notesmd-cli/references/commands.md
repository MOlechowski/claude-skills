# NotesMD CLI -- Command Reference

Exhaustive reference for all 12 commands, their flags, edge cases, and examples.

## open (alias: o)

Open a note in Obsidian or $EDITOR.

```
notesmd-cli open <note> [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |
| `--section` | `-s` | string | -- | Heading to scroll to (case-sensitive) |
| `--editor` | `-e` | bool | false | Open in $EDITOR |

**Notes:**
- `<note>` is the note name or path relative to vault root.
- `.md` extension is added automatically.
- `--section` matches heading text exactly (case-sensitive).
- If default open type is "editor", `--editor` is implied automatically.

```bash
notesmd-cli open "Projects/roadmap"
notesmd-cli open "design-doc" --section "Authentication" --vault "Work"
notesmd-cli open "todo" --editor
```

---

## daily (alias: d)

Create or open today's daily note on disk. Does not require Obsidian to be running.

```
notesmd-cli daily [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |
| `--editor` | `-e` | bool | false | Open in $EDITOR |

**Config:** Reads `.obsidian/daily-notes.json` from the vault:
- `folder` -- Subdirectory for daily notes (default: vault root)
- `format` -- Moment.js date format (default: `YYYY-MM-DD`)
- `template` -- Template note path (content copied to new daily notes)

**Behavior:**
- If the daily note already exists, it is opened without modification.
- If the config file is missing or unreadable, defaults are used.
- Template content is only applied when creating a new note, never when opening an existing one.
- Intermediate directories are created automatically.

```bash
notesmd-cli daily
notesmd-cli daily --vault "Journal" --editor
```

---

## search (alias: s)

Launch fuzzy search TUI to find notes by name. Select a result to open it.

```
notesmd-cli search [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |
| `--editor` | `-e` | bool | false | Open selected note in $EDITOR |

**Notes:**
- Interactive TUI -- requires a terminal (not suitable for piping/scripting).
- Press Enter on a result to open it.

```bash
notesmd-cli search
notesmd-cli search --vault "Work" --editor
```

---

## search-content (alias: sc)

Search note content for a term. Shows matching files with line numbers and snippets. Select a result to open it.

```
notesmd-cli search-content <term> [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |
| `--editor` | `-e` | bool | false | Open selected note in $EDITOR |

**Notes:**
- Interactive TUI -- requires a terminal.
- Search term is a single required argument (quote multi-word terms).
- Results show file path, line number, and matching line snippet.

```bash
notesmd-cli search-content "API endpoint"
notesmd-cli search-content "TODO" --vault "Work" --editor
```

---

## create (alias: c)

Create a note on disk. Does not require Obsidian to be running.

```
notesmd-cli create <note> [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |
| `--content` | `-c` | string | "" | Text to write |
| `--append` | `-a` | bool | false | Append to existing note |
| `--overwrite` | `-o` | bool | false | Overwrite existing note |
| `--open` | -- | bool | false | Open note after creation |
| `--editor` | `-e` | bool | false | Open in $EDITOR (requires `--open`) |

**Behavior:**
- `.md` extension added automatically.
- If the note exists and neither `--append` nor `--overwrite` is set, the file is left unchanged.
- `--append` and `--overwrite` are mutually exclusive (enforced).
- Notes without an explicit path (no `/`) are placed in the vault's configured default folder (from `.obsidian/app.json` `newFileFolderPath`).
- Intermediate directories are created automatically.
- Content supports escape sequences: `\n`, `\t`, `\r`, `\\`, `\"`, `\'`.

```bash
notesmd-cli create "inbox/quick-note" --content "# Quick Note\n\nCapture here."
notesmd-cli create "log" --content "\n- $(date): Event happened" --append
notesmd-cli create "scratch" --content "Replaced content" --overwrite
notesmd-cli create "new-doc" --open --editor
```

---

## move (alias: m)

Move or rename a note. All wikilinks and markdown links across the vault are updated to match.

```
notesmd-cli move <current-path> <new-path> [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |
| `--open` | `-o` | bool | false | Open note after move |
| `--editor` | `-e` | bool | false | Open in $EDITOR (requires `--open`) |

**Behavior:**
- Both paths are relative to vault root.
- Same directory + different name = rename.
- Different directory = move (and optionally rename).
- Updates both `[[wikilink]]` and `[text](markdown-link)` references in all vault files.
- Path traversal protection prevents escaping the vault directory.

```bash
# Rename
notesmd-cli move "old-name.md" "new-name.md"

# Move to subfolder
notesmd-cli move "inbox/idea.md" "projects/active/idea.md"

# Move and open
notesmd-cli move "drafts/post.md" "published/post.md" --open --editor
```

---

## delete

Delete a note permanently from disk.

```
notesmd-cli delete <note> [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |

**Behavior:**
- Permanent deletion. No trash, no recycle bin, no undo.
- Does NOT update links in other files that reference the deleted note.
- `<note>` is a path relative to vault root.

```bash
notesmd-cli delete "scratch-note"
notesmd-cli delete "archive/old-project" --vault "Work"
```

---

## list (alias: ls)

List files and folders in a vault directory.

```
notesmd-cli list [path] [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |

**Notes:**
- Without `[path]`, lists vault root.
- Lists immediate children only (not recursive).
- Output is bullet-pointed (`- filename`).

```bash
notesmd-cli list
notesmd-cli list "Projects/2024" --vault "Work"
```

---

## print (alias: p)

Print note contents to stdout.

```
notesmd-cli print <note> [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |
| `--mentions` | `-m` | bool | false | Append linked mentions (backlinks) |

**Notes:**
- `<note>` is a name or path relative to vault root.
- `--mentions` scans the entire vault for files that link to this note (wikilinks and markdown links).
- Backlinks are appended as a `## Linked Mentions` section grouped by source file.
- Useful for piping note content to other tools.

```bash
notesmd-cli print "architecture"
notesmd-cli print "api-design" --mentions
notesmd-cli print "config" --vault "Infra" | grep "endpoint"
```

---

## frontmatter (alias: fm)

View, edit, or delete YAML frontmatter in notes.

```
notesmd-cli frontmatter <note> [flags]
```

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--vault` | `-v` | string | (default vault) | Vault name |
| `--print` | `-p` | bool | false | Print frontmatter |
| `--edit` | `-e` | bool | false | Edit a frontmatter key |
| `--delete` | `-d` | bool | false | Delete a frontmatter key |
| `--key` | `-k` | string | "" | Key name (required for `--edit` and `--delete`) |
| `--value` | -- | string | "" | Value to set (required for `--edit`) |

**Exactly one of `--print`, `--edit`, or `--delete` must be specified.**

**Value type inference (for `--edit`):**
- `"true"` / `"false"` -> boolean
- `"[a, b, c]"` -> string array (comma-separated, in brackets)
- Everything else -> string

**Behavior:**
- `--edit` creates frontmatter if the note has none.
- `--delete` on the last key removes the entire YAML block.
- `--print` on a note without frontmatter returns empty output (no error).

```bash
# View
notesmd-cli frontmatter "project-plan" --print

# Set/update
notesmd-cli frontmatter "post" --edit --key "status" --value "published"
notesmd-cli frontmatter "post" --edit --key "tags" --value "[blog,tech,go]"
notesmd-cli frontmatter "post" --edit --key "draft" --value "false"

# Delete
notesmd-cli frontmatter "post" --delete --key "draft"
```

---

## set-default (alias: sd)

Set default vault name and/or open type.

```
notesmd-cli set-default [vault-name] [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--open-type` | string | -- | Default open type: `obsidian` or `editor` |

**Notes:**
- At least one of `[vault-name]` or `--open-type` must be provided.
- Vault name is the Obsidian vault name, not the filesystem path.
- Config stored at `~/.config/notesmd-cli/preferences.json`.
- When `open-type` is `editor`, all commands that support `--open` will use `$EDITOR` by default.

```bash
notesmd-cli set-default "Personal"
notesmd-cli set-default --open-type editor
notesmd-cli set-default "Work" --open-type obsidian
```

---

## print-default (alias: pd)

Print default vault information.

```
notesmd-cli print-default [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path-only` | bool | false | Print only the vault filesystem path |

**Output (default):**
```
Default vault name: MyVault
Default vault path: /Users/me/Documents/MyVault
Default open type: editor
```

**Output (--path-only):**
```
/Users/me/Documents/MyVault
```

`--path-only` is useful for scripting (e.g., `cd $(notesmd-cli print-default --path-only)`).

```bash
notesmd-cli print-default
notesmd-cli print-default --path-only
```
