# NotesMD CLI -- Automation & Scripting Patterns

Shell aliases, scripting recipes, and workflow patterns for integrating notesmd-cli into automated workflows.

## Shell Aliases

Add to `~/.zshrc` or `~/.bashrc`:

```bash
# Quick access
alias nmd="notesmd-cli"
alias nmd-d="notesmd-cli daily --editor"
alias nmd-s="notesmd-cli search --editor"
alias nmd-sc="notesmd-cli search-content"
alias nmd-ls="notesmd-cli list"

# Navigate to vault directory
nmd_cd() {
    local path
    path=$(notesmd-cli print-default --path-only)
    [ -n "$path" ] && cd -- "$path"
}

# Quick note capture from terminal
nmd_capture() {
    local note="${1:-inbox}"
    shift
    notesmd-cli create "$note" --content "\n- $(date '+%Y-%m-%d %H:%M'): $*" --append
}
# Usage: nmd_capture "inbox" "Remember to review PR #42"
# Usage: nmd_capture "" "Quick thought"  (defaults to "inbox")
```

## Scripting Recipes

### Batch Frontmatter Update

```bash
#!/usr/bin/env bash
# Tag all notes in a folder with a project tag
FOLDER="projects/alpha"
TAG="alpha"

for file in $(notesmd-cli list "$FOLDER"); do
    # Skip directories (entries ending with /)
    [[ "$file" == */ ]] && continue
    note="${FOLDER}/${file}"
    notesmd-cli frontmatter "$note" --edit --key "project" --value "$TAG"
    echo "Tagged: $note"
done
```

### Daily Log Appender

```bash
#!/usr/bin/env bash
# Append a timestamped entry to today's daily note
# Usage: daily-log "Completed code review for auth module"

MESSAGE="$*"
if [ -z "$MESSAGE" ]; then
    echo "Usage: daily-log <message>" >&2
    exit 1
fi

# Ensure daily note exists
notesmd-cli daily --editor 2>/dev/null &
sleep 0.5
kill %1 2>/dev/null

# Build the daily note path (matches YYYY-MM-DD default format)
DATE=$(date '+%Y-%m-%d')
notesmd-cli create "$DATE" --content "\n- $(date '+%H:%M') $MESSAGE" --append
```

### Export Note to Clipboard

```bash
#!/usr/bin/env bash
# Print a note and copy to clipboard
# macOS
notesmd-cli print "$1" | pbcopy
echo "Copied '$1' to clipboard"

# Linux (xclip)
# notesmd-cli print "$1" | xclip -selection clipboard
```

### Find Notes Missing Frontmatter

```bash
#!/usr/bin/env bash
# Scan vault for notes without frontmatter
VAULT_PATH=$(notesmd-cli print-default --path-only)

find "$VAULT_PATH" -name "*.md" -not -path "*/.obsidian/*" | while read -r file; do
    # Check if file starts with ---
    if ! head -1 "$file" | grep -q "^---$"; then
        # Get relative path
        echo "${file#$VAULT_PATH/}"
    fi
done
```

### Bulk Move/Reorganize

```bash
#!/usr/bin/env bash
# Move all notes from inbox/ to archive/ with link updates
for file in $(notesmd-cli list "inbox"); do
    [[ "$file" == */ ]] && continue
    notesmd-cli move "inbox/${file}" "archive/${file}"
    echo "Moved: inbox/${file} -> archive/${file}"
done
```

### Note Content Search to File

```bash
#!/usr/bin/env bash
# Search vault content and save results (non-interactive alternative)
VAULT_PATH=$(notesmd-cli print-default --path-only)
TERM="$1"

grep -rl "$TERM" "$VAULT_PATH" --include="*.md" | while read -r file; do
    rel="${file#$VAULT_PATH/}"
    echo "## $rel"
    grep -n "$TERM" "$file"
    echo
done
```

### Status Report from Frontmatter

```bash
#!/usr/bin/env bash
# List notes by frontmatter status value
STATUS="${1:-in-progress}"
VAULT_PATH=$(notesmd-cli print-default --path-only)

find "$VAULT_PATH" -name "*.md" -not -path "*/.obsidian/*" | while read -r file; do
    fm=$(notesmd-cli print "$(basename "${file%.md}")" 2>/dev/null | head -20)
    if echo "$fm" | grep -q "status: $STATUS"; then
        echo "$(basename "${file%.md}")"
    fi
done
```

## Git Integration

### Pre-commit Hook for Vault

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit in vault repo
# Ensure all committed notes have required frontmatter keys

REQUIRED_KEYS=("title" "date")
ERRORS=0

for file in $(git diff --cached --name-only --diff-filter=ACM | grep "\.md$"); do
    for key in "${REQUIRED_KEYS[@]}"; do
        if ! head -20 "$file" | grep -q "^${key}:"; then
            echo "ERROR: $file missing frontmatter key '$key'"
            ERRORS=$((ERRORS + 1))
        fi
    done
done

exit $ERRORS
```

### Automated Daily Note with Cron

```bash
# crontab -e
# Create daily note at 8am every weekday
0 8 * * 1-5 notesmd-cli daily 2>/dev/null
```

## Piping Patterns

```bash
# Count notes in vault
notesmd-cli list | wc -l

# Get vault path for use in other commands
VAULT=$(notesmd-cli print-default --path-only)

# Print note and pipe to processing
notesmd-cli print "meeting-notes" | grep "ACTION:"

# Create note from command output
notesmd-cli create "system-info" --content "$(uname -a)" --overwrite

# Create note from file
notesmd-cli create "imported" --content "$(cat external-doc.md)" --overwrite

# Chain create + open
notesmd-cli create "new-note" --content "# Title" --open --editor
```

## Multi-Vault Patterns

```bash
# Operate on a specific vault without changing defaults
notesmd-cli list --vault "Work"
notesmd-cli create "note" --vault "Personal" --content "text"

# Copy a note between vaults
notesmd-cli print "shared-template" --vault "Templates" | \
    xargs -I{} notesmd-cli create "template-copy" --vault "Work" --content "{}"

# Simpler: use print + create with command substitution
CONTENT=$(notesmd-cli print "shared-template" --vault "Templates")
notesmd-cli create "template-copy" --vault "Work" --content "$CONTENT" --overwrite
```
