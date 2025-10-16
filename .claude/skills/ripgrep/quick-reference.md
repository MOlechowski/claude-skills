# ripgrep Quick Reference

## Basic Command
```bash
rg [OPTIONS] PATTERN [PATH...]
```

## Essential Flags

| Flag | Description |
|------|-------------|
| `-i` / `--ignore-case` | Case insensitive search |
| `-w` / `--word-regexp` | Match whole words only |
| `-F` / `--fixed-strings` | Treat pattern as literal string |
| `-v` / `--invert-match` | Invert matching (show non-matches) |
| `-c` / `--count` | Show count of matches per file |
| `-l` / `--files-with-matches` | Show only filenames with matches |
| `-o` / `--only-matching` | Show only matching part |

## Context Display

| Flag | Description |
|------|-------------|
| `-C NUM` / `--context NUM` | Show NUM lines before and after |
| `-B NUM` / `--before-context NUM` | Show NUM lines before |
| `-A NUM` / `--after-context NUM` | Show NUM lines after |
| `-n` / `--line-number` | Show line numbers (default) |
| `-N` / `--no-line-number` | Hide line numbers |

## File Type Filtering

| Flag | Description |
|------|-------------|
| `-t TYPE` / `--type TYPE` | Include only TYPE files |
| `-T TYPE` / `--type-not TYPE` | Exclude TYPE files |
| `--type-list` | List all supported file types |
| `--type-add NAME:GLOB` | Add custom file type |

**Common Types**: `js`, `ts`, `py`, `rust`, `go`, `java`, `cpp`, `html`, `css`, `json`, `yaml`, `md`

## Path Filtering

| Flag | Description |
|------|-------------|
| `-g GLOB` / `--glob GLOB` | Include files matching GLOB |
| `-g !GLOB` | Exclude files matching GLOB |
| `--hidden` | Search hidden files |
| `--no-ignore` | Don't respect .gitignore |
| `--follow` | Follow symbolic links |

## Output Control

| Flag | Description |
|------|-------------|
| `--color WHEN` | When to use colors (never, auto, always) |
| `--no-heading` | Don't group matches by file |
| `--json` | Output results as JSON |
| `--stats` | Show search statistics |
| `-m NUM` / `--max-count NUM` | Stop after NUM matches per file |

## Performance

| Flag | Description |
|------|-------------|
| `--max-depth NUM` | Max directory depth to search |
| `--max-filesize SIZE` | Ignore files larger than SIZE |
| `--threads NUM` | Number of threads to use |
| `--mmap` | Use memory maps (faster for large files) |

## Replace Operations

| Flag | Description |
|------|-------------|
| `-r TEXT` / `--replace TEXT` | Replace matches with TEXT (preview only) |

## Quick Patterns

```bash
# Search current directory
rg "pattern"

# Case insensitive
rg -i "pattern"

# Whole words only
rg -w "function"

# Show context
rg -C 3 "error"

# Search specific file types
rg -tjs "pattern"

# Exclude file types
rg -Tjs "pattern"

# Search with glob
rg -g '*.ts' "pattern"

# List matching files
rg -l "pattern"

# Count matches
rg -c "pattern"

# Only show matches (no context)
rg -o "https?://[^\s]+"

# Multiple patterns
rg "error|warning|fatal"

# Word boundary
rg "\bfunction\b"

# Replace preview
rg "old" --replace "new"

# Include hidden files
rg --hidden "pattern"

# Ignore .gitignore
rg --no-ignore "pattern"

# Show statistics
rg "pattern" --stats

# JSON output
rg --json "pattern"

# Fixed string (no regex)
rg -F "function()"

# Multiline search
rg -U "class.*{.*constructor"
```

## Common Combos

```bash
# TypeScript/JavaScript search
rg -tjs -tts "pattern"

# Exclude tests and node_modules
rg "pattern" -g '!tests/' -g '!node_modules/'

# Find TODOs with context
rg -C 2 "TODO|FIXME"

# Security audit
rg -i "password|secret|api_key" -Ttest

# Find in git diff
git diff | rg "pattern"

# Count per file, sorted
rg -c "pattern" | sort -t: -k2 -rn

# Extract URLs
rg -o "https?://[^\s]+" | sort -u
```
