# ripgrep Quick Reference

## Basic Command
```bash
rg [OPTIONS] PATTERN [PATH...]
```

## Essential Flags

| Flag | Description |
|------|-------------|
| `-i` | Case insensitive |
| `-w` | Whole words only |
| `-F` | Literal string (no regex) |
| `-v` | Invert match |
| `-c` | Count per file |
| `-l` | Filenames only |
| `-o` | Matches only |

## Context Display

| Flag | Description |
|------|-------------|
| `-C NUM` | Lines before and after |
| `-B NUM` | Lines before |
| `-A NUM` | Lines after |
| `-n` | Line numbers (default) |
| `-N` | Hide line numbers |

## File Type Filtering

| Flag | Description |
|------|-------------|
| `-t TYPE` | Include type |
| `-T TYPE` | Exclude type |
| `--type-list` | List types |
| `--type-add NAME:GLOB` | Add custom type |

**Common Types**: `js`, `ts`, `py`, `rust`, `go`, `java`, `cpp`, `html`, `css`, `json`, `yaml`, `md`

## Path Filtering

| Flag | Description |
|------|-------------|
| `-g GLOB` | Include glob |
| `-g !GLOB` | Exclude glob |
| `--hidden` | Include hidden |
| `--no-ignore` | Ignore .gitignore |
| `--follow` | Follow symlinks |

## Output Control

| Flag | Description |
|------|-------------|
| `--color WHEN` | never/auto/always |
| `--no-heading` | No file grouping |
| `--json` | JSON output |
| `--stats` | Statistics |
| `-m NUM` | Max matches per file |

## Performance

| Flag | Description |
|------|-------------|
| `--max-depth NUM` | Max depth |
| `--max-filesize SIZE` | Max file size |
| `--threads NUM` | Thread count |
| `--mmap` | Memory maps |

## Replace Operations

| Flag | Description |
|------|-------------|
| `-r TEXT` | Preview replacement |

## Quick Patterns

```bash
rg "pattern"
rg -i "pattern"
rg -w "function"
rg -C 3 "error"
rg -tjs "pattern"
rg -Tjs "pattern"
rg -g '*.ts' "pattern"
rg -l "pattern"
rg -c "pattern"
rg -o "https?://[^\s]+"
rg "error|warning|fatal"
rg "\bfunction\b"
rg "old" --replace "new"
rg --hidden "pattern"
rg --no-ignore "pattern"
rg "pattern" --stats
rg --json "pattern"
rg -F "function()"
rg -U "class.*{.*constructor"
```

## Common Combos

```bash
rg -tjs -tts "pattern"
rg "pattern" -g '!tests/' -g '!node_modules/'
rg -C 2 "TODO|FIXME"
rg -i "password|secret|api_key" -Ttest
git diff | rg "pattern"
rg -c "pattern" | sort -t: -k2 -rn
rg -o "https?://[^\s]+" | sort -u
```
