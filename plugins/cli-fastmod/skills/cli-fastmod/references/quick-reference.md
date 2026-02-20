# Fastmod Quick Reference

## Command Syntax

```bash
fastmod [OPTIONS] <REGEX_PATTERN> <REPLACEMENT> [PATH]
```

## Options

| Option | Description | Example |
|--------|-------------|---------|
| `-d <DIR>` | Search directory | `-d src` |
| `--extensions <EXT>` | File types | `--extensions ts,tsx,js` |
| `-i` | Case insensitive | `-i` |
| `-m` | Multiline mode | `-m` |
| `--iglob <PATTERN>` | Include glob | `--iglob '**/*.test.ts'` |
| `--exclude-dir <DIR>` | Exclude directory | `--exclude-dir node_modules` |
| `--accept-all` | Non-interactive (test first!) | Use carefully |

## Interactive Commands

| Key | Action |
|-----|--------|
| `y` | Accept |
| `n` | Reject |
| `e` | Edit in $EDITOR |
| `d` | Accept all in file |
| `q` | Quit |
| `s` | Skip file |

## Regex Syntax

### Rust vs Python/JS

| Feature | Python/JS | Rust (fastmod) |
|---------|-----------|----------------|
| Capture group | `\1` | `${1}` |
| Literal `$` | `$` | `$$` |
| Lookahead | `(?=...)` | Not supported |
| Lookbehind | `(?<=...)` | Not supported |

### Common Patterns

```bash
\b     # Word boundary
\s     # Whitespace
\w     # Word char
\d     # Digit
.      # Any char
*      # Zero or more
+      # One or more
?      # Optional
(x)    # Capture group
(?:x)  # Non-capturing
```

## Quick Patterns

```bash
# Simple rename
fastmod 'OldName' 'NewName'

# Scoped rename
fastmod -d src --extensions ts,tsx 'OldName' 'NewName'

# Function call update
fastmod 'oldFunction\((.*?)\)' 'newFunction(${1})'

# Import path change
fastmod "from './old/path'" "from './new/path'"

# Add parameter
fastmod 'doSomething\((.*?)\)' 'doSomething(${1}, newParam)'

# JSX prop rename
fastmod '<Button type=' '<Button variant='

# CSS class rename
fastmod 'className="old-class"' 'className="new-class"'
```

## Safety Checklist

Before:
- [ ] Git clean
- [ ] Pattern tested
- [ ] Extensions specified
- [ ] Build dirs excluded
- [ ] Interactive mode

After:
- [ ] Build passes
- [ ] Tests pass
- [ ] Review `git diff`
- [ ] Commit

## Common Issues

| Problem | Solution |
|---------|----------|
| No matches | Check pattern, extensions, directory |
| Too many matches | Add context, use word boundaries |
| Pattern invalid | No lookahead/lookbehind in Rust regex |
| Replacement wrong | Use `${1}` not `\1`, `$$` for literal `$` |

## Workflow

```bash
git status
fastmod -d src/components --extensions tsx 'OldComponent' 'NewComponent'
# Review and accept
fastmod -d src --extensions tsx,ts 'OldComponent' 'NewComponent'
npm run build && npm test
git add -A && git commit -m "refactor: rename OldComponent to NewComponent"
```

## When to Use

**Good for:** 20+ files, pattern-based changes, human review needed

**Not ideal for:** 1-3 files (IDE), semantic changes (AST tools), full automation (sed)

## Rollback

```bash
git restore .            # Undo all
git restore path/to/file # Undo file
git stash                # Stash for later
```
