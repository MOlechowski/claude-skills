# Fastmod Quick Reference

## Command Syntax

```bash
fastmod [OPTIONS] <REGEX_PATTERN> <REPLACEMENT> [PATH]
```

## Most Used Options

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
| `?` | Help |

## Regex Syntax

### Rust vs Python/JS

| Feature | Python/JS | Rust (fastmod) |
|---------|-----------|----------------|
| Capture group reference | `\1` | `${1}` |
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

### Simple Rename
```bash
fastmod 'OldName' 'NewName'
```

### Rename with Scope
```bash
fastmod -d src --extensions ts,tsx 'OldName' 'NewName'
```

### Function Call Update
```bash
fastmod 'oldFunction\((.*?)\)' 'newFunction(${1})'
```

### Import Path Change
```bash
fastmod "from './old/path'" "from './new/path'"
```

### Add Parameter
```bash
fastmod 'doSomething\((.*?)\)' 'doSomething(${1}, newParam)'
```

### JSX Prop Rename
```bash
fastmod '<Button type=' '<Button variant='
```

### CSS Class Rename
```bash
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
| No matches found | Check pattern syntax, file extensions, directory |
| Too many matches | Add more context to pattern, use word boundaries |
| Pattern invalid | Verify Rust regex syntax (no lookahead/lookbehind) |
| Replacement wrong | Use `${1}` for capture groups, `$$` for literal `$` |

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

**Good for:**
- 20+ files with similar changes
- Pattern-based refactoring
- Human review needed

**Not ideal for:**
- 1-3 files (use IDE)
- Semantic changes (use AST tools)
- Full automation (use sed)

## Rollback

```bash
git restore .            # Undo all
git restore path/to/file # Undo file
git stash                # Stash for later
```
