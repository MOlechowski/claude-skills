# Fastmod Quick Reference

Quick lookup guide for common fastmod patterns and options.

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

During review of each match:

| Key | Action |
|-----|--------|
| `y` | Accept this change |
| `n` | Reject this change |
| `e` | Edit in $EDITOR |
| `d` | Accept this and all remaining in file |
| `q` | Quit fastmod |
| `s` | Skip this entire file |
| `?` | Show help |

## Regex Syntax Reminders

### Rust vs Python/JavaScript

| Feature | Python/JS | Rust (fastmod) |
|---------|-----------|----------------|
| Capture group reference | `\1` | `${1}` |
| Literal `$` | `$` | `$$` |
| Lookahead | `(?=...)` | Not supported |
| Lookbehind | `(?<=...)` | Not supported |

### Common Patterns

```bash
# Word boundary
\b

# Whitespace
\s

# Word character
\w

# Digit
\d

# Any character
.

# Zero or more
*

# One or more
+

# Optional
?

# Capture group
(pattern)

# Non-capturing group
(?:pattern)
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

Before running fastmod:

- [ ] Git status is clean (all changes committed)
- [ ] Pattern tested on small sample
- [ ] Appropriate file extensions specified
- [ ] Excluded build/dependency directories
- [ ] Using interactive mode (not --accept-all)
- [ ] Ready to review each change carefully

After running fastmod:

- [ ] Run build/compile to check for errors
- [ ] Run test suite
- [ ] Review `git diff` for unexpected changes
- [ ] Commit with descriptive message

## Common Issues

| Problem | Solution |
|---------|----------|
| No matches found | Check pattern syntax, file extensions, directory |
| Too many matches | Add more context to pattern, use word boundaries |
| Pattern invalid | Verify Rust regex syntax (no lookahead/lookbehind) |
| Replacement wrong | Use `${1}` for capture groups, `$$` for literal `$` |

## Example Workflow

```bash
# 1. Check git status
git status

# 2. Test pattern on subset
fastmod -d src/components --extensions tsx 'OldComponent' 'NewComponent'

# 3. Review carefully, accept changes

# 4. Expand scope
fastmod -d src --extensions tsx,ts 'OldComponent' 'NewComponent'

# 5. Validate
npm run build && npm test

# 6. Commit
git add -A && git commit -m "refactor: rename OldComponent to NewComponent"
```

## When to Use Fastmod

**Good for:**
- 20+ files need similar changes
- Pattern-based refactoring
- Human review per file desired
- Command-line workflow preferred

**Not ideal for:**
- 1-3 file changes (use IDE or Edit)
- Requires semantic understanding (use AST tools)
- Fully automated scripts (consider sed)
- Complex multi-step logic (break into multiple runs)

## Emergency Rollback

```bash
# Undo all changes
git restore .

# Undo specific file
git restore path/to/file.ts

# Stash to review later
git stash
```
