---
name: fastmod
description: "Large-scale codebase refactoring with interactive review. Use for: (1) bulk find-and-replace across 20+ files, (2) renaming classes/functions/variables codebase-wide, (3) updating API calls or import patterns systematically, (4) regex-based transformations with human oversight. Triggers: rename across codebase, bulk replace, update all occurrences, refactor imports."
---

# Fastmod Skill

## Core Capabilities

1. **Pattern Matching**: Precise Rust regex patterns for transformations
2. **Safe Refactoring**: Interactive review of each change
3. **Scope Management**: File filters and directory boundaries
4. **Syntax Expertise**: Rust regex differences from Python/JS
5. **Best Practices**: Safe large-scale refactoring

## Critical Syntax Differences

**IMPORTANT**: fastmod uses Rust regex, NOT Python/JS regex:

### Capture Groups
```bash
# WRONG (Python style)
fastmod 'function (\w+)' 'const \1 ='

# CORRECT (Rust style)
fastmod 'function (\w+)' 'const ${1} ='
```

### Literal Dollar Signs
```bash
# Literal $ requires $$
fastmod 'price' 'cost is $$10'
```

### Not Supported
- Lookahead: `(?=pattern)`
- Lookbehind: `(?<=pattern)`
- Backreferences: `\1` (use `${1}`)

### Shell Quoting
```bash
# Single quotes prevent shell interpretation
fastmod 'pattern' 'replacement'  # Good

# Double quotes require escaping $
fastmod "pattern" "replacement with \$${1}"  # Careful
```

## Basic Usage

```bash
fastmod [OPTIONS] <REGEX_PATTERN> <REPLACEMENT> [PATH]
```

## Essential Options

### Scope Control
```bash
-d <DIR>              # Directory (default: current)
--extensions <EXT>    # Extensions (e.g., js,jsx,ts,tsx)
--iglob <PATTERN>     # Include glob pattern
--exclude-dir <DIR>   # Exclude directory
```

### Pattern Matching
```bash
-i                    # Case-insensitive
-m, --multiline       # Match across lines
```

### Execution Control
```bash
--accept-all          # Non-interactive (test first!)
--print-changed-files # Show modified files
```

## Interactive Workflow

For each match, fastmod shows colored diff and prompts:

- `y` - Accept change
- `n` - Reject change
- `e` - Open in $EDITOR
- `d` - Accept all remaining in file
- `q` - Quit
- `s` - Skip file
- `?` - Help

## Common Refactoring Patterns

### 1. Simple Rename
```bash
fastmod -d src --extensions ts,tsx 'UserManager' 'UserService'
```

### 2. Function Signature Changes
```bash
# Add parameter
fastmod 'authenticate\((.*?)\)' 'authenticate(${1}, context)'

# Update method calls
fastmod '\.save\(\)' '.save({ validateBeforeSave: true })'
```

### 3. Import Path Updates
```bash
fastmod "from '\./utils/old'" "from './utils/new'"
fastmod "from '@/components/old" "from '@/components/new"
```

### 4. Framework Migrations
```bash
fastmod 'size="small"' 'size="sm"'
fastmod 'size="medium"' 'size="md"'
fastmod 'size="large"' 'size="lg"'
```

### 5. API Updates
```bash
fastmod 'fetch\((.*?)\)' 'apiClient.fetch(${1})'
fastmod '/api/v1/' '/api/v2/'
```

### 6. Scoped Refactoring
```bash
fastmod --iglob '**/*Service.ts' 'OldPattern' 'NewPattern'
fastmod --exclude-dir node_modules --exclude-dir dist 'pattern' 'replacement'
```

## Safety Guidelines

### MUST

1. **Test patterns first** on small subset:
   ```bash
   fastmod -d src/components/Button 'pattern' 'replacement'
   ```

2. **Ensure clean git state**:
   ```bash
   git status  # Should be clean
   git stash   # If needed
   ```

3. **Use interactive mode** (default) for new patterns

4. **Review first few matches** before using `d`

5. **Use specific scope** with `--extensions` or `--iglob`

### SHOULD

1. **Start narrow, expand**:
   ```bash
   fastmod -d src/utils 'pattern' 'replacement'
   fastmod -d src 'pattern' 'replacement'
   ```

2. **Use file extensions** to avoid unintended changes

3. **Exclude build/dependency directories**

4. **Test regex** with Rust regex syntax

### MUST NOT

1. Use `--accept-all` without testing
2. Run with uncommitted changes
3. Use broad patterns without filtering
4. Rely on lookahead/lookbehind

### When `--accept-all` IS Safe

All conditions must be met:
1. Clean git state
2. Simple, well-defined patterns
3. Word boundaries (`\b`) used
4. File type filtering applied
5. Test suite available

## Error Recovery

### Pattern Matching Too Much
```bash
# Too broad
fastmod 'user' 'customer'  # Matches "username"

# More specific
fastmod '\buser\b' 'customer'  # Whole word only
```

### Partial Refactoring
```bash
git status        # See changed files
git restore .     # Undo all
```

### Compilation Errors
```bash
npm run build             # Identify failures
git diff path/to/file.ts  # Review changes
git restore path/to/file.ts  # Revert if needed
```

## Advanced Patterns

### Multi-Step Refactoring
```bash
# 1: Class definitions
fastmod 'class UserManager' 'class UserService'

# 2: Imports
fastmod 'import.*UserManager' 'import { UserService }'

# 3: Usages
fastmod 'UserManager' 'UserService'

# 4: File names (manual)
git mv src/UserManager.ts src/UserService.ts
```

### Complex Patterns
```bash
# Multiple capture groups
fastmod 'function (\w+)\((.*?)\)' 'const ${1} = (${2}) =>'

# Preserve whitespace
fastmod 'if\s*\((.*?)\)\s*{' 'if (${1}) {'
```

## Workflow Integration

### Pre-Refactoring
```bash
git status                              # Clean state
git checkout -b refactor/update-name    # Checkpoint branch
npm test                                # Baseline
fastmod -d src --extensions ts,tsx 'pattern' 'replacement'
```

### Post-Refactoring
```bash
git status && git diff   # Check changes
npm run build            # Verify build
npm test                 # Run tests
git add -A && git commit -m "refactor: rename UserManager to UserService"
```

## Troubleshooting

### "No matches found"
- Verify pattern with test file
- Check extensions filter
- Try `-i` for case-insensitive

### "Pattern is invalid"
- Test at https://regex101.com (Rust flavor)
- Check for unsupported features

### "Replacement has syntax errors"
- Use `${1}` not `\1`
- Use `$$` for literal `$`
- Prefer single quotes

## Resources

See `examples.md` and `quick-reference.md`.

- Fastmod: https://github.com/facebookincubator/fastmod
- Rust Regex: https://docs.rs/regex/latest/regex/#syntax
