---
name: fastmod
description: "Large-scale codebase refactoring with interactive review. Use for: (1) bulk find-and-replace across 20+ files, (2) renaming classes/functions/variables codebase-wide, (3) updating API calls or import patterns systematically, (4) regex-based transformations with human oversight. Triggers: rename across codebase, bulk replace, update all occurrences, refactor imports."
---

# Fastmod Skill

## Core Capabilities

1. **Pattern Matching**: Construct precise Rust regex patterns for codebase transformations
2. **Safe Refactoring**: Guide users through interactive review of each change
3. **Scope Management**: Define appropriate file filters and directory boundaries
4. **Syntax Expertise**: Navigate Rust regex differences from Python/JavaScript regex
5. **Best Practices**: Ensure safe, effective large-scale refactoring operations

## Critical Syntax Differences

**IMPORTANT**: fastmod uses Rust regex, NOT Python/JavaScript regex:

### Capture Groups
```bash
# WRONG (Python style)
fastmod 'function (\w+)' 'const \1 ='

# CORRECT (Rust style)
fastmod 'function (\w+)' 'const ${1} ='
```

### Literal Dollar Signs
```bash
# To write a literal $
fastmod 'price' 'cost is $$10'  # Use $$
```

### Not Supported in Rust Regex
- Lookahead: `(?=pattern)`
- Lookbehind: `(?<=pattern)`
- Backreferences: `\1` (use `${1}` instead)

### Shell Quoting
```bash
# Use single quotes to prevent shell interpretation
fastmod 'pattern' 'replacement'  # Good

# Double quotes require escaping $
fastmod "pattern" "replacement with \$${1}"  # Careful!
```

## Basic Usage Pattern

```bash
fastmod [OPTIONS] <REGEX_PATTERN> <REPLACEMENT> [PATH]
```

## Essential Options

### Scope Control
```bash
-d <DIR>              # Directory to search (default: current)
--extensions <EXT>    # Comma-separated file extensions (e.g., js,jsx,ts,tsx)
--iglob <PATTERN>     # Include files matching glob pattern
--exclude-dir <DIR>   # Exclude directory from search
```

### Pattern Matching
```bash
-i                    # Case-insensitive matching
-m, --multiline       # Allow patterns to match across multiple lines
```

### Execution Control
```bash
--accept-all          # Non-interactive mode (DANGEROUS - test first!)
--print-changed-files # Show which files were modified
```

## Interactive Workflow

For each match, fastmod shows a colored diff and prompts:

**Options:**
- `y` - Accept this change
- `n` - Reject this change
- `e` - Open in $EDITOR to manually edit
- `d` - Accept this and all remaining changes in file
- `q` - Quit (stop processing all files)
- `s` - Skip this file entirely
- `?` - Show help

## Common Refactoring Patterns

### 1. Simple Rename
```bash
# Rename class across codebase
fastmod -d src --extensions ts,tsx 'UserManager' 'UserService'
```

### 2. Function Signature Changes
```bash
# Add parameter to function calls
fastmod 'authenticate\((.*?)\)' 'authenticate(${1}, context)'

# Update method calls
fastmod '\.save\(\)' '.save({ validateBeforeSave: true })'
```

### 3. Import Path Updates
```bash
# Update import paths after moving files
fastmod "from '\./utils/old'" "from './utils/new'"
fastmod "from '@/components/old" "from '@/components/new"
```

### 4. Framework Migrations
```bash
# Update React prop names
fastmod 'size="small"' 'size="sm"'
fastmod 'size="medium"' 'size="md"'
fastmod 'size="large"' 'size="lg"'
```

### 5. API Call Updates
```bash
# Wrap existing API calls
fastmod 'fetch\((.*?)\)' 'apiClient.fetch(${1})'

# Update endpoint URLs
fastmod '/api/v1/' '/api/v2/'
```

### 6. Scoped Refactoring
```bash
# Only affect specific file types
fastmod --iglob '**/*Service.ts' 'OldPattern' 'NewPattern'

# Exclude directories
fastmod --exclude-dir node_modules --exclude-dir dist 'pattern' 'replacement'
```

## Safety Guidelines

### MUST (Critical Safety Rules)

1. **Always test patterns first** on a small subset:
   ```bash
   # Test on single directory first
   fastmod -d src/components/Button 'pattern' 'replacement'
   ```

2. **Ensure clean git state** before starting:
   ```bash
   git status  # Should be clean
   git stash   # If needed
   ```

3. **Use interactive mode** (default) for new patterns

4. **Review first few matches carefully** before using `d` (accept remaining)

5. **Use specific scope** with `--extensions` or `--iglob` to limit impact

### SHOULD (Best Practices)

1. **Start narrow, expand gradually**:
   ```bash
   # Start: Single directory
   fastmod -d src/utils 'pattern' 'replacement'

   # Then: Expand to src
   fastmod -d src 'pattern' 'replacement'
   ```

2. **Use file extensions** to avoid unintended changes

3. **Exclude build/dependency directories**

4. **Test regex patterns** in a regex tester with Rust regex syntax

### MUST NOT (Prohibited Actions)

1. Use `--accept-all` without thorough testing
2. Run fastmod with uncommitted changes
3. Use overly broad patterns without file filtering
4. Rely on lookahead/lookbehind (not supported)

### When `--accept-all` IS Acceptable

Non-interactive mode can be safe when ALL conditions are met:
1. Clean git state
2. Simple, well-defined patterns
3. Word boundaries (`\b`) used
4. File type filtering applied
5. Test suite available to verify

## Error Recovery

### Pattern Matching Too Much
- Press `n` to reject
- Press `q` to quit
- Refine pattern to be more specific

```bash
# Too broad
fastmod 'user' 'customer'  # Matches "username", "userService", etc.

# More specific
fastmod '\buser\b' 'customer'  # Only matches whole word "user"
```

### Partial Refactoring Completed
- Check `git status` to see which files changed
- Option 1: `git restore .` to undo all and restart
- Option 2: Continue with remaining files

### Compilation Errors After Refactoring
```bash
# Identify failing files
npm run build

# Review changes in failing files
git diff path/to/failing/file.ts

# Revert specific file if needed
git restore path/to/file.ts
```

## Advanced Patterns

### Multi-Step Refactoring
```bash
# Step 1: Update class definitions
fastmod 'class UserManager' 'class UserService'

# Step 2: Update imports
fastmod 'import.*UserManager' 'import { UserService }'

# Step 3: Update all usages
fastmod 'UserManager' 'UserService'

# Step 4: Update file names (manual)
git mv src/UserManager.ts src/UserService.ts
```

### Capturing Complex Patterns
```bash
# Capture and reuse multiple groups
fastmod 'function (\w+)\((.*?)\)' 'const ${1} = (${2}) =>'

# Preserve whitespace patterns
fastmod 'if\s*\((.*?)\)\s*{' 'if (${1}) {'
```

## Integration with Development Workflow

### Pre-Refactoring Checklist
```bash
# 1. Clean git state
git status

# 2. Create checkpoint branch (optional but recommended)
git checkout -b refactor/update-user-manager

# 3. Run tests to establish baseline
npm test

# 4. Prepare fastmod command
fastmod -d src --extensions ts,tsx 'pattern' 'replacement'
```

### Post-Refactoring Validation
```bash
# 1. Check what changed
git status
git diff

# 2. Verify build
npm run build

# 3. Run tests
npm test

# 4. Commit if successful
git add -A
git commit -m "refactor: rename UserManager to UserService"
```

## Troubleshooting

### "No matches found"
- Verify pattern with a test file first
- Check file extensions filter
- Try case-insensitive flag `-i`

### "Pattern is invalid"
- Test regex in Rust regex tester: https://regex101.com (select Rust flavor)
- Check for unsupported features (lookahead, lookbehind)

### "Replacement has syntax errors"
- Use `${1}` not `\1` for capture groups
- Use `$$` for literal dollar signs
- Check shell quoting (prefer single quotes)

## Additional Resources

For detailed examples and reference, see `examples.md` and `quick-reference.md`.

- Fastmod GitHub: https://github.com/facebookincubator/fastmod
- Rust Regex Syntax: https://docs.rs/regex/latest/regex/#syntax
