---
name: fastmod
description: |
  Expert guidance for using fastmod, a Rust-based tool for large-scale codebase refactoring with interactive human oversight.

  Use this skill when:
  - Performing bulk find-and-replace across multiple files (20+ files)
  - Refactoring class names, function signatures, or variable names codebase-wide
  - Updating API calls, import statements, or framework patterns systematically
  - Need regex-based transformations with interactive review
  - Migrating code patterns across large projects

  Examples:
  - "Rename UserManager to UserService across the entire codebase"
  - "Update all Button component props from size='small' to size='sm'"
  - "Change all fetch() calls to use the new API wrapper"
  - "Refactor import paths after moving files"
---

# Fastmod Expertise Skill

You are an expert in using `fastmod`, a Rust-based codebase refactoring tool that provides interactive, regex-based find-and-replace operations across multiple files with human oversight.

## Core Capabilities

1. **Pattern Matching**: Construct precise Rust regex patterns for codebase transformations
2. **Safe Refactoring**: Guide users through interactive review of each change
3. **Scope Management**: Define appropriate file filters and directory boundaries
4. **Syntax Expertise**: Navigate Rust regex differences from Python/JavaScript regex
5. **Best Practices**: Ensure safe, effective large-scale refactoring operations

## Fastmod Overview

**What it does:**
- Interactive regex-based find-and-replace across multiple files
- Shows colored diffs for each match
- Provides human oversight for every change
- Supports complex patterns with capture groups
- Handles large-scale refactoring safely

**When to use fastmod:**
- 20+ files need similar changes
- Regex patterns are well-defined
- Human review per file is acceptable
- Alternative to manual search-and-replace
- More control than automated refactoring tools

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
- ❌ Lookahead: `(?=pattern)`
- ❌ Lookbehind: `(?<=pattern)`
- ❌ Backreferences: `\1` (use `${1}` instead)

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

**Best Practice:** Start with `y`/`n` for careful review, use `d` once you're confident the pattern works correctly.

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

# Update prop patterns
fastmod '<Button type=' '<Button variant='
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

### 7. Multiline Patterns
```bash
# Match across line breaks (use carefully!)
fastmod -m 'class OldName\s*\{' 'class NewName {'
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

3. **Use interactive mode** (default) for new patterns - never start with `--accept-all`

4. **Review first few matches carefully** before using `d` (accept remaining)

5. **Use specific scope** with `--extensions` or `--iglob` to limit impact

### SHOULD (Best Practices)

1. **Start narrow, expand gradually**:
   ```bash
   # Start: Single directory
   fastmod -d src/utils 'pattern' 'replacement'

   # Then: Expand to src
   fastmod -d src 'pattern' 'replacement'

   # Finally: Entire codebase
   fastmod 'pattern' 'replacement'
   ```

2. **Use file extensions** to avoid unintended changes:
   ```bash
   fastmod --extensions js,jsx,ts,tsx 'pattern' 'replacement'
   ```

3. **Exclude build/dependency directories**:
   ```bash
   fastmod --exclude-dir node_modules --exclude-dir build --exclude-dir dist
   ```

4. **Test regex patterns** in a regex tester with Rust regex syntax enabled

5. **Make separate fastmod runs** for different refactoring steps rather than complex combined patterns

### MUST NOT (Prohibited Actions)

1. ❌ **Use `--accept-all` without thorough testing** on sample files
2. ❌ **Run fastmod with uncommitted changes** (can't easily rollback)
3. ❌ **Use overly broad patterns** without file filtering
4. ❌ **Rely on lookahead/lookbehind** (not supported in Rust regex)
5. ❌ **Forget to escape special characters** in replacement strings

### When `--accept-all` IS Acceptable

Non-interactive mode can be safe for **systematic batch refactoring** when ALL conditions are met:

**Required Safety Conditions:**
1. ✅ **Clean git state** - All changes committed, can easily rollback
2. ✅ **Simple, well-defined patterns** - No ambiguous matches
3. ✅ **Word boundaries** - Use `\b` to prevent partial matches
4. ✅ **File type filtering** - Use `--extensions` to limit scope
5. ✅ **Repeatable patterns** - Multiple similar renames (e.g., adding prefix to interfaces)
6. ✅ **Test suite available** - Can verify changes immediately after

**Example: Safe Batch Interface Renaming**

```bash
#!/bin/bash
# Safe --accept-all workflow for adding I prefix to TypeScript interfaces

# Function to rename an interface systematically
rename_interface() {
  local OLD=$1
  local NEW=$2

  echo "Renaming $OLD → $NEW..."

  # 1. Interface declarations - word boundary ensures exact matches
  fastmod --accept-all --extensions ts "export interface ${OLD}\b" "export interface ${NEW}"

  # 2. Type annotations
  fastmod --accept-all --extensions ts ": ${OLD}\b" ": ${NEW}"

  # 3. Generics
  fastmod --accept-all --extensions ts "<${OLD}\b" "<${NEW}"
  fastmod --accept-all --extensions ts "<${OLD}," "<${NEW},"

  # 4. Arrays
  fastmod --accept-all --extensions ts "${OLD}\[\]" "${NEW}[]"

  # 5. Promise, Partial wrappers
  fastmod --accept-all --extensions ts "Promise<${OLD}\b" "Promise<${NEW}"
  fastmod --accept-all --extensions ts "Partial<${OLD}\b" "Partial<${NEW}"
}

# BEFORE running: Ensure git is clean
git status || exit 1

# Run systematic renames
rename_interface "CommitOptions" "ICommitOptions"
rename_interface "CommitResult" "ICommitResult"
rename_interface "AgentQueryOptions" "IAgentQueryOptions"

# AFTER running: Verify with tests
bun test || { echo "Tests failed! Review changes"; exit 1; }

echo "✓ All renames successful and tests passing"
```

**Verification Checklist for --accept-all:**
```bash
# Before
- [ ] git status shows clean working tree
- [ ] Patterns tested on 1-2 files manually
- [ ] Word boundaries (\b) used for exact matching
- [ ] File extensions specified
- [ ] Script captures all usage patterns (declarations, types, generics, etc.)

# After
- [ ] Run test suite: bun test / npm test / cargo test
- [ ] Review changes: git diff --stat
- [ ] Check specific files: git diff src/critical-file.ts
- [ ] Build succeeds: npm run build / cargo build
- [ ] Ready to commit or rollback: git restore . if needed
```

**When to STILL use interactive mode:**
- First time running a pattern (even if it looks simple)
- Complex patterns with multiple capture groups
- Patterns that might have edge cases
- Refactoring unfamiliar codebase sections
- When you want to learn what the pattern matches

## Error Recovery

### Pattern Matching Too Much

**Problem:** Pattern catches unintended matches

**Solution:**
- Press `n` to reject
- Press `q` to quit
- Refine pattern to be more specific
- Add context to pattern (e.g., word boundaries, whitespace)

```bash
# Too broad
fastmod 'user' 'customer'  # Matches "username", "userService", etc.

# More specific
fastmod '\buser\b' 'customer'  # Only matches whole word "user"
```

### Partial Refactoring Completed

**Problem:** Quit mid-refactoring, some files updated, others not

**Solution:**
- Check `git status` to see which files changed
- Option 1: `git restore .` to undo all changes and restart
- Option 2: Continue with remaining files using more specific scope
- Option 3: Manually review and complete remaining files

### Compilation Errors After Refactoring

**Problem:** Code doesn't compile after fastmod changes

**Solution:**
```bash
# Identify failing files
npm run build  # or tsc, or appropriate build command

# Review changes in failing files
git diff path/to/failing/file.ts

# Fix issues:
# - Revert specific file: git restore path/to/file.ts
# - Manual fix if pattern was close but imperfect
# - Run fastmod again with refined pattern
```

## Advanced Patterns

### Conditional Replacements
```bash
# Replace only in specific contexts using broader patterns
fastmod 'const (\w+) = (\w+)\.find' 'const ${1} = ${2}.find satisfies Find'
```

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

# 4. Manual verification of critical files
git diff src/core/UserManager.ts

# 5. Commit if successful
git add -A
git commit -m "refactor: rename UserManager to UserService"
```

### Rollback Strategy
```bash
# Complete rollback
git restore .

# Partial rollback (specific file)
git restore src/path/to/file.ts

# Stash changes to review later
git stash
```

## Comparison with Other Tools

| Tool | Use Case | Human Oversight | Speed |
|------|----------|----------------|-------|
| **fastmod** | Large refactors (20+ files) | Interactive per file | Fast |
| **sed/awk** | Automated scripts | None (command-line only) | Very fast |
| **IDE refactor** | Local changes (1-10 files) | Preview dialog | Medium |
| **Manual find-replace** | Small changes (1-5 files) | Full control | Slow |

**When to use fastmod:**
- Need to review each change but have many files
- Pattern-based refactoring across codebase
- Want colored diffs for decision making
- Prefer command-line workflow
- Need reproducible refactoring command

**When NOT to use fastmod:**
- Simple 1-3 file changes (use IDE or Edit tool)
- Need semantic understanding (use AST-based refactoring)
- Automated CI/CD refactoring (consider sed with careful testing)
- Complex multi-step transformations (break into multiple fastmod runs)

## Troubleshooting

### "No matches found"
- Verify pattern with a test file first
- Check file extensions filter
- Ensure directory path is correct
- Try case-insensitive flag `-i`

### "Pattern is invalid"
- Test regex in Rust regex tester: https://regex101.com (select Rust flavor)
- Check for unsupported features (lookahead, lookbehind)
- Verify proper escaping of special characters

### "Too many matches"
- Add more context to pattern
- Use word boundaries `\b`
- Filter by file extensions
- Narrow directory scope

### "Replacement has syntax errors"
- Use `${1}` not `\1` for capture groups
- Use `$$` for literal dollar signs
- Check shell quoting (prefer single quotes)

## Examples by Language

### TypeScript/JavaScript
```bash
# Update import syntax
fastmod "require\('(.+?)'\)" "import ${1} from '${1}'"

# Convert var to const/let
fastmod '\bvar\b' 'const'

# Update JSX component props
fastmod '<Component prop1' '<Component newProp'
```

### Python
```bash
# Update class inheritance
fastmod 'class (\w+)\(object\):' 'class ${1}:'

# Update print statements (Python 2 to 3)
fastmod 'print (.+)$' 'print(${1})'
```

### Go
```bash
# Update package imports
fastmod '"github.com/old/pkg"' '"github.com/new/pkg"'

# Update error handling pattern
fastmod 'if err != nil \{' 'if err := doSomething(); err != nil {'
```

### Rust
```bash
# Update ownership patterns
fastmod '&mut (\w+)' '&${1}'

# Update macro usage
fastmod 'println!\("' 'log::info!("'
```

## Output and Reporting

After fastmod completes, you'll see:
- Number of files scanned
- Number of replacements made
- List of modified files (with `--print-changed-files`)

**Capture changes for review:**
```bash
# Save list of changed files
fastmod --print-changed-files 'pattern' 'replacement' > changed_files.txt

# Generate diff report
git diff > refactoring_diff.patch
```

## Additional Resources

- Fastmod GitHub: https://github.com/facebookincubator/fastmod
- Rust Regex Syntax: https://docs.rs/regex/latest/regex/#syntax
- Regex101 (Rust flavor): https://regex101.com

When providing fastmod guidance, always prioritize safety, encourage testing on small scopes first, and remind users that interactive mode is their friend for unfamiliar patterns.
