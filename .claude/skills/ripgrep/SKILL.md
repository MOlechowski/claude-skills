---
name: ripgrep
description: Fast recursive code search. Use for: (1) searching large codebases for patterns, (2) finding code references and function calls, (3) filtering by file type or path, (4) security audits and pattern detection. Triggers: search codebase, find occurrences, grep files, search for pattern, find all usages.
---

# ripgrep (rg) Expertise Skill

You are an expert in `ripgrep` (`rg`), a fast line-oriented search tool that recursively searches directories for a regex pattern while respecting gitignore rules and providing smart defaults for developers.

## Core Capabilities

1. **Lightning Fast Search**: Multi-threaded parallel search optimized for large codebases
2. **Smart Filtering**: Automatic respect for `.gitignore`, `.ignore`, and file type detection
3. **Context Display**: Show surrounding lines, file names, line numbers, and match highlighting
4. **Advanced Patterns**: Full regex support with multiple pattern matching
5. **Binary Safety**: Automatically skip binary files unless explicitly requested
6. **Replacement**: Preview and execute find-and-replace operations

## ripgrep Overview

**What it does:**
- Recursively searches directories for regex patterns
- Respects `.gitignore` and other ignore files by default
- Automatically skips binary files and hidden files
- Provides colored output with smart highlighting
- Supports file type filtering (--type) and glob patterns
- Multi-threaded for maximum performance

**When to use ripgrep:**
- Searching large codebases (faster than grep, ag, ack)
- Finding code patterns across many files
- Refactoring code by finding all usages
- Security audits and vulnerability scanning
- Documentation and comment searches

**Why ripgrep vs alternatives:**
- **Faster** than grep, ack, ag (silver searcher)
- **Smarter defaults** (respects gitignore, skips binaries)
- **Better output** (colors, line numbers, context)
- **Type filtering** (--type js, --type py)

## Basic Usage

### Simple Search
```bash
# Search for pattern in current directory
rg "pattern"

# Search with case insensitivity
rg -i "pattern"

# Search for whole words only
rg -w "function"

# Fixed string search (no regex)
rg -F "function()"
```

### Common Options
```bash
# Show line numbers (default)
rg -n "pattern"

# Show file names only (no matches)
rg -l "pattern"

# Count matches per file
rg -c "pattern"

# Show context lines
rg -C 3 "pattern"          # 3 before and after
rg -B 2 "pattern"          # 2 before
rg -A 1 "pattern"          # 1 after
```

## File Type Filtering

### Using --type
```bash
# Search only JavaScript files
rg --type js "pattern"

# Multiple types
rg --type js --type ts "pattern"

# Short form
rg -tjs -tts "pattern"

# List available types
rg --type-list

# Common types: js, ts, py, rust, go, java, cpp, html, css, json, yaml
```

### Type Negation
```bash
# Exclude specific types
rg --type-not js "pattern"

# Exclude multiple types
rg -Tjs -Tcss "pattern"
```

### Custom Type Definitions
```bash
# Add custom type
rg --type-add 'config:*.{yml,yaml,toml,json}' -tconfig "database"
```

## Path and File Filtering

### Glob Patterns
```bash
# Include specific paths
rg -g '*.js' "pattern"
rg -g 'src/**/*.ts' "pattern"

# Exclude paths
rg -g '!tests/' "pattern"
rg -g '!*.min.js' "pattern"

# Multiple globs
rg -g '*.{js,ts}' -g '!node_modules/' "pattern"
```

### Specific Directories
```bash
# Search only in specific directory
rg "pattern" src/

# Multiple directories
rg "pattern" src/ lib/

# Exclude directories
rg "pattern" --glob '!node_modules/**'
```

### Hidden and Ignored Files
```bash
# Include hidden files
rg --hidden "pattern"

# Include ignored files (.gitignore)
rg --no-ignore "pattern"

# Include everything
rg --hidden --no-ignore "pattern"
```

## Advanced Regex Patterns

### Basic Regex
```bash
# Anchors
rg "^import"              # Start of line
rg ";\$"                  # End of line

# Character classes
rg "[0-9]+"               # One or more digits
rg "[a-zA-Z_]\w*"         # Identifier pattern

# Quantifiers
rg "colou?r"              # Optional 'u'
rg "\d{3}-\d{4}"          # 3 digits, dash, 4 digits
```

### Advanced Patterns
```bash
# Word boundaries
rg "\bfunction\b"         # Whole word 'function'

# Alternation
rg "error|warning|fatal"  # Multiple patterns

# Groups
rg "(get|set)User"        # Matches getUser or setUser
```

### Multi-line Patterns
```bash
# Enable multiline mode
rg -U "function.*{.*return" file.js

# Across multiple lines with context
rg -U "class \w+ {[\s\S]*?constructor" src/
```

## Output Formatting

### Display Options
```bash
# No line numbers
rg --no-line-number "pattern"

# No filename
rg --no-filename "pattern"

# Only filename (no matches)
rg -l "pattern"

# Only matches (no filename or line numbers)
rg --only-matching "pattern"
```

### Colors and Highlighting
```bash
# Force colors (for piping)
rg --color always "pattern"

# No colors
rg --color never "pattern"
```

### JSON Output
```bash
# Output as JSON
rg --json "pattern"

# Pretty JSON
rg --json "pattern" | jq '.'
```

## Context and Grouping

### Context Lines
```bash
# Show context around matches
rg -C 3 "error"           # 3 lines before and after
rg -B 5 "TODO"            # 5 lines before
rg -A 2 "FIXME"           # 2 lines after
```

## Replace Operations

### Preview Replacements
```bash
# See what would be replaced
rg "old_name" --replace "new_name"

# With context
rg -C 1 "old_name" --replace "new_name"
```

### Execute Replacements
```bash
# Using sed with ripgrep
rg -l "old_pattern" | xargs sed -i '' 's/old_pattern/new_pattern/g'

# Using fastmod (safer)
rg -l "old_pattern" | xargs fastmod "old_pattern" "new_pattern"
```

## Performance Optimization

### Speed Tips
```bash
# Limit search depth
rg --max-depth 3 "pattern"

# Stop after first match per file
rg --max-count 1 "pattern"

# Use fixed strings for speed
rg -F "literal_string"

# Specify file types
rg -tjs "pattern"  # Much faster than searching all files
```

## Integration Patterns

### With Git
```bash
# Search unstaged changes
git diff | rg "pattern"

# Find files changed that contain pattern
rg -l "pattern" $(git diff --name-only)
```

### With Xargs
```bash
# Process matches
rg -l "TODO" | xargs -I {} echo "TODO found in: {}"

# Open files in editor
rg -l "FIXME" | xargs vim
```

### Piping to Other Tools
```bash
# Count unique matches
rg -o "\w+@\w+\.\w+" emails.txt | sort -u | wc -l

# Format output
rg "error" --json | jq -r '.data.lines.text'
```

## Common Workflows

### Find and Review
```bash
# Find all TODOs with context
rg -C 2 "TODO|FIXME|HACK"

# Find security issues
rg -i "password|secret|api_key" --type-not test

# Find deprecated usage
rg "deprecated|obsolete" --stats
```

### Code Analysis
```bash
# Find all function definitions
rg "function \w+\(" -tjs

# Find all imports
rg "^import " -tts

# Find unused variables (combined with other tools)
rg "\bvar \w+" -o | sort | uniq -c | sort -rn
```

### Refactoring Support
```bash
# Find all usages before rename
rg "\boldName\b" -C 1

# Verify rename completeness
rg "oldName" --count-matches

# Find similar patterns
rg "get[A-Z]\w+" -o | sort -u
```

## Configuration

### Config File
```bash
# Create ~/.ripgreprc
--smart-case
--hidden
--glob=!.git/*
--glob=!node_modules/*
--glob=!*.min.js
--type-add=web:*.{html,css,js}
```

### Environment Variable
```bash
# Set config file location
export RIPGREP_CONFIG_PATH=~/.ripgreprc
```

## Debugging and Troubleshooting

### Common Issues

**No matches found:**
```bash
# Check if files are ignored
rg --no-ignore "pattern"

# Check file types
rg --files | head

# Verify pattern
rg --debug "pattern"
```

**Too many matches:**
```bash
# Limit results
rg --max-count 100 "pattern"

# Be more specific
rg "\bpattern\b" -tjs -g 'src/**'
```

## Best Practices

### DO
- Use `--type` to narrow searches to relevant files
- Leverage `.gitignore` (default behavior)
- Use `--smart-case` for case-insensitive when pattern is lowercase
- Preview replacements before executing
- Use `--stats` to understand search scope

### DON'T
- Search all files when you can specify types
- Forget to escape regex special characters
- Use `.*` when you can be more specific
- Ignore performance with `--no-ignore` unless necessary

## Examples by Use Case

### Security Auditing
```bash
# Find hardcoded credentials
rg -i "password\s*=|api_key\s*=" --type-not test

# Find SQL injection risks
rg "execute.*\+.*" -tpy -tjs

# Find XSS vulnerabilities
rg "innerHTML|outerHTML" -tjs -tts
```

### Performance Analysis
```bash
# Find console.log statements
rg "console\.(log|warn|error)" -tjs -tts

# Find TODO performance items
rg "TODO.*performance|PERF:" -i
```

## Additional Resources

For detailed examples and reference, see `examples.md` and `quick-reference.md`.

- Official Manual: https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md
- Performance Guide: https://blog.burntsushi.net/ripgrep/

When providing ripgrep guidance, prioritize performance with smart filtering (--type, -g), respect user's gitignore by default, and suggest preview before destructive operations.
