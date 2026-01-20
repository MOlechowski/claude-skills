---
name: ripgrep
description: "Fast recursive code search. Use for: (1) searching large codebases for patterns, (2) finding code references and function calls, (3) filtering by file type or path, (4) security audits and pattern detection. Triggers: search codebase, find occurrences, grep files, search for pattern, find all usages."
---

# ripgrep (rg) Skill

## Basic Usage

### Simple Search
```bash
rg "pattern"
rg -i "pattern"       # Case insensitive
rg -w "function"      # Whole words only
rg -F "function()"    # Fixed string (no regex)
```

### Common Options
```bash
rg -n "pattern"       # Line numbers (default)
rg -l "pattern"       # File names only
rg -c "pattern"       # Count per file
rg -C 3 "pattern"     # 3 lines context
rg -B 2 "pattern"     # 2 lines before
rg -A 1 "pattern"     # 1 line after
```

## File Type Filtering

### Using --type
```bash
rg --type js "pattern"
rg --type js --type ts "pattern"
rg -tjs -tts "pattern"          # Short form
rg --type-list                  # List types
# Common: js, ts, py, rust, go, java, cpp, html, css, json, yaml
```

### Type Negation
```bash
rg --type-not js "pattern"
rg -Tjs -Tcss "pattern"
```

### Custom Type Definitions
```bash
rg --type-add 'config:*.{yml,yaml,toml,json}' -tconfig "database"
```

## Path and File Filtering

### Glob Patterns
```bash
rg -g '*.js' "pattern"
rg -g 'src/**/*.ts' "pattern"
rg -g '!tests/' "pattern"       # Exclude
rg -g '!*.min.js' "pattern"
rg -g '*.{js,ts}' -g '!node_modules/' "pattern"
```

### Specific Directories
```bash
rg "pattern" src/
rg "pattern" src/ lib/
rg "pattern" --glob '!node_modules/**'
```

### Hidden and Ignored Files
```bash
rg --hidden "pattern"           # Include hidden
rg --no-ignore "pattern"        # Include gitignored
rg --hidden --no-ignore "pattern"
```

## Advanced Regex Patterns

### Basic Regex
```bash
rg "^import"              # Start of line
rg ";\$"                  # End of line
rg "[0-9]+"               # One or more digits
rg "[a-zA-Z_]\w*"         # Identifier
rg "colou?r"              # Optional 'u'
rg "\d{3}-\d{4}"          # Phone pattern
```

### Advanced Patterns
```bash
rg "\bfunction\b"         # Word boundary
rg "error|warning|fatal"  # Alternation
rg "(get|set)User"        # Groups
```

### Multi-line Patterns
```bash
rg -U "function.*{.*return" file.js
rg -U "class \w+ {[\s\S]*?constructor" src/
```

## Output Formatting

### Display Options
```bash
rg --no-line-number "pattern"
rg --no-filename "pattern"
rg -l "pattern"               # Filenames only
rg --only-matching "pattern"  # Matches only
```

### Colors and JSON
```bash
rg --color always "pattern"   # Force colors
rg --color never "pattern"    # No colors
rg --json "pattern"           # JSON output
rg --json "pattern" | jq '.'
```

## Context Lines
```bash
rg -C 3 "error"           # 3 before and after
rg -B 5 "TODO"            # 5 before
rg -A 2 "FIXME"           # 2 after
```

## Replace Operations

### Preview Replacements
```bash
rg "old_name" --replace "new_name"
rg -C 1 "old_name" --replace "new_name"
```

### Execute Replacements
```bash
rg -l "old_pattern" | xargs sed -i '' 's/old_pattern/new_pattern/g'
rg -l "old_pattern" | xargs fastmod "old_pattern" "new_pattern"
```

## Performance Optimization

```bash
rg --max-depth 3 "pattern"    # Limit depth
rg --max-count 1 "pattern"    # First match per file
rg -F "literal_string"        # Fixed string (faster)
rg -tjs "pattern"             # Specify type (faster)
```

## Integration Patterns

### With Git
```bash
git diff | rg "pattern"
rg -l "pattern" $(git diff --name-only)
```

### With Xargs
```bash
rg -l "TODO" | xargs -I {} echo "TODO found in: {}"
rg -l "FIXME" | xargs vim
```

### Piping
```bash
rg -o "\w+@\w+\.\w+" emails.txt | sort -u | wc -l
rg "error" --json | jq -r '.data.lines.text'
```

## Common Workflows

### Find and Review
```bash
rg -C 2 "TODO|FIXME|HACK"
rg -i "password|secret|api_key" --type-not test
rg "deprecated|obsolete" --stats
```

### Code Analysis
```bash
rg "function \w+\(" -tjs
rg "^import " -tts
rg "\bvar \w+" -o | sort | uniq -c | sort -rn
```

### Refactoring Support
```bash
rg "\boldName\b" -C 1
rg "oldName" --count-matches
rg "get[A-Z]\w+" -o | sort -u
```

## Configuration

### Config File (~/.ripgreprc)
```bash
--smart-case
--hidden
--glob=!.git/*
--glob=!node_modules/*
--glob=!*.min.js
--type-add=web:*.{html,css,js}
```

### Environment Variable
```bash
export RIPGREP_CONFIG_PATH=~/.ripgreprc
```

## Troubleshooting

**No matches found:**
```bash
rg --no-ignore "pattern"
rg --files | head
rg --debug "pattern"
```

**Too many matches:**
```bash
rg --max-count 100 "pattern"
rg "\bpattern\b" -tjs -g 'src/**'
```

## Additional Resources

See `examples.md` and `quick-reference.md` for detailed examples.
