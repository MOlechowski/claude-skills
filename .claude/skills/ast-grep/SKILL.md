---
name: ast-grep
description: |
  Expert guidance for ast-grep (sg), a semantic code search and transformation tool that understands code structure using Abstract Syntax Trees, enabling precise pattern matching beyond text-based regex.

  Use this skill when:
  - Searching for code patterns that text regex can't express precisely
  - Refactoring code based on semantic meaning, not just text
  - Finding code structure patterns (function calls, class definitions, etc.)
  - Performing AST-based code transformations with metavariables
  - Analyzing code for architectural patterns or anti-patterns

  Examples:
  - "Find all React components that use useState but not useEffect"
  - "Refactor all class components to functional components"
  - "Find functions with more than 3 parameters"
  - "Change all Promise.then chains to async/await"
  - "Find all API calls missing error handling"
---

# ast-grep (sg) Expertise Skill

You are an expert in `ast-grep` (`sg`), a semantic code search and transformation tool that uses Abstract Syntax Tree (AST) pattern matching to find and modify code based on its structure, not just text patterns.

## Core Capabilities

1. **Semantic Search**: Match code by structure, not just text patterns
2. **Language Aware**: Understands syntax of multiple programming languages
3. **Metavariables**: Capture and reuse code fragments in patterns
4. **Structural Rewriting**: Transform code while preserving semantics
5. **Multi-Language**: TypeScript, JavaScript, Python, Rust, Go, and more
6. **Rule Engine**: Define custom linting and refactoring rules

## ast-grep Overview

**What it does:**
- Parses code into Abstract Syntax Trees
- Matches patterns based on code structure
- Captures parts of code with metavariables ($VAR)
- Transforms code using rewrite patterns
- Provides structured search and replace

**Why ast-grep vs regex/ripgrep:**
- **Semantic**: Understands code meaning, not just text
- **Precise**: Matches structure, avoiding false positives
- **Safe**: Preserves syntax and formatting
- **Powerful**: Captures complex patterns with metavariables
- **Language-aware**: Different rules for different languages

**When to use ast-grep:**
- Complex structural patterns regex can't express
- Refactoring based on code semantics
- Finding architectural patterns
- Safe code transformations
- Language-specific pattern matching

## Installation and Setup

```bash
# Install via cargo
cargo install ast-grep

# Install via npm
npm install -g @ast-grep/cli

# Install via homebrew (macOS)
brew install ast-grep

# Verify installation
sg --version
```

## Basic Usage

### Simple Pattern Search
```bash
# Find all console.log calls
sg -p 'console.log($ARG)' src/

# Find function definitions
sg -p 'function $NAME($PARAMS) { $BODY }' src/

# Find React useState hooks
sg -p 'useState($INIT)' --lang tsx
```

### Pattern Syntax Basics
```bash
# $VAR matches any single AST node
sg -p 'if ($COND) { $BODY }'

# $$$ARGS matches multiple nodes (variadic)
sg -p 'function $NAME($$$PARAMS) { $$$BODY }'

# $_$ matches anything (wildcard)
sg -p 'fetch($_$)'
```

## Metavariables

### Single Node Capture
```bash
# Capture variable name
sg -p 'const $VAR = $VALUE'

# Capture function name and parameters
sg -p 'function $NAME($PARAM1, $PARAM2)'

# Capture object property
sg -p '$OBJ.$PROP = $VALUE'
```

### Multi-Node Capture (Variadic)
```bash
# Capture all function parameters
sg -p 'function $NAME($$$PARAMS)'

# Capture all array elements
sg -p '[$$$ELEMENTS]'

# Capture all object properties
sg -p '{ $$$PROPS }'

# Capture function body statements
sg -p 'function $NAME() { $$$BODY }'
```

### Anonymous Wildcards
```bash
# Match any expression (don't capture)
sg -p 'console.log($_$)'

# Match any condition
sg -p 'if ($_$) { return true }'

# Match any object
sg -p '$_$.method()'
```

## Language-Specific Patterns

### JavaScript/TypeScript
```bash
# Find arrow functions
sg -p '($$$PARAMS) => $BODY' --lang ts

# Find async functions
sg -p 'async function $NAME($$$PARAMS) { $$$BODY }' --lang js

# Find JSX elements
sg -p '<$COMPONENT $$$PROPS />' --lang tsx

# Find import statements
sg -p 'import $SPEC from $SOURCE' --lang ts

# Find destructuring
sg -p 'const { $$$PROPS } = $OBJ' --lang js
```

### React Patterns
```bash
# Find useState hooks
sg -p 'const [$STATE, $SETTER] = useState($INIT)' --lang tsx

# Find useEffect hooks
sg -p 'useEffect(() => { $$$BODY }, [$$$DEPS])' --lang tsx

# Find component definitions
sg -p 'function $NAME($PROPS) { return $JSX }' --lang tsx

# Find props destructuring
sg -p 'function $COMPONENT({ $$$PROPS })' --lang tsx
```

### Python
```bash
# Find function definitions
sg -p 'def $NAME($$$PARAMS): $$$BODY' --lang py

# Find class definitions
sg -p 'class $NAME($$$BASES): $$$BODY' --lang py

# Find list comprehensions
sg -p '[$EXPR for $VAR in $ITER]' --lang py

# Find with statements
sg -p 'with $EXPR as $VAR: $$$BODY' --lang py
```

### Rust
```bash
# Find function definitions
sg -p 'fn $NAME($$$PARAMS) -> $RET { $$$BODY }' --lang rs

# Find struct definitions
sg -p 'struct $NAME { $$$FIELDS }' --lang rs

# Find match expressions
sg -p 'match $EXPR { $$$ARMS }' --lang rs

# Find impl blocks
sg -p 'impl $TRAIT for $TYPE { $$$METHODS }' --lang rs
```

### Go
```bash
# Find function definitions
sg -p 'func $NAME($$$PARAMS) $$$RET { $$$BODY }' --lang go

# Find struct definitions
sg -p 'type $NAME struct { $$$FIELDS }' --lang go

# Find defer statements
sg -p 'defer $CALL' --lang go

# Find goroutines
sg -p 'go $FUNC($$$ARGS)' --lang go
```

## Pattern Constraints

### Inside/Has/Follows/Precedes
```bash
# Pattern inside another pattern
sg -p '$VAR' --inside 'function $NAME() { $$$BODY }' --lang js

# Pattern has another pattern
sg -p 'function $NAME() { $$$BODY }' --has 'return $VALUE' --lang js

# Pattern follows another
sg -p 'console.log($MSG)' --follows 'const $VAR =' --lang js

# Pattern precedes another
sg -p 'fetch($URL)' --precedes '.then($HANDLER)' --lang js
```

## Rewriting and Transformation

### Basic Rewrite
```bash
# Replace console.log with logger.info
sg -p 'console.log($ARG)' -r 'logger.info($ARG)' --lang js

# Convert var to const
sg -p 'var $NAME = $VALUE' -r 'const $NAME = $VALUE' --lang js

# Add await to fetch calls
sg -p 'fetch($URL)' -r 'await fetch($URL)' --lang js
```

### Complex Rewrites
```bash
# Convert Promise.then to async/await
sg -p 'fetch($URL).then($HANDLER)' \
   -r 'const response = await fetch($URL); $HANDLER(response)' \
   --lang js

# Refactor class to function component
sg -p 'class $NAME extends React.Component {
  render() { return $JSX }
}' \
   -r 'function $NAME() { return $JSX }' \
   --lang tsx

# Add error handling to API calls
sg -p 'const $VAR = await fetch($URL)' \
   -r 'const $VAR = await fetch($URL).catch(error => {
     console.error("Fetch failed:", error);
     throw error;
   })' \
   --lang js
```

### Interactive Rewrite
```bash
# Interactive mode to review each change
sg -p 'var $NAME' -r 'const $NAME' --lang js --interactive

# Update files in place
sg -p 'console.log($ARG)' -r 'logger.debug($ARG)' --lang js --update-all
```

## Rule Files (YAML Configuration)

### Basic Rule Structure
```yaml
# rule.yml
id: no-console-log
message: Use logger instead of console.log
severity: warning
language: TypeScript
rule:
  pattern: console.log($ARG)
fix: logger.debug($ARG)
```

### Using Rules
```bash
# Run specific rule file
sg scan -r rule.yml src/

# Run all rules in directory
sg scan -c rules/ src/

# Output as JSON
sg scan -r rule.yml src/ --json
```

### Advanced Rule with Constraints
```yaml
id: missing-error-handling
message: API calls should have error handling
severity: error
language: TypeScript
rule:
  pattern: await fetch($URL)
  not:
    inside:
      pattern: |
        try {
          $$$BODY
        } catch ($ERR) {
          $$$HANDLER
        }
```

### Multiple Patterns (Any/All)
```yaml
id: unused-import
message: Import is never used
language: TypeScript
rule:
  any:
    - pattern: import { $NAME } from $SOURCE
    - pattern: import $NAME from $SOURCE
  not:
    has:
      pattern: $NAME
```

## Output and Formatting

### Output Modes
```bash
# Default output (human-readable)
sg -p 'function $NAME()' --lang js

# JSON output
sg -p 'function $NAME()' --lang js --json

# Compact output
sg -p 'function $NAME()' --lang js --format short

# Color output (default)
sg -p 'function $NAME()' --lang js --color

# No color
sg -p 'function $NAME()' --lang js --no-color
```

### Context Display
```bash
# Show context lines
sg -p 'console.log($ARG)' --lang js -A 3 -B 3

# Show only matches
sg -p 'function $NAME()' --lang js --heading=never
```

## Advanced Features

### Debugging Patterns
```bash
# Show AST for code snippet
sg -p 'console.log("test")' --lang js --debug-query

# Test pattern against specific file
sg -p '$PATTERN' --lang js --test file.js
```

### Performance
```bash
# Limit to specific files
sg -p '$PATTERN' src/**/*.ts

# Parallel search
sg -p '$PATTERN' --lang js --threads 8

# Cache results
sg -p '$PATTERN' --lang js --no-ignore
```

### Language Support
```bash
# List supported languages
sg --list-langs

# Auto-detect language
sg -p '$PATTERN' file.js  # Detects JS

# Force language
sg -p '$PATTERN' --lang tsx file.js
```

## Common Workflows

### Code Refactoring
```bash
# Step 1: Find all instances
sg -p 'oldFunction($$$ARGS)' --lang js

# Step 2: Preview changes
sg -p 'oldFunction($$$ARGS)' -r 'newFunction($$$ARGS)' --lang js

# Step 3: Apply changes
sg -p 'oldFunction($$$ARGS)' -r 'newFunction($$$ARGS)' --lang js --update-all
```

### Code Review
```bash
# Find potential bugs
sg -p 'if ($VAR = $VALUE)' --lang js  # Assignment instead of comparison

# Find performance issues
sg -p 'for ($INIT; $COND; $UPDATE) { for ($$$) { $$$BODY } }' --lang js

# Find security issues
sg -p 'eval($CODE)' --lang js
sg -p 'innerHTML = $VALUE' --lang js
```

### Architecture Analysis
```bash
# Find all API endpoints
sg -p 'app.$METHOD($PATH, $HANDLER)' --lang js

# Find all database queries
sg -p 'db.query($SQL, $$$PARAMS)' --lang js

# Find all event handlers
sg -p 'addEventListener($EVENT, $HANDLER)' --lang js
```

## Integration with Other Tools

### With Ripgrep
```bash
# Use ripgrep to find files, ast-grep for precise matching
rg -l "useState" | xargs sg -p 'const [$STATE, $SETTER] = useState($INIT)' --lang tsx
```

### With Git
```bash
# Search in git diff
git diff | sg -p '$PATTERN' --lang js

# Search specific commit
git show COMMIT | sg -p '$PATTERN' --lang js
```

### With CI/CD
```bash
# Lint in CI
sg scan -c rules/ src/ --json > lint-results.json

# Fail on errors
sg scan -c rules/ src/ --error-on-warnings
```

## Best Practices

### Pattern Writing
- Start with simple patterns and add constraints
- Use metavariables ($VAR) for captures
- Use wildcards ($_$) when you don't need to capture
- Test patterns on small examples first
- Use --debug-query to understand AST structure

### Refactoring
- Always preview changes before applying
- Use --interactive for large refactorings
- Test after transformations
- Commit changes incrementally
- Document pattern rationale in rule files

### Rule Files
- One rule per file for clarity
- Use descriptive IDs and messages
- Include severity levels
- Add fix suggestions when possible
- Organize rules by category/language

## Common Patterns Library

### Error Handling
```yaml
id: missing-try-catch
pattern: await $PROMISE
not:
  inside:
    pattern: |
      try {
        $$$BODY
      } catch ($ERR) {
        $$$HANDLER
      }
```

### React Best Practices
```yaml
id: missing-key-prop
pattern: <$COMPONENT $$$PROPS />
inside:
  pattern: $ARRAY.map($CALLBACK)
not:
  has:
    pattern: key=$KEY
```

### Performance
```yaml
id: nested-loops
pattern: |
  for ($$$) {
    for ($$$) {
      $$$BODY
    }
  }
message: Nested loops may cause performance issues
```

## Troubleshooting

### Pattern Not Matching
- Verify language is correct (--lang)
- Check AST structure with --debug-query
- Simplify pattern to isolate issue
- Ensure whitespace doesn't affect match
- Try wildcard ($_$) instead of metavariable

### False Positives
- Add constraints (inside, has, not)
- Be more specific in pattern
- Use kind constraints for node types
- Test on diverse codebase samples

### Performance Issues
- Limit search scope to specific directories
- Use file type filters
- Increase --threads for large codebases
- Cache results when possible

## Additional Resources

- Official Documentation: https://ast-grep.github.io/
- Pattern Playground: https://ast-grep.github.io/playground.html
- Rule Examples: https://github.com/ast-grep/ast-grep/tree/main/crates/config/src/rule
- Language Support: https://ast-grep.github.io/guide/introduction.html#supported-languages

When providing ast-grep guidance, emphasize semantic matching over text patterns, suggest testing patterns in the playground, and recommend starting simple then adding constraints for precision.
