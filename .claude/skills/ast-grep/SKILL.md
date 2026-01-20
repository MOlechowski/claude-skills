---
name: ast-grep
description: Semantic code search and transformation using ASTs. Use for: (1) structural pattern matching beyond regex, (2) AST-based refactoring with metavariables, (3) finding architectural patterns or anti-patterns, (4) language-aware code transformations. Triggers: semantic search, find code patterns, refactor class/function structure, AST matching.
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

# Capture function body statements
sg -p 'function $NAME() { $$$BODY }'
```

### Anonymous Wildcards
```bash
# Match any expression (don't capture)
sg -p 'console.log($_$)'

# Match any condition
sg -p 'if ($_$) { return true }'
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
```

### React Patterns
```bash
# Find useState hooks
sg -p 'const [$STATE, $SETTER] = useState($INIT)' --lang tsx

# Find useEffect hooks
sg -p 'useEffect(() => { $$$BODY }, [$$$DEPS])' --lang tsx

# Find component definitions
sg -p 'function $NAME($PROPS) { return $JSX }' --lang tsx
```

### Python
```bash
# Find function definitions
sg -p 'def $NAME($$$PARAMS): $$$BODY' --lang py

# Find class definitions
sg -p 'class $NAME($$$BASES): $$$BODY' --lang py

# Find list comprehensions
sg -p '[$EXPR for $VAR in $ITER]' --lang py
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

## Troubleshooting

### Pattern Not Matching
- Verify language is correct (--lang)
- Check AST structure with --debug-query
- Simplify pattern to isolate issue
- Ensure whitespace doesn't affect match

### False Positives
- Add constraints (inside, has, not)
- Be more specific in pattern
- Use kind constraints for node types

## Additional Resources

For detailed examples and advanced patterns, see `examples.md` and `quick-reference.md`.

- Official Documentation: https://ast-grep.github.io/
- Pattern Playground: https://ast-grep.github.io/playground.html

When providing ast-grep guidance, emphasize semantic matching over text patterns, suggest testing patterns in the playground, and recommend starting simple then adding constraints for precision.
