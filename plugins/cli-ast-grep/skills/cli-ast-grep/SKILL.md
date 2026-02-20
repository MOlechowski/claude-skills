---
name: cli-ast-grep
description: "Semantic code search and transformation using ASTs. Use for: (1) structural pattern matching beyond regex, (2) AST-based refactoring with metavariables, (3) finding architectural patterns or anti-patterns, (4) language-aware code transformations. Triggers: semantic search, find code patterns, refactor class/function structure, AST matching."
---

# ast-grep (sg) Skill

## Core Capabilities

1. **Semantic Search**: Match code by structure, not text
2. **Language Aware**: Understands multiple language syntaxes
3. **Metavariables**: Capture and reuse code fragments
4. **Structural Rewriting**: Transform code preserving semantics
5. **Multi-Language**: TypeScript, JavaScript, Python, Rust, Go, etc.
6. **Rule Engine**: Custom linting and refactoring rules

## Basic Usage

### Pattern Search
```bash
# Find console.log calls
sg -p 'console.log($ARG)' src/

# Find function definitions
sg -p 'function $NAME($PARAMS) { $BODY }' src/

# Find React useState hooks
sg -p 'useState($INIT)' --lang tsx
```

### Pattern Syntax
```bash
# $VAR matches single AST node
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
# Match without capturing
sg -p 'console.log($_$)'

# Match any condition
sg -p 'if ($_$) { return true }'
```

## Language-Specific Patterns

### JavaScript/TypeScript
```bash
# Arrow functions
sg -p '($$$PARAMS) => $BODY' --lang ts

# Async functions
sg -p 'async function $NAME($$$PARAMS) { $$$BODY }' --lang js

# JSX elements
sg -p '<$COMPONENT $$$PROPS />' --lang tsx

# Import statements
sg -p 'import $SPEC from $SOURCE' --lang ts
```

### React Patterns
```bash
# useState hooks
sg -p 'const [$STATE, $SETTER] = useState($INIT)' --lang tsx

# useEffect hooks
sg -p 'useEffect(() => { $$$BODY }, [$$$DEPS])' --lang tsx

# Component definitions
sg -p 'function $NAME($PROPS) { return $JSX }' --lang tsx
```

### Python
```bash
# Function definitions
sg -p 'def $NAME($$$PARAMS): $$$BODY' --lang py

# Class definitions
sg -p 'class $NAME($$$BASES): $$$BODY' --lang py

# List comprehensions
sg -p '[$EXPR for $VAR in $ITER]' --lang py
```

## Pattern Constraints

### Inside/Has/Follows/Precedes
```bash
# Pattern inside another
sg -p '$VAR' --inside 'function $NAME() { $$$BODY }' --lang js

# Pattern containing another
sg -p 'function $NAME() { $$$BODY }' --has 'return $VALUE' --lang js

# Pattern following another
sg -p 'console.log($MSG)' --follows 'const $VAR =' --lang js
```

## Rewriting and Transformation

### Basic Rewrite
```bash
# Replace console.log with logger.info
sg -p 'console.log($ARG)' -r 'logger.info($ARG)' --lang js

# Convert var to const
sg -p 'var $NAME = $VALUE' -r 'const $NAME = $VALUE' --lang js

# Add await to fetch
sg -p 'fetch($URL)' -r 'await fetch($URL)' --lang js
```

### Complex Rewrites
```bash
# Convert Promise.then to async/await
sg -p 'fetch($URL).then($HANDLER)' \
   -r 'const response = await fetch($URL); $HANDLER(response)' \
   --lang js

# Add error handling
sg -p 'const $VAR = await fetch($URL)' \
   -r 'const $VAR = await fetch($URL).catch(error => {
     console.error("Fetch failed:", error);
     throw error;
   })' \
   --lang js
```

### Interactive Rewrite
```bash
# Review each change interactively
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
# 1: Find instances
sg -p 'oldFunction($$$ARGS)' --lang js

# 2: Preview changes
sg -p 'oldFunction($$$ARGS)' -r 'newFunction($$$ARGS)' --lang js

# 3: Apply changes
sg -p 'oldFunction($$$ARGS)' -r 'newFunction($$$ARGS)' --lang js --update-all
```

### Code Review
```bash
# Find potential bugs (assignment in condition)
sg -p 'if ($VAR = $VALUE)' --lang js

# Find security issues
sg -p 'eval($CODE)' --lang js
sg -p 'innerHTML = $VALUE' --lang js
```

### Architecture Analysis
```bash
# Find API endpoints
sg -p 'app.$METHOD($PATH, $HANDLER)' --lang js

# Find database queries
sg -p 'db.query($SQL, $$$PARAMS)' --lang js
```

## Best Practices

### Pattern Writing
- Start simple, add constraints incrementally
- Use metavariables ($VAR) for captures
- Use wildcards ($_$) when capture unnecessary
- Test on small examples first
- Use --debug-query to understand AST structure

### Refactoring
- Preview changes before applying
- Use --interactive for large refactorings
- Test after transformations
- Commit incrementally

## Troubleshooting

### Pattern Not Matching
- Verify language (--lang)
- Check AST structure with --debug-query
- Simplify pattern to isolate issue
- Check whitespace effects

### False Positives
- Add constraints (inside, has, not)
- Make pattern more specific
- Use kind constraints for node types

## Additional Resources

See `examples.md` and `quick-reference.md` for detailed examples.

- Official Documentation: https://cli-ast-grep.github.io/
- Pattern Playground: https://cli-ast-grep.github.io/playground.html

Prioritize semantic matching over text patterns. Test in playground. Start simple, add constraints for precision.
