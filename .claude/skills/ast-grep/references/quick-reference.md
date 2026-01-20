# ast-grep Quick Reference

## Basic Command
```bash
sg [OPTIONS] -p <PATTERN> [PATH...]
```

## Essential Flags

| Flag | Description |
|------|-------------|
| `-p <PATTERN>` / `--pattern` | Search pattern |
| `-r <REPLACE>` / `--rewrite` | Replacement pattern |
| `-l <LANG>` / `--lang` | Language (js, ts, py, etc.) |
| `--json` | JSON output |
| `--update-all` | Update files in place |
| `--interactive` | Interactive replacement |

## Metavariables

| Syntax | Description | Example |
|--------|-------------|---------|
| `$VAR` | Single AST node | `$NAME($ARGS)` |
| `$$$VAR` | Multiple nodes (variadic) | `function f($$$PARAMS)` |
| `$_$` | Wildcard (no capture) | `console.log($_$)` |

## Pattern Constraints

| Flag | Description |
|------|-------------|
| `--inside <PATTERN>` | Match inside another pattern |
| `--has <PATTERN>` | Match if contains pattern |
| `--follows <PATTERN>` | Match if follows pattern |
| `--precedes <PATTERN>` | Match if precedes pattern |
| `--not <PATTERN>` | Exclude matches with pattern |

## Output Control

| Flag | Description |
|------|-------------|
| `-A <NUM>` | Lines after match |
| `-B <NUM>` | Lines before match |
| `-C <NUM>` | Lines before and after |
| `--heading` | Group by file |
| `--color` / `--no-color` | Color output |
| `--format <FMT>` | Format (short, json) |

## Rule Files

```bash
# Run rule file
sg scan -r rule.yml src/

# Run all rules in directory
sg scan -c rules/ src/

# JSON output
sg scan -r rule.yml --json
```

## Rule File Structure

```yaml
id: rule-name
message: Description of issue
severity: error|warning|hint
language: JavaScript|TypeScript|Python|Rust|Go
rule:
  pattern: <pattern>
  inside: <constraint>
  has: <constraint>
  not: <constraint>
fix: <replacement>
```

## Language Codes

| Language | Code | Extensions |
|----------|------|------------|
| JavaScript | `js` | .js, .mjs |
| TypeScript | `ts` | .ts |
| TSX/JSX | `tsx` | .tsx, .jsx |
| Python | `py` | .py |
| Rust | `rs` | .rs |
| Go | `go` | .go |
| Java | `java` | .java |
| C++ | `cpp` | .cpp, .cc |
| HTML | `html` | .html |
| CSS | `css` | .css |

## Quick Patterns

```bash
# Function calls
sg -p '$FUNC($$$ARGS)' --lang js

# Function definitions
sg -p 'function $NAME($$$PARAMS) { $$$BODY }' --lang js

# Variable declarations
sg -p 'const $VAR = $VALUE' --lang js

# Imports
sg -p 'import $SPEC from $SOURCE' --lang js

# React hooks
sg -p 'use$HOOK($$$ARGS)' --lang tsx

# Class definitions
sg -p 'class $NAME extends $BASE { $$$BODY }' --lang js

# Arrow functions
sg -p '($$$PARAMS) => $BODY' --lang js

# Async functions
sg -p 'async function $NAME() { $$$BODY }' --lang js

# Try-catch blocks
sg -p 'try { $$$TRY } catch ($ERR) { $$$CATCH }' --lang js

# Object destructuring
sg -p 'const { $$$PROPS } = $OBJ' --lang js

# JSX elements
sg -p '<$COMPONENT $$$PROPS />' --lang tsx

# API calls
sg -p 'fetch($URL)' --lang js

# Console statements
sg -p 'console.$METHOD($$$ARGS)' --lang js
```

## Rewrite Patterns

```bash
# Simple replacement
sg -p 'var $NAME' -r 'const $NAME' --lang js

# Add await
sg -p 'fetch($URL)' -r 'await fetch($URL)' --lang js

# Convert to template string
sg -p '"Hello " + $NAME' -r '`Hello ${$NAME}`' --lang js

# Replace method call
sg -p '$OBJ.oldMethod($$$ARGS)' -r '$OBJ.newMethod($$$ARGS)' --lang js

# Add error handling
sg -p 'await $PROMISE' \
   -r 'await $PROMISE.catch(err => handleError(err))' \
   --lang js
```

## Common Workflows

```bash
# Find and preview
sg -p 'OLD' -r 'NEW' --lang js

# Interactive replacement
sg -p 'OLD' -r 'NEW' --lang js --interactive

# Apply all changes
sg -p 'OLD' -r 'NEW' --lang js --update-all

# Search with constraints
sg -p '$VAR' --inside 'function $NAME() { $$$BODY }' --lang js

# Run linting rules
sg scan -c rules/ src/

# Debug pattern
sg -p '$PATTERN' --lang js --debug-query

# List languages
sg --list-langs

# Test pattern
sg -p '$PATTERN' --lang js --test file.js
```

## Constraints Example

```bash
# useState not in useEffect
sg -p 'useState($INIT)' \
   --not-inside 'useEffect(() => { $$$BODY }, [$$$DEPS])' \
   --lang tsx

# fetch without error handling
sg -p 'fetch($URL)' \
   --not-inside 'try { $$$BODY } catch ($ERR) { $$$HANDLER }' \
   --lang js

# console.log after variable declaration
sg -p 'console.log($VAR)' \
   --follows 'const $VAR =' \
   --lang js
```

## Rule File Operators

```yaml
# All conditions must match
rule:
  all:
    - pattern: $PATTERN1
    - pattern: $PATTERN2

# Any condition must match
rule:
  any:
    - pattern: $PATTERN1
    - pattern: $PATTERN2

# Pattern must not match
rule:
  not:
    pattern: $PATTERN

# Pattern must be inside
rule:
  pattern: $INNER
  inside:
    pattern: $OUTER

# Pattern must have
rule:
  pattern: $OUTER
  has:
    pattern: $INNER
```

## Debugging

```bash
# Show AST structure
sg -p 'code' --lang js --debug-query

# Verbose output
sg -p '$PATTERN' --lang js -vv

# Test pattern match
sg -p '$PATTERN' --lang js --test file.js

# Verify rule file
sg scan -r rule.yml --dry-run
```
