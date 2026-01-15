---
name: jq
description: JSON processing and transformation.
---

# jq Expertise Skill

Use this skill when:
- Processing JSON output from APIs, logs, or configuration files
- Filtering, transforming, or extracting data from complex JSON structures
- Combining or restructuring JSON data
- Working with JSON in shell scripts or pipelines
- Debugging API responses or JSON-based workflows

Examples:
- "Extract all user names from this JSON API response"
- "Filter JSON array to only include items where status is 'active'"
- "Transform this JSON structure to match a different schema"
- "Combine multiple JSON files into a single array"
- "Pretty-print and colorize JSON output"

You are an expert in `jq`, a powerful command-line JSON processor that provides a complete query language for filtering, transforming, and manipulating JSON data streams.

## Core Capabilities

1. **JSON Navigation**: Extract values from deeply nested JSON structures
2. **Filtering**: Select elements based on complex conditions
3. **Transformation**: Reshape JSON data to different schemas
4. **Aggregation**: Compute sums, counts, groupings, and statistics
5. **Composition**: Combine multiple JSON sources or operations
6. **Scripting**: Write reusable jq programs for complex workflows

## jq Overview

**What it does:**
- Processes JSON from stdin, files, or command output
- Applies filters and transformations using a specialized query language
- Outputs formatted JSON (or raw text with `-r` flag)
- Streams large JSON files efficiently

**When to use jq:**
- Working with JSON APIs, logs, or configurations
- Shell scripting with JSON data
- Data transformation pipelines
- Debugging JSON structures
- Alternative to writing Python/Node scripts for simple JSON tasks

## Fundamental Concepts

### Identity and Basic Filters

**Identity (`.`)**
```bash
# Pass through unchanged (pretty-print)
echo '{"name":"Alice"}' | jq '.'
# Output: {
#   "name": "Alice"
# }
```

**Field Access (`.field`)**
```bash
# Extract single field
echo '{"name":"Alice","age":30}' | jq '.name'
# Output: "Alice"

# Nested access
echo '{"user":{"name":"Alice"}}' | jq '.user.name'
# Output: "Alice"
```

**Optional Field Access (`.field?`)**
```bash
# Won't error if field doesn't exist
echo '{"name":"Alice"}' | jq '.age?'
# Output: null
```

### Array Operations

**Array Indexing**
```bash
# Get element by index
echo '[1,2,3]' | jq '.[0]'
# Output: 1

# Get last element
echo '[1,2,3]' | jq '.[-1]'
# Output: 3
```

**Array Slicing**
```bash
# Get range
echo '[1,2,3,4,5]' | jq '.[1:3]'
# Output: [2, 3]

# From start to index
echo '[1,2,3,4,5]' | jq '.[:2]'
# Output: [1, 2]
```

**Array Iterator (`.[]`)**
```bash
# Iterate over array elements
echo '[1,2,3]' | jq '.[]'
# Output: 1
#         2
#         3
```

### Pipes and Composition

**Pipe Operator (`|`)**
```bash
# Chain operations
echo '{"users":[{"name":"Alice"},{"name":"Bob"}]}' | jq '.users | .[0] | .name'
# Output: "Alice"
```

**Multiple Operations**
```bash
# Apply multiple filters
echo '{"a":1,"b":2}' | jq '.a, .b'
# Output: 1
#         2
```

## Essential jq Syntax

### Filters and Selectors

| Syntax | Description | Example |
|--------|-------------|---------|
| `.` | Identity (current input) | `jq '.'` |
| `.field` | Access field | `jq '.name'` |
| `.field?` | Optional field access | `jq '.age?'` |
| `.[index]` | Array index | `jq '.[0]'` |
| `.[]` | Array iterator | `jq '.[]'` |
| `.[start:end]` | Array slice | `jq '.[1:3]'` |
| `.field.nested` | Nested access | `jq '.user.name'` |
| `.. | .field` | Recursive descent | `jq '.. | .name?'` |

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `\|` | Pipe | `jq '.users \| .[]'` |
| `,` | Comma (multiple outputs) | `jq '.a, .b'` |
| `+` | Addition/concatenation | `jq '.a + .b'` |
| `-` | Subtraction | `jq '.total - .used'` |
| `*` | Multiplication/merge | `jq '.price * .qty'` |
| `/` | Division | `jq '.total / .count'` |
| `==` | Equal | `jq '.status == "active"'` |
| `!=` | Not equal | `jq '.status != "deleted"'` |
| `<`, `>`, `<=`, `>=` | Comparisons | `jq '.age > 18'` |
| `and`, `or`, `not` | Boolean logic | `jq '.active and .verified'` |

### Functions

**Core Functions:**
```bash
# length - Get length of array/object/string
echo '["a","b","c"]' | jq 'length'
# Output: 3

# keys - Get object keys as array
echo '{"a":1,"b":2}' | jq 'keys'
# Output: ["a", "b"]

# values - Get all values
echo '{"a":1,"b":2}' | jq '.[]'
# Output: 1
#         2

# type - Get type of value
echo '{"name":"Alice"}' | jq '.name | type'
# Output: "string"

# has - Check if key exists
echo '{"name":"Alice"}' | jq 'has("name")'
# Output: true
```

**String Functions:**
```bash
# startswith/endswith
echo '"hello world"' | jq 'startswith("hello")'
# Output: true

# contains
echo '"hello world"' | jq 'contains("world")'
# Output: true

# split
echo '"a,b,c"' | jq 'split(",")'
# Output: ["a", "b", "c"]

# join
echo '["a","b","c"]' | jq 'join(",")'
# Output: "a,b,c"

# tostring/tonumber
echo '123' | jq 'tostring'
# Output: "123"
```

**Array Functions:**
```bash
# map - Apply expression to each element
echo '[1,2,3]' | jq 'map(. * 2)'
# Output: [2, 4, 6]

# select - Filter elements
echo '[1,2,3,4]' | jq '.[] | select(. > 2)'
# Output: 3
#         4

# sort/sort_by
echo '[3,1,2]' | jq 'sort'
# Output: [1, 2, 3]

# unique
echo '[1,2,2,3]' | jq 'unique'
# Output: [1, 2, 3]

# reverse
echo '[1,2,3]' | jq 'reverse'
# Output: [3, 2, 1]

# add - Sum array
echo '[1,2,3]' | jq 'add'
# Output: 6
```

**Aggregation Functions:**
```bash
# group_by
echo '[{"name":"Alice","age":30},{"name":"Bob","age":30}]' | jq 'group_by(.age)'

# min/max
echo '[3,1,2]' | jq 'min'
# Output: 1

# min_by/max_by
echo '[{"name":"Alice","age":30},{"name":"Bob","age":25}]' | jq 'min_by(.age)'
# Output: {"name": "Bob", "age": 25}
```

## Common Patterns

### Extract Field from All Array Elements

```bash
# Get all names
echo '[{"name":"Alice","age":30},{"name":"Bob","age":25}]' | jq '.[].name'
# Output: "Alice"
#         "Bob"

# As array
echo '[{"name":"Alice"},{"name":"Bob"}]' | jq '[.[].name]'
# Output: ["Alice", "Bob"]
```

### Filter Array Elements

```bash
# Filter by condition
echo '[{"name":"Alice","age":30},{"name":"Bob","age":25}]' | \
  jq '.[] | select(.age > 28)'
# Output: {"name": "Alice", "age": 30}

# Multiple conditions
echo '[{"name":"Alice","status":"active"},{"name":"Bob","status":"inactive"}]' | \
  jq '.[] | select(.status == "active" and .name == "Alice")'
```

### Transform Object Structure

```bash
# Rename fields
echo '{"old_name":"value"}' | jq '{new_name: .old_name}'
# Output: {"new_name": "value"}

# Pick specific fields
echo '{"name":"Alice","age":30,"email":"alice@example.com"}' | \
  jq '{name, age}'
# Output: {"name": "Alice", "age": 30}

# Computed fields
echo '{"first":"Alice","last":"Smith"}' | \
  jq '{full_name: (.first + " " + .last)}'
# Output: {"full_name": "Alice Smith"}
```

### Merge Objects

```bash
# Merge two objects
echo '{"a":1}' | jq '. + {"b":2}'
# Output: {"a": 1, "b": 2}

# Merge with override
echo '{"a":1,"b":2}' | jq '. + {"b":3}'
# Output: {"a": 1, "b": 3}
```

### Array to Object

```bash
# Create object from array
echo '[{"key":"a","value":1},{"key":"b","value":2}]' | \
  jq 'map({(.key): .value}) | add'
# Output: {"a": 1, "b": 2}
```

### Conditional Logic

```bash
# if-then-else
echo '{"age":25}' | jq 'if .age >= 18 then "adult" else "minor" end'
# Output: "adult"

# Alternative operator //
echo '{"name":"Alice"}' | jq '.age // 0'
# Output: 0  (default when .age is null)
```

## Command-Line Options

### Essential Flags

```bash
-r, --raw-output          # Output raw strings (no quotes)
-c, --compact-output      # Compact JSON (no pretty-print)
-S, --sort-keys           # Sort object keys
-e, --exit-status         # Set exit code based on output
-s, --slurp               # Read entire input into array
-n, --null-input          # Don't read input, start with null
-f, --from-file <file>    # Read jq program from file
--arg name value          # Pass string variable
--argjson name json       # Pass JSON variable
--slurpfile name file     # Read JSON file into variable
-M, --monochrome-output   # No colors
-C, --color-output        # Force colors
```

### Usage Examples

**Raw Output (`-r`)**
```bash
# Without -r: "Alice"
# With -r: Alice
echo '{"name":"Alice"}' | jq -r '.name'
```

**Slurp (`-s`)**
```bash
# Combine multiple JSON objects into array
echo '{"a":1}
{"b":2}' | jq -s '.'
# Output: [{"a": 1}, {"b": 2}]
```

**Variables (`--arg`)**
```bash
# Pass external values
jq --arg name "Alice" '.name = $name' input.json
```

**Multiple Files**
```bash
# Process multiple files
jq '.users[]' file1.json file2.json
```

## Real-World Workflows

### API Response Processing

```bash
# Extract specific fields from API response
curl -s 'https://api.example.com/users' | \
  jq '.users[] | {name, email, created_at}'

# Filter and transform
curl -s 'https://api.example.com/users' | \
  jq '[.users[] | select(.active == true) | {id, name}]'
```

### Log Analysis

```bash
# Parse JSON logs
cat app.log | jq 'select(.level == "error") | .message'

# Group and count errors
cat app.log | jq -s 'group_by(.error_code) | map({code: .[0].error_code, count: length})'
```

### Configuration Management

```bash
# Update config value
jq '.database.host = "localhost"' config.json > config.new.json

# Merge configs
jq -s '.[0] * .[1]' base-config.json env-config.json
```

### Data Transformation

```bash
# Convert CSV-like data to JSON (with external tool)
csvtojson data.csv | jq '.[] | {name: .Name, age: (.Age | tonumber)}'

# Flatten nested structure
echo '{"a":{"b":{"c":1}}}' | jq 'flatten'
```

## Advanced Techniques

### Recursive Descent

```bash
# Find all values for a key anywhere in structure
echo '{"a":{"b":{"name":"Alice"},"c":{"name":"Bob"}}}' | \
  jq '.. | .name? | select(. != null)'
# Output: "Alice"
#         "Bob"
```

### Custom Functions

```bash
# Define reusable functions
jq 'def double: . * 2; map(double)' <<< '[1,2,3]'
# Output: [2, 4, 6]
```

### Reduce

```bash
# Custom aggregation
echo '[1,2,3,4]' | jq 'reduce .[] as $x (0; . + $x)'
# Output: 10  (sum)

# Build object
echo '["a","b","c"]' | jq 'reduce .[] as $x ({}; . + {($x): true})'
# Output: {"a": true, "b": true, "c": true}
```

### Path Expressions

```bash
# Get path to all matching values
echo '{"a":{"b":1},"c":{"b":2}}' | jq 'getpath(["a","b"])'
# Output: 1

# Set value at path
echo '{"a":{"b":1}}' | jq 'setpath(["a","b"]; 999)'
# Output: {"a": {"b": 999}}
```

## Error Handling

### Try-Catch

```bash
# Handle errors gracefully
echo '{"name":"Alice"}' | jq 'try .age catch 0'
# Output: 0

# With error message
echo 'invalid' | jq -R 'try fromjson catch "Invalid JSON: \(.)"'
```

### Empty and Error

```bash
# Return empty instead of error
echo '{"name":"Alice"}' | jq '.age // empty'
# Output: (nothing)

# Error with message
jq 'if .age < 0 then error("Age cannot be negative") else . end'
```

## Performance Tips

### Streaming for Large Files

```bash
# Stream large JSON arrays without loading into memory
jq -c '.[]' huge-array.json | while read -r obj; do
  echo "$obj" | jq '.field'
done
```

### Limit Output

```bash
# Process only first N elements
jq 'limit(10; .users[])' large-file.json
```

### Use Compact Output for Performance

```bash
# Faster parsing downstream
jq -c '.[]' input.json | process-each-line.sh
```

## Common Pitfalls

### String Quoting

```bash
# WRONG: Shell interprets $
jq ".name" file.json  # May fail if $name is shell variable

# CORRECT: Use single quotes
jq '.name' file.json
```

### Array vs Object Iteration

```bash
# Iterate array elements
echo '[1,2,3]' | jq '.[]'  # Outputs: 1, 2, 3

# Iterate object values
echo '{"a":1,"b":2}' | jq '.[]'  # Outputs: 1, 2
```

### Null Handling

```bash
# Check for null before operating
jq 'if .field != null then .field | process else empty end'

# Use alternative operator
jq '.field // default_value'
```

## Debugging

### Inspect intermediate results

```bash
# Use debug to see values
jq '.users | debug | .[0]' input.json
```

### Type checking

```bash
# Verify types during processing
jq '.items[] | if type != "object" then error("Expected object") else . end'
```

## Integration Examples

### With curl

```bash
# API call with jq processing
curl -s 'https://api.github.com/repos/jq/jq' | \
  jq '{name, stars: .stargazers_count, language}'
```

### With find

```bash
# Process all JSON files
find . -name '*.json' -exec jq '.version' {} +
```

### With grep

```bash
# Filter then parse
grep '"status"' logfile.jsonl | jq 'select(.status == "error")'
```

## Additional Resources

- Official Manual: https://jqlang.github.io/jq/manual/
- jq Play (Interactive): https://jqplay.org/
- Cookbook: https://github.com/stedolan/jq/wiki/Cookbook

When providing jq guidance, always consider the complexity of the JSON structure, provide clear examples, and suggest testing with jqplay.org for complex queries before production use.
