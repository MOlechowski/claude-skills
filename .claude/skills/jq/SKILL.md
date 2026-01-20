---
name: jq
description: JSON processing and transformation. Use for: (1) extracting data from API responses, (2) filtering and transforming JSON structures, (3) combining or restructuring JSON data, (4) JSON processing in shell pipelines. Triggers: parse JSON, extract from JSON, filter JSON array, transform JSON, pretty-print JSON.
---

# jq Expertise Skill

## Fundamental Concepts

### Identity and Basic Filters

**Identity (`.`)**
```bash
# Pass through unchanged (pretty-print)
echo '{"name":"Alice"}' | jq '.'
```

**Field Access (`.field`)**
```bash
# Extract single field
echo '{"name":"Alice","age":30}' | jq '.name'
# Output: "Alice"

# Nested access
echo '{"user":{"name":"Alice"}}' | jq '.user.name'
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

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `\|` | Pipe | `jq '.users \| .[]'` |
| `,` | Comma (multiple outputs) | `jq '.a, .b'` |
| `+` | Addition/concatenation | `jq '.a + .b'` |
| `==` | Equal | `jq '.status == "active"'` |
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

# type - Get type of value
echo '{"name":"Alice"}' | jq '.name | type'
# Output: "string"

# has - Check if key exists
echo '{"name":"Alice"}' | jq 'has("name")'
# Output: true
```

**String Functions:**
```bash
# split
echo '"a,b,c"' | jq 'split(",")'
# Output: ["a", "b", "c"]

# join
echo '["a","b","c"]' | jq 'join(",")'
# Output: "a,b,c"
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

# add - Sum array
echo '[1,2,3]' | jq 'add'
# Output: 6
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
-s, --slurp               # Read entire input into array
-n, --null-input          # Don't read input, start with null
--arg name value          # Pass string variable
--argjson name json       # Pass JSON variable
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
```

## Error Handling

### Try-Catch

```bash
# Handle errors gracefully
echo '{"name":"Alice"}' | jq 'try .age catch 0'
# Output: 0
```

### Empty and Error

```bash
# Return empty instead of error
echo '{"name":"Alice"}' | jq '.age // empty'
# Output: (nothing)
```

## Additional Resources

For detailed examples and reference, see `examples.md` and `quick-reference.md`.
