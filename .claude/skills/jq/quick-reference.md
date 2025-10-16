# jq Quick Reference

## Command Syntax
```bash
jq [OPTIONS] '<filter>' [FILE...]
```

## Essential Flags
| Flag | Description |
|------|-------------|
| `-r` | Raw output (no quotes) |
| `-c` | Compact output |
| `-s` | Slurp (array of inputs) |
| `-n` | Null input |
| `-e` | Exit status based on output |
| `--arg name value` | Pass string variable |
| `--argjson name json` | Pass JSON variable |

## Basic Filters
| Filter | Description | Example |
|--------|-------------|---------|
| `.` | Identity | `jq '.'` |
| `.field` | Access field | `jq '.name'` |
| `.[]` | Array iterator | `jq '.[]'` |
| `.[0]` | Array index | `jq '.[0]'` |
| `.[1:3]` | Array slice | `jq '.[1:3]'` |
| `.field?` | Optional access | `jq '.age?'` |

## Operators
| Operator | Use |
|----------|-----|
| `\|` | Pipe |
| `,` | Multiple outputs |
| `+` | Add/concatenate |
| `==`, `!=` | Compare |
| `and`, `or`, `not` | Boolean |
| `//` | Alternative (default) |

## Common Functions
```bash
length              # Array/object/string length
keys                # Object keys
values              # Object values
type                # Get type
has("key")          # Check key exists
select(condition)   # Filter
map(expression)     # Transform array
sort, sort_by()     # Sort
unique              # Remove duplicates
group_by()          # Group elements
add                 # Sum array
min, max            # Min/max value
```

## Quick Patterns
```bash
# Extract field from array
jq '.[].name'

# Filter array
jq '.[] | select(.age > 18)'

# Transform object
jq '{new_name: .old_name}'

# Merge objects
jq '. + {"key": "value"}'

# Default value
jq '.field // "default"'

# Conditional
jq 'if .age >= 18 then "adult" else "minor" end'
```
