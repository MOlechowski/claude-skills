# yq Quick Reference

## Basic Command
```bash
yq [OPTIONS] <expression> [FILE...]
```

## Essential Flags

| Flag | Description |
|------|-------------|
| `-i` / `--inplace` | Update file in-place |
| `-P` / `--prettyPrint` | Pretty-print YAML |
| `-o <format>` / `--output-format` | Output format (yaml, json, xml, props, csv) |
| `-I <num>` / `--indent` | Indentation (default: 2) |
| `-C` / `--colors` | Force colored output |
| `-M` / `--no-colors` | Disable colored output |
| `-N` / `--no-doc` | Don't print document separator `---` |

## Input/Output Formats

| Flag | Format |
|------|--------|
| `-o yaml` / `-o y` | YAML (default) |
| `-o json` / `-o j` | JSON |
| `-o xml` / `-o x` | XML |
| `-o props` / `-o p` | Properties |
| `-o csv` / `-o c` | CSV |
| `-o toml` / `-o t` | TOML |
| `-p <format>` | Input format (auto-detected by default) |

## Path Expressions

| Expression | Description | Example |
|------------|-------------|---------|
| `.` | Root/identity | `yq '.' file.yml` |
| `.key` | Top-level key | `yq '.name' file.yml` |
| `.a.b.c` | Nested keys | `yq '.spec.replicas' file.yml` |
| `.[0]` | Array index | `yq '.items[0]' file.yml` |
| `.[-1]` | Last element | `yq '.items[-1]' file.yml` |
| `.[1:3]` | Array slice | `yq '.items[1:3]' file.yml` |
| `.[]` | All array elements | `yq '.items[]' file.yml` |
| `.*` | All values at level | `yq '.metadata.*' file.yml` |
| `..` | Recursive descent | `yq '.. \| .name' file.yml` |

## Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `\|` | Pipe | `yq '.items \| length' file.yml` |
| `=` | Assignment | `yq '.name = "new"' file.yml` |
| `\|=` | Update | `yq '.count \|= . + 1' file.yml` |
| `//` | Alternative (default) | `yq '.port // 8080' file.yml` |
| `//=` | Set if null/empty | `yq '.timeout //= 30' file.yml` |
| `+` | Add/concatenate | `yq '.items + ["new"]' file.yml` |
| `-` | Subtract | `yq '.items - ["old"]' file.yml` |
| `*` | Multiply/merge | `yq '. * {"new": "value"}' file.yml` |
| `*+` | Deep merge | `yq eval-all '. *+ .' a.yml b.yml` |

## Common Functions

```bash
# Length
yq '.items | length' file.yml

# Keys
yq 'keys' file.yml

# Values
yq '.[] | values' file.yml

# Type
yq '.field | type' file.yml

# Has key
yq 'has("key")' file.yml

# Select
yq '.items[] | select(.active == true)' file.yml

# Map
yq '.items | map(.name)' file.yml

# Sort
yq '.items | sort' file.yml
yq '.items | sort_by(.name)' file.yml

# Unique
yq '.items | unique' file.yml

# Group
yq 'group_by(.category)' file.yml

# Add (sum)
yq '.numbers | add' file.yml

# Min/Max
yq '.numbers | min' file.yml
yq '.numbers | max' file.yml

# Join
yq '.names | join(", ")' file.yml

# Split
yq '.text | split(" ")' file.yml
```

## String Functions

```bash
# Test regex
yq '.name | test("^prod-")' file.yml

# Match regex
yq '.text | match("pattern")' file.yml

# Replace
yq '.name | sub("old", "new")' file.yml

# Uppercase/Lowercase
yq '.name | upcase' file.yml
yq '.name | downcase' file.yml

# Trim
yq '.text | trim' file.yml

# Contains
yq '.text | contains("substring")' file.yml

# Starts/Ends with
yq '.name | startswith("prefix")' file.yml
yq '.name | endswith("suffix")' file.yml
```

## Quick Patterns

```bash
# Read file
yq '.' file.yml

# Get value
yq '.key' file.yml

# Update value
yq '.key = "value"' file.yml

# Update in-place
yq -i '.key = "value"' file.yml

# Delete key
yq 'del(.key)' file.yml

# Add to array
yq '.items += ["new"]' file.yml

# Filter array
yq '.items[] | select(.active)' file.yml

# Convert to JSON
yq -o json '.' file.yml

# Convert to YAML
yq -P '.' file.json

# Merge files
yq eval-all '. as $item ireduce ({}; . * $item)' file1.yml file2.yml

# Merge with priority
yq ea 'select(fileIndex == 0) * select(fileIndex == 1)' base.yml override.yml

# Update all files
yq -i '.version = "2.0"' *.yml

# Get from all files
yq '.name' *.yml

# Format YAML
yq -i '.' file.yml

# Sort keys
yq -i 'sort_keys(.)' file.yml

# Extract to JSON
yq -o json '.config' file.yml > config.json

# Validate YAML
yq '.' file.yml > /dev/null && echo "Valid"

# Use environment variable
yq '.db.host = env(DB_HOST)' file.yml

# Conditional update
yq '(.items[] | select(.name == "target")).value = "new"' file.yml

# Split multi-doc YAML
yq -s '.kind + "-" + .metadata.name' multi.yml

# Combine into single file
yq eval-all '.' file1.yml file2.yml > combined.yml
```

## Kubernetes Helpers

```bash
# Get image
yq '.spec.template.spec.containers[0].image' deployment.yml

# Update image
yq -i '.spec.template.spec.containers[0].image = "app:v2"' deployment.yml

# Get all images
yq '.spec.template.spec.containers[].image' deployment.yml

# Get resource name
yq '.metadata.name' resource.yml

# Update replicas
yq -i '.spec.replicas = 5' deployment.yml

# Add label
yq -i '.metadata.labels.env = "prod"' deployment.yml

# Get all service names
yq 'select(.kind == "Service") | .metadata.name' *.yml

# Extract by kind
yq 'select(.kind == "Deployment")' all.yml
```

## Docker Compose Helpers

```bash
# Get service names
yq '.services | keys' docker-compose.yml

# Get service image
yq '.services.web.image' docker-compose.yml

# Update service image
yq -i '.services.web.image = "nginx:latest"' docker-compose.yml

# Get all ports
yq '.services[].ports[]' docker-compose.yml

# Add environment variable
yq -i '.services.app.environment.VAR = "value"' docker-compose.yml

# Get environment
yq '.services.app.environment' docker-compose.yml
```

## Multi-File Operations

```bash
# eval-all (ea) - process multiple files
yq eval-all '.' file1.yml file2.yml

# Merge (second file wins)
yq ea 'select(fileIndex == 0) * select(fileIndex == 1)' base.yml override.yml

# Deep merge
yq ea '. as $item ireduce ({}; . *+ $item)' file1.yml file2.yml

# Combine into array
yq ea '[.]' file1.yml file2.yml

# Select by file
yq ea 'select(fileIndex == 0)' file1.yml file2.yml
```

## Formatting

```bash
# Pretty-print
yq -P '.' file.yml

# Custom indentation
yq -I 4 '.' file.yml

# Compact (no indent)
yq -I 0 '.' file.yml

# No colors
yq -M '.' file.yml

# No document separator
yq -N '.' file.yml

# Preserve order
yq --preserve-order '.' file.yml
```

## Debugging

```bash
# Debug mode
yq --verbose '.' file.yml

# Print variable
yq '.path | debug' file.yml

# Check type
yq '.field | type' file.yml

# Show help
yq --help

# Show version
yq --version
```

## Common Combos

```bash
# Update and format
yq -i -P '.version = "2.0"' file.yml

# Convert and pretty-print
yq -P -o json '.' file.yml

# Merge and output JSON
yq ea -o json '. as $item ireduce ({}; . * $item)' base.yml env.yml

# Extract, filter, convert
yq '.items[] | select(.active) | {"name": .name}' -o json file.yml

# Bulk update with backup
cp file.yml file.yml.bak && yq -i '.version = "2.0"' file.yml

# Extract config to env file
yq '.env | to_entries | .[] | .key + "=" + .value' config.yml > .env
```
