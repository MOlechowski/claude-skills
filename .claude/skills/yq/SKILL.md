---
name: yq
description: |
  Expert guidance for yq, a portable command-line YAML, JSON, XML, CSV, and properties processor that uses jq-like syntax for querying and transforming structured data across multiple formats.

  Use this skill when:
  - Processing YAML configuration files (Kubernetes, Docker Compose, CI/CD)
  - Converting between YAML, JSON, XML, CSV formats
  - Querying and transforming structured data files
  - Automating configuration management workflows
  - Validating and formatting YAML/JSON files

  Examples:
  - "Extract all image names from Kubernetes manifests"
  - "Convert docker-compose.yml to JSON"
  - "Update version in all YAML config files"
  - "Merge multiple YAML files"
  - "Validate and format YAML files"
---

# yq Expertise Skill

You are an expert in `yq`, a lightweight and portable command-line YAML, JSON, XML, CSV, and properties processor that uses jq-like syntax for querying and transforming structured data.

## Core Capabilities

1. **Multi-Format Support**: Process YAML, JSON, XML, CSV, properties, TOML
2. **jq-Compatible Syntax**: Use familiar jq expressions for queries
3. **In-Place Editing**: Modify files directly with `-i` flag
4. **Format Conversion**: Convert between YAML, JSON, XML
5. **Merge Operations**: Combine multiple files intelligently
6. **Validation**: Check syntax and structure

## yq Overview

**What it does:**
- Reads and writes YAML, JSON, XML, CSV, properties, TOML
- Queries data using jq-like path expressions
- Transforms data with filters and operations
- Merges multiple files with customizable strategies
- Validates and formats structured data files

**Key differences from jq:**
- **Multi-format**: Not just JSON
- **YAML-first**: Optimized for YAML processing
- **In-place editing**: Built-in file modification
- **Comment preservation**: Maintains YAML comments
- **Type-aware**: Handles YAML-specific types (anchors, tags)

**When to use yq:**
- YAML configuration files (K8s, Docker, CI/CD)
- Format conversions (YAML ↔ JSON ↔ XML)
- Infrastructure as code updates
- Configuration management
- Multi-environment configs

## Installation

```bash
# macOS (Homebrew)
brew install yq

# Linux (snap)
snap install yq

# Go install
go install github.com/mikefarah/yq/v4@latest

# Verify installation
yq --version
```

**Important:** This skill covers yq v4+ (mikefarah/yq). There's an older Python-based yq with different syntax.

## Basic Usage

### Read and Query
```bash
# Print entire file
yq '.' file.yml

# Get specific field
yq '.metadata.name' pod.yml

# Get nested field
yq '.spec.containers[0].image' pod.yml

# Get array length
yq '.items | length' list.yml

# Check if key exists
yq 'has("metadata")' file.yml
```

### Output Formats
```bash
# Default YAML output
yq '.' file.yml

# JSON output
yq -o json '.' file.yml

# XML output
yq -o xml '.' file.yml

# Properties format
yq -o props '.' file.yml

# CSV output
yq -o csv '.' file.yml

# Compact (no colors or formatting)
yq -o json -I=0 '.' file.yml
```

## Path Expressions

### Basic Paths
```bash
# Root
yq '.' file.yml

# Top-level key
yq '.key' file.yml

# Nested keys
yq '.level1.level2.level3' file.yml

# Array index
yq '.items[0]' file.yml

# Last array element
yq '.items[-1]' file.yml

# Array range
yq '.items[1:3]' file.yml
```

### Wildcards and Recursion
```bash
# All items in array
yq '.items[]' file.yml

# All values at level
yq '.metadata.*' file.yml

# Recursive descent (all matching keys)
yq '.. | select(has("name")) | .name' file.yml

# Find all matching paths
yq '.. | select(. == "target-value")' file.yml
```

### Optional Paths
```bash
# Won't error if key doesn't exist
yq '.optional.path // "default"' file.yml

# Alternative operator
yq '.primary // .fallback // "default"' file.yml
```

## Filtering and Selection

### Select and Filter
```bash
# Filter array by condition
yq '.items[] | select(.status == "active")' file.yml

# Multiple conditions
yq '.items[] | select(.age > 18 and .verified == true)' file.yml

# Regex matching
yq '.items[] | select(.name | test("^prod-"))' file.yml

# Type filtering
yq '.items[] | select(type == "string")' file.yml
```

### Map and Transform
```bash
# Map over array
yq '.items | map(.name)' file.yml

# Transform structure
yq '.items[] | {"name": .name, "value": .value}' file.yml

# Flatten nested arrays
yq '.items[] | .[]' file.yml

# Sort array
yq '.items | sort_by(.name)' file.yml

# Unique values
yq '.items | unique' file.yml
```

## Updating and Modifying

### Update Values
```bash
# Set value
yq '.metadata.name = "new-name"' file.yml

# Update nested value
yq '.spec.replicas = 3' file.yml

# Update in-place (modify file)
yq -i '.version = "2.0"' file.yml

# Update multiple values
yq '.replicas = 5 | .version = "2.0"' file.yml
```

### Conditional Updates
```bash
# Update if condition matches
yq '(.items[] | select(.name == "target")).value = "new"' file.yml

# Update with alternative
yq '.port = (.port // 8080)' file.yml

# Set default if missing
yq '.timeout //= 30' file.yml
```

### Array Operations
```bash
# Add to array
yq '.items += ["new-item"]' file.yml

# Prepend to array
yq '.items = ["first"] + .items' file.yml

# Remove from array
yq '.items -= ["item-to-remove"]' file.yml

# Update array element
yq '.items[0].status = "updated"' file.yml

# Delete array element
yq 'del(.items[2])' file.yml
```

### Delete Operations
```bash
# Delete key
yq 'del(.unwanted)' file.yml

# Delete nested key
yq 'del(.spec.template.metadata.labels.old)' file.yml

# Delete matching items
yq 'del(.items[] | select(.deprecated == true))' file.yml

# Delete in-place
yq -i 'del(.temporary)' file.yml
```

## Working with Multiple Files

### Merge Files
```bash
# Merge two files (second wins)
yq eval-all '. as $item ireduce ({}; . * $item)' file1.yml file2.yml

# Merge with priority
yq ea 'select(fileIndex == 0) * select(fileIndex == 1)' base.yml override.yml

# Deep merge
yq eval-all '. as $item ireduce ({}; . *+ $item)' base.yml env.yml

# Merge arrays
yq ea '[.]' file1.yml file2.yml
```

### Process Multiple Files
```bash
# Combine all files
yq eval-all '.' *.yml

# Extract from all files
yq '.metadata.name' *.yml

# Update all files
yq -i '.version = "2.0"' *.yml

# Different operations per file
yq eval-all 'select(fileIndex == 0) .= .base | select(fileIndex == 1) .= .override' base.yml override.yml
```

### Split Files
```bash
# Split by key
yq eval -N '.items[] | split_doc' multi-doc.yml > output.yml

# Extract to separate files
yq eval '.items[] | . as $item | $item' list.yml | \
  split -l $(yq '.items | length' list.yml) - item-

# Split YAML stream
yq -N '.' multi-doc.yml  # -N = no document separator
```

## Format Conversion

### YAML to JSON
```bash
# Basic conversion
yq -o json '.' file.yml > file.json

# Pretty JSON
yq -o json -I 2 '.' file.yml

# Compact JSON
yq -o json -I 0 '.' file.yml
```

### JSON to YAML
```bash
# Basic conversion
yq -P '.' file.json > file.yml

# With custom indentation
yq -P -I 4 '.' file.json

# Preserve order
yq -P --preserve-order '.' file.json
```

### XML Conversion
```bash
# YAML to XML
yq -o xml '.' file.yml

# XML to YAML
yq -p xml '.' file.xml

# XML to JSON
yq -p xml -o json '.' file.xml
```

### Other Formats
```bash
# YAML to properties
yq -o props '.' config.yml

# CSV to JSON
yq -p csv -o json '.' data.csv

# TOML to YAML
yq -p toml '.' config.toml
```

## Kubernetes Workflows

### Query Manifests
```bash
# Get all container images
yq '.spec.template.spec.containers[].image' deployment.yml

# Get all resource names
yq '.metadata.name' *.yml

# Find resources of specific kind
yq 'select(.kind == "Service")' *.yml

# Get all labels
yq '.metadata.labels' pod.yml
```

### Update Manifests
```bash
# Update image version
yq -i '.spec.template.spec.containers[0].image = "app:v2.0"' deployment.yml

# Update replicas
yq -i '.spec.replicas = 5' deployment.yml

# Add label
yq -i '.metadata.labels.env = "production"' deployment.yml

# Update ConfigMap data
yq -i '.data.API_URL = "https://api.prod.com"' configmap.yml
```

### Multi-Resource Files
```bash
# Split multi-doc YAML
yq -s '.kind + "-" + .metadata.name' all-resources.yml

# Combine into single file
yq eval-all '.' *.yml > all.yml

# Extract specific resource
yq 'select(.kind == "Deployment" and .metadata.name == "app")' all.yml
```

## Docker Compose Operations

### Query Compose Files
```bash
# Get all service names
yq '.services | keys' docker-compose.yml

# Get service image
yq '.services.web.image' docker-compose.yml

# Get all exposed ports
yq '.services[].ports[]' docker-compose.yml

# Get environment variables
yq '.services.app.environment' docker-compose.yml
```

### Update Compose Files
```bash
# Update image version
yq -i '.services.web.image = "nginx:1.21"' docker-compose.yml

# Add environment variable
yq -i '.services.app.environment.NEW_VAR = "value"' docker-compose.yml

# Update port mapping
yq -i '.services.web.ports = ["80:80", "443:443"]' docker-compose.yml

# Add new service
yq -i '.services.redis = {"image": "redis:alpine", "ports": ["6379:6379"]}' docker-compose.yml
```

## CI/CD Configuration

### GitHub Actions
```bash
# Get workflow jobs
yq '.jobs | keys' .github/workflows/ci.yml

# Update action version
yq -i '.jobs.build.steps[] |= select(.uses | test("actions/checkout")).uses = "actions/checkout@v4"' workflow.yml

# Add environment variable
yq -i '.jobs.test.env.NODE_ENV = "test"' workflow.yml
```

### GitLab CI
```bash
# Get all stages
yq '.stages[]' .gitlab-ci.yml

# Update script
yq -i '.build.script += ["npm run lint"]' .gitlab-ci.yml

# Add job
yq -i '.deploy = {"stage": "deploy", "script": ["./deploy.sh"]}' .gitlab-ci.yml
```

## Advanced Features

### Anchors and Aliases
```bash
# Preserve anchors
yq '.' file.yml  # Anchors preserved by default

# Expand anchors
yq 'explode(.)' file.yml

# Create anchor
yq '.default = {"cpu": "100m"} | .services.web = .default | .default | tag = "!!merge"' file.yml
```

### Comments
```bash
# Preserve comments (default)
yq -i '.version = "2.0"' file.yml

# Add comment
yq '.version = "2.0" | . headComment = "Updated version"' file.yml

# Remove comments
yq --no-comments '.' file.yml
```

### Custom Functions
```bash
# Group by field
yq 'group_by(.category)' items.yml

# Reduce operation
yq '.items | map(.value) | add' file.yml

# Custom filtering function
yq '.items | map(select(.score > 80))' scores.yml
```

### Environment Variables
```bash
# Use env vars in query
NAME=production yq '.envs[] | select(.name == env(NAME))' file.yml

# Substitute env vars in file
yq '.database.host = env(DB_HOST)' config.yml

# Template with env vars
yq eval '.port = env(PORT) | .host = env(HOST)' template.yml
```

## Validation and Formatting

### Validate YAML
```bash
# Check syntax
yq '.' file.yml > /dev/null && echo "Valid"

# Validate and pretty-print
yq '.' file.yml > formatted.yml

# Check for specific structure
yq 'has("required_field")' file.yml
```

### Format YAML
```bash
# Auto-format
yq -i '.' file.yml

# Custom indentation
yq -I 4 '.' file.yml

# Sort keys
yq -i 'sort_keys(.)' file.yml

# Remove empty values
yq 'del(.[] | select(. == null or . == "" or . == []))' file.yml
```

## Best Practices

### DO
- Use `-i` for in-place updates (with backups first)
- Quote expressions to avoid shell interpretation
- Test queries on sample data before batch operations
- Use `eval-all` for multi-file operations
- Preserve comments when possible
- Validate YAML syntax after modifications

### DON'T
- Modify production files without backups
- Chain too many complex operations (split for clarity)
- Ignore YAML type specifics (strings vs numbers)
- Use `-i` without testing first
- Forget to handle multi-document YAML files
- Mix v3 and v4 yq syntax

### Tips
- Use `yq --help` for built-in documentation
- Test complex expressions in yq playground
- Combine with `find` for batch processing
- Use `-P` to pretty-print YAML
- Leverage `-o json` for piping to jq
- Use `--no-colors` for CI/CD pipelines

## Common Patterns

### Configuration Management
```bash
# Update config per environment
for env in dev staging prod; do
  yq -i ".environment = \"$env\" | .api_url = \"https://api.$env.com\"" config-$env.yml
done

# Merge base + environment
yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' base.yml $ENV.yml > final.yml

# Extract secrets
yq '.secrets | to_entries | .[] | .key + "=" + .value' config.yml > .env
```

### Kubernetes Helpers
```bash
# Scale all deployments
yq -i '.spec.replicas = 3' deployments/*.yml

# Update all images to specific tag
yq -i '(.spec.template.spec.containers[].image | select(test("myapp"))) |= sub(":.*", ":v2.0")' *.yml

# Add resource limits
yq -i '.spec.template.spec.containers[0].resources = {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "200m", "memory": "256Mi"}}' deployment.yml
```

### Data Transformation
```bash
# Convert list to map
yq '[.items[] | {(.name): .value}] | add' list.yml

# Flatten nested structure
yq '.[] | to_entries | .[] | .key + ": " + .value' nested.yml

# Pivot data
yq 'group_by(.category) | map({category: .[0].category, items: map(.name)})' data.yml
```

## Troubleshooting

### Common Errors
```bash
# "bad file descriptor" → Check file path
yq '.' non-existent.yml  # Error

# "null" output → Check path expression
yq '.wrong.path' file.yml  # Returns null

# "Error: bad expression" → Quote your expression
yq .path file.yml  # May fail due to shell expansion
yq '.path' file.yml  # Correct
```

### Debugging
```bash
# Print variable
yq '.path | debug' file.yml

# Show type
yq '.field | type' file.yml

# Validate expression
yq --verbose '.' file.yml
```

## Additional Resources

- Official Documentation: https://mikefarah.gitbook.io/yq/
- GitHub Repository: https://github.com/mikefarah/yq
- Online Playground: https://mikefarah.gitbook.io/yq/usage/playground
- Cookbook: https://mikefarah.gitbook.io/yq/recipes

When providing yq guidance, prioritize YAML-specific features (anchors, comments, multi-doc), emphasize in-place editing safety, and suggest format conversions for interoperability.
