---
name: yq
description: "YAML/JSON/XML processing with jq-like syntax. Use for: (1) querying and updating YAML configs (Kubernetes, Docker Compose, CI/CD), (2) converting between YAML/JSON/XML formats, (3) merging configuration files, (4) automating config management. Triggers: parse YAML, update config file, convert YAML to JSON, merge YAML files, edit Kubernetes manifest."
---

# yq Expertise Skill

Covers yq v4+ (mikefarah/yq). Older Python yq has different syntax.

## Basic Usage

### Read and Query
```bash
yq '.' file.yml                          # Print entire file
yq '.metadata.name' pod.yml              # Get field
yq '.spec.containers[0].image' pod.yml   # Get nested field
yq '.items | length' list.yml            # Array length
yq 'has("metadata")' file.yml            # Check key exists
```

### Output Formats
```bash
yq '.' file.yml             # YAML (default)
yq -o json '.' file.yml     # JSON
yq -o xml '.' file.yml      # XML
yq -o props '.' file.yml    # Properties
yq -o json -I=0 '.' file.yml  # Compact JSON
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
```

### Optional Paths
```bash
yq '.optional.path // "default"' file.yml          # Default if missing
yq '.primary // .fallback // "default"' file.yml   # Alternative chain
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
```

### Map and Transform
```bash
# Map over array
yq '.items | map(.name)' file.yml

# Transform structure
yq '.items[] | {"name": .name, "value": .value}' file.yml

# Sort array
yq '.items | sort_by(.name)' file.yml

# Unique values
yq '.items | unique' file.yml
```

## Updating and Modifying

### Update Values
```bash
yq '.metadata.name = "new-name"' file.yml          # Set value
yq '.spec.replicas = 3' file.yml                   # Nested value
yq -i '.version = "2.0"' file.yml                  # In-place
yq '.replicas = 5 | .version = "2.0"' file.yml     # Multiple
```

### Conditional Updates
```bash
yq '(.items[] | select(.name == "target")).value = "new"' file.yml  # Conditional
yq '.timeout //= 30' file.yml                                       # Default if missing
```

### Array Operations
```bash
# Add to array
yq '.items += ["new-item"]' file.yml

# Prepend to array
yq '.items = ["first"] + .items' file.yml

# Update array element
yq '.items[0].status = "updated"' file.yml

# Delete array element
yq 'del(.items[2])' file.yml
```

### Delete Operations
```bash
yq 'del(.unwanted)' file.yml                                      # Delete key
yq 'del(.spec.template.metadata.labels.old)' file.yml             # Nested
yq 'del(.items[] | select(.deprecated == true))' file.yml         # Matching
yq -i 'del(.temporary)' file.yml                                  # In-place
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
```

### Process Multiple Files
```bash
# Combine all files
yq eval-all '.' *.yml

# Extract from all files
yq '.metadata.name' *.yml

# Update all files
yq -i '.version = "2.0"' *.yml
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
```

## CI/CD Configuration

### GitHub Actions
```bash
# Get workflow jobs
yq '.jobs | keys' .github/workflows/ci.yml

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

## Resources

See `references/examples.md` and `references/quick-reference.md`.
