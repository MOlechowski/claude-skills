---
name: oci-dive
description: "Docker image layer explorer for analyzing image contents, finding wasted space, and detecting secrets/bloat. Use for: (1) exploring image layers interactively, (2) finding secrets or sensitive files, (3) optimizing image size, (4) CI efficiency checks. Triggers: dive, image layers, docker image analyze, image efficiency, find secrets in image, image bloat."
---

# Dive

Explore Docker image layers to find secrets, bloat, and optimization opportunities.

## Quick Start

```bash
# Analyze image interactively
dive <image:tag>

# Analyze local image
dive <image-id>

# Build and analyze
dive build -t <tag> .

# CI mode (non-interactive)
dive <image> --ci
```

## Core Commands

### Interactive Exploration

```bash
# Explore image from registry
dive alpine:latest

# Explore local image by ID
dive $(docker images -q myapp:latest)

# Explore with source
dive --source docker myapp:latest
dive --source podman myapp:latest
dive --source docker-archive ./image.tar
```

### CI Integration

```bash
# CI mode with exit code
dive --ci myapp:latest

# Custom thresholds
dive --ci --lowestEfficiency 0.9 --highestWastedBytes 20MB myapp:latest

# JSON output
dive --ci --json myapp:latest > report.json
```

## Interactive Controls

| Key | Action |
|-----|--------|
| `Tab` | Switch between layer/file views |
| `Ctrl+Space` | Collapse/expand directory |
| `Space` | Toggle file tree visibility |
| `Ctrl+A` | Show/hide added files |
| `Ctrl+R` | Show/hide removed files |
| `Ctrl+M` | Show/hide modified files |
| `Ctrl+U` | Show/hide unmodified files |
| `Ctrl+L` | Toggle layer details |
| `Ctrl+F` | Filter files |
| `Ctrl+C` | Exit |

## File Status Indicators

| Symbol | Meaning |
|--------|---------|
| `+` | Added in this layer |
| `-` | Removed in this layer |
| `M` | Modified in this layer |
| (none) | Unchanged from previous layer |

## Efficiency Analysis

### Understanding Metrics

```
Image efficiency score: 0.95 (higher is better)
Wasted space: 12 MB

Layer Details:
├── Layer 1: 5.2 MB (base image)
├── Layer 2: 120 KB (apt update)
├── Layer 3: 45 MB (install packages)
├── Layer 4: -45 MB (cleanup) <- wasted if Layer 3 could be combined
└── Layer 5: 2 MB (app code)
```

### Common Waste Patterns

**Package manager caches:**
```dockerfile
# Bad: cache remains in layer
RUN apt-get update && apt-get install -y curl

# Good: single layer cleanup
RUN apt-get update && apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/*
```

**Build artifacts:**
```dockerfile
# Bad: build tools in final image
RUN npm install && npm run build

# Good: multi-stage build
FROM node:18 AS builder
RUN npm install && npm run build

FROM node:18-slim
COPY --from=builder /app/dist ./dist
```

## Finding Secrets

### What to Look For

| Pattern | Risk |
|---------|------|
| `.env`, `.env.*` | Environment secrets |
| `*.pem`, `*.key` | Private keys |
| `.git/` | Repository history |
| `*.log` | Debug information |
| `.aws/`, `.ssh/` | Credential directories |
| `*_history` | Shell history |

### Detection Workflow

1. Run `dive <image>`
2. Press `Tab` to switch to file tree
3. Use `Ctrl+F` to filter: `.env`, `.key`, `.pem`, `.git`
4. Check each layer for sensitive additions
5. Note which layer introduced the file

## CI Configuration

### .dive-ci File

```yaml
rules:
  # Fail if efficiency is below threshold
  lowestEfficiency: 0.9

  # Fail if wasted space exceeds threshold
  highestWastedBytes: 20MB

  # Fail if too many user wasted bytes
  highestUserWastedPercent: 0.1
```

### GitHub Actions Example

```yaml
- name: Analyze Docker image
  run: |
    dive --ci --json ${{ env.IMAGE }} > dive-report.json

- name: Check efficiency
  run: |
    EFFICIENCY=$(jq '.image.efficiencyScore' dive-report.json)
    if (( $(echo "$EFFICIENCY < 0.9" | bc -l) )); then
      echo "Image efficiency too low: $EFFICIENCY"
      exit 1
    fi
```

## Common Patterns

### Dockerfile Optimization

```bash
# Analyze current image
dive myapp:current

# Identify wasted layers
# Look for:
# - Large additions followed by deletions
# - Cache directories
# - Build-time dependencies

# Rebuild with optimizations
docker build -t myapp:optimized .
dive myapp:optimized

# Compare efficiency scores
```

### Multi-stage Build Analysis

```bash
# Analyze builder stage
docker build --target builder -t myapp:builder .
dive myapp:builder

# Analyze final stage
docker build -t myapp:final .
dive myapp:final

# Compare sizes and contents
```

### Registry Image Audit

```bash
# Pull and analyze third-party images
dive nginx:alpine
dive python:3.11-slim
dive node:18-alpine

# Check for unexpected files
# Verify base image efficiency
```

## Output Formats

### JSON Report

```bash
dive --ci --json myapp:latest
```

```json
{
  "image": {
    "efficiencyScore": 0.95,
    "sizeBytes": 125000000,
    "inefficientBytes": 6250000
  },
  "layer": [
    {
      "index": 0,
      "digestId": "sha256:...",
      "sizeBytes": 5000000,
      "command": "/bin/sh -c #(nop) ADD file:..."
    }
  ]
}
```

## Integration

For vulnerability scanning of discovered files, use `/trivy` or `/grype`.
For SBOM generation from image contents, use `/syft`.
For image manipulation and copying, use `/crane` or `/skopeo`.
