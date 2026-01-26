---
name: crane
description: "Container image manipulation tool for registries. Push, pull, copy, mutate, and inspect images. Use for: (1) image manipulation, (2) registry operations, (3) layer extraction, (4) manifest inspection, (5) tag management. Triggers: crane, image manipulation, registry push, image layers, manifest, gcrane, image copy."
---

# Crane

Interact with remote container registries for image manipulation and inspection.

## Quick Start

```bash
# Pull image to tarball
crane pull alpine:3.18 alpine.tar

# Push tarball to registry
crane push image.tar myregistry/image:tag

# Copy image between registries
crane copy source/image:tag dest/image:tag

# Get manifest
crane manifest alpine:3.18
```

## Inspection Commands

### Manifest Operations

```bash
# Get manifest
crane manifest alpine:3.18

# Get manifest digest
crane digest alpine:3.18

# Get manifest for specific platform
crane manifest --platform linux/arm64 alpine:3.18

# List manifests (multi-arch)
crane manifest alpine:3.18 | jq '.manifests'
```

### Configuration

```bash
# Get image config
crane config alpine:3.18

# Get config digest
crane config alpine:3.18 | jq -r '.config.digest'

# View environment variables
crane config alpine:3.18 | jq '.config.Env'

# View labels
crane config alpine:3.18 | jq '.config.Labels'

# View entrypoint/cmd
crane config alpine:3.18 | jq '{entrypoint: .config.Entrypoint, cmd: .config.Cmd}'
```

### Layer Information

```bash
# List layers
crane manifest alpine:3.18 | jq '.layers'

# Get layer digests
crane manifest alpine:3.18 | jq -r '.layers[].digest'

# Export specific layer
crane blob alpine:3.18@sha256:abc123... > layer.tar.gz
```

## Registry Operations

### Pull and Push

```bash
# Pull to local tarball
crane pull alpine:3.18 alpine.tar

# Pull specific platform
crane pull --platform linux/amd64 alpine:3.18 alpine-amd64.tar

# Push tarball to registry
crane push myimage.tar myregistry/myimage:tag

# Push with platform
crane push --platform linux/amd64 myimage.tar myregistry/myimage:tag
```

### Copy Images

```bash
# Copy between registries
crane copy source-registry/image:tag dest-registry/image:tag

# Copy all tags
crane copy --all-tags source/image dest/image

# Copy preserving digest
crane copy source/image@sha256:abc123 dest/image:tag
```

### Tag Management

```bash
# List tags
crane ls gcr.io/google-containers/pause

# Tag image
crane tag myregistry/image:latest myregistry/image:v1.0.0

# Delete tag (careful!)
crane delete myregistry/image:tag
```

## Image Mutation

### Append Layers

```bash
# Append tarball as new layer
crane append -f layer.tar.gz -t myregistry/image:new alpine:3.18

# Append with platform
crane append \
  --platform linux/amd64 \
  -f layer.tar.gz \
  -t myregistry/image:new \
  alpine:3.18
```

### Mutate Configuration

```bash
# Change entrypoint
crane mutate --entrypoint /bin/sh alpine:3.18 -t myregistry/alpine:custom

# Add environment variable
crane mutate --env FOO=bar alpine:3.18 -t myregistry/alpine:custom

# Add label
crane mutate --label version=1.0 alpine:3.18 -t myregistry/alpine:custom

# Change user
crane mutate --user nobody alpine:3.18 -t myregistry/alpine:custom

# Set working directory
crane mutate --workdir /app alpine:3.18 -t myregistry/alpine:custom

# Combined mutations
crane mutate \
  --entrypoint /app/run.sh \
  --env APP_ENV=production \
  --label maintainer=team@example.com \
  --user appuser \
  alpine:3.18 \
  -t myregistry/alpine:production
```

### Flatten Image

```bash
# Flatten to single layer
crane flatten alpine:3.18 -t myregistry/alpine:flat
```

### Rebase Image

```bash
# Rebase on new base image
crane rebase \
  --old-base alpine:3.17 \
  --new-base alpine:3.18 \
  myimage:old \
  -t myimage:rebased
```

## Authentication

```bash
# Login to registry
crane auth login registry.io -u username -p password

# Login with token
crane auth login gcr.io -u _token -p $(gcloud auth print-access-token)

# Get token (for scripting)
crane auth token myregistry/image:tag

# AWS ECR
crane auth login $(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-east-1.amazonaws.com
```

## Multi-platform Images

### Inspect

```bash
# List platforms
crane manifest alpine:3.18 | jq '.manifests[] | {platform: .platform, digest: .digest}'

# Get specific platform manifest
crane manifest --platform linux/arm64 alpine:3.18
```

### Build Multi-arch

```bash
# Create index from platform-specific images
crane index append \
  -t myregistry/image:multi \
  -m myregistry/image:amd64 \
  -m myregistry/image:arm64
```

## Common Patterns

### Registry Mirror

```bash
# Mirror image
crane copy docker.io/library/alpine:3.18 myregistry.io/mirror/alpine:3.18

# Mirror with all tags
crane copy --all-tags docker.io/library/nginx myregistry.io/mirror/nginx
```

### Extract File from Image

```bash
# Pull and extract
crane pull alpine:3.18 - | tar -xf - -O etc/os-release
```

### Layer Extraction

```bash
# Get layer digests
LAYERS=$(crane manifest alpine:3.18 | jq -r '.layers[].digest')

# Extract each layer
for layer in $LAYERS; do
  crane blob alpine:3.18@$layer > layer-${layer#sha256:}.tar.gz
done
```

### Image Size Analysis

```bash
# Get total size
crane manifest alpine:3.18 | jq '[.layers[].size] | add'

# Size per layer
crane manifest alpine:3.18 | jq '.layers[] | {digest: .digest, size: .size, human: (.size / 1048576 | floor | tostring + " MB")}'
```

### Verify Image

```bash
# Get and verify digest
EXPECTED="sha256:abc123..."
ACTUAL=$(crane digest alpine:3.18)

[ "$EXPECTED" = "$ACTUAL" ] && echo "Verified" || echo "Digest mismatch"
```

### Export for Air-gap

```bash
# Save with all platforms
crane pull --platform all alpine:3.18 alpine-all.tar

# Save specific platforms
crane pull --platform linux/amd64 alpine:3.18 alpine-amd64.tar
crane pull --platform linux/arm64 alpine:3.18 alpine-arm64.tar
```

## gcrane (Google Cloud)

```bash
# Copy within GCR
gcrane copy gcr.io/project1/image:tag gcr.io/project2/image:tag

# Garbage collect old images
gcrane gc gcr.io/project/image
```

## Integration

For image layer analysis, use `/dive`.
For image inspection without Docker, use `/skopeo`.
For vulnerability scanning, use `/trivy` or `/grype`.
For SBOM generation, use `/syft`.
