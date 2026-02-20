---
name: oci-skopeo
description: "Container image operations without Docker daemon. Inspect, copy, delete, and sync images across registries. Use for: (1) inspecting remote images, (2) copying between registries, (3) mirroring images, (4) working without Docker installed. Triggers: skopeo, image inspect, copy image, registry mirror, docker-less, image manifest, image digest."
---

# Skopeo

Perform container image operations without requiring a Docker daemon.

## Quick Start

```bash
# Inspect remote image
skopeo inspect docker://alpine:3.18

# Copy image between registries
skopeo copy docker://source/image:tag docker://dest/image:tag

# Get image digest
skopeo inspect --format '{{.Digest}}' docker://alpine:3.18

# List tags
skopeo list-tags docker://alpine
```

## Image References

### Transport Formats

| Transport | Format | Description |
|-----------|--------|-------------|
| `docker://` | docker://registry/image:tag | Remote registry |
| `docker-daemon:` | docker-daemon:image:tag | Local Docker |
| `docker-archive:` | docker-archive:file.tar | Docker save format |
| `oci:` | oci:path:tag | OCI layout directory |
| `oci-archive:` | oci-archive:file.tar | OCI archive |
| `dir:` | dir:path | Directory with files |
| `containers-storage:` | containers-storage:image | Podman storage |

## Inspect Operations

### Basic Inspection

```bash
# Full manifest and config
skopeo inspect docker://alpine:3.18

# Raw manifest
skopeo inspect --raw docker://alpine:3.18

# Config blob
skopeo inspect --config docker://alpine:3.18

# Specific architecture
skopeo inspect --override-arch arm64 docker://alpine:3.18
```

### Extract Specific Fields

```bash
# Get digest
skopeo inspect --format '{{.Digest}}' docker://alpine:3.18

# Get labels
skopeo inspect --format '{{.Labels}}' docker://alpine:3.18

# Get environment
skopeo inspect --format '{{.Env}}' docker://alpine:3.18

# Get created date
skopeo inspect --format '{{.Created}}' docker://alpine:3.18

# Get architecture
skopeo inspect --format '{{.Architecture}}' docker://alpine:3.18
```

### List Tags

```bash
# All tags
skopeo list-tags docker://alpine

# Filter with jq
skopeo list-tags docker://alpine | jq '.Tags | map(select(startswith("3.")))'
```

## Copy Operations

### Between Registries

```bash
# Direct copy
skopeo copy docker://source-registry/image:tag docker://dest-registry/image:tag

# With credentials
skopeo copy \
  --src-creds user:pass \
  --dest-creds user:pass \
  docker://source/image:tag docker://dest/image:tag

# Preserve digests
skopeo copy --preserve-digests docker://source/image:tag docker://dest/image:tag
```

### Format Conversion

```bash
# Registry to OCI directory
skopeo copy docker://alpine:3.18 oci:./alpine-oci:3.18

# Registry to Docker archive
skopeo copy docker://alpine:3.18 docker-archive:./alpine.tar:alpine:3.18

# Docker archive to registry
skopeo copy docker-archive:./image.tar docker://registry/image:tag

# OCI to Docker daemon
skopeo copy oci:./image:tag docker-daemon:image:tag
```

### Multi-arch Images

```bash
# Copy all architectures
skopeo copy --all docker://alpine:3.18 docker://myregistry/alpine:3.18

# Copy specific architecture
skopeo copy \
  --override-arch arm64 \
  --override-os linux \
  docker://alpine:3.18 docker://myregistry/alpine:3.18-arm64
```

## Sync Operations

### Mirror Registry

```bash
# Sync single image
skopeo sync --src docker --dest docker alpine:3.18 myregistry.io/mirror/

# Sync from YAML config
skopeo sync --src yaml --dest docker ./sync.yaml myregistry.io/

# Sync directory to registry
skopeo sync --src dir --dest docker ./images/ myregistry.io/images/
```

### Sync Configuration (sync.yaml)

```yaml
registry.hub.docker.com:
  images:
    alpine:
      - "3.18"
      - "3.19"
    nginx:
      - "latest"
      - "alpine"

gcr.io:
  images:
    google-containers/pause:
      - "3.9"
```

## Delete Operations

```bash
# Delete from registry (requires auth)
skopeo delete docker://myregistry/image:tag

# Delete specific digest
skopeo delete docker://myregistry/image@sha256:abc123...
```

## Authentication

### Login Methods

```bash
# Interactive login
skopeo login registry.io

# With credentials
skopeo login -u user -p password registry.io

# With auth file
skopeo login --authfile ~/.docker/config.json registry.io

# AWS ECR
aws ecr get-login-password | skopeo login --password-stdin aws_account.dkr.ecr.region.amazonaws.com
```

### Credential Sources

```bash
# Use Docker config
skopeo copy --authfile ~/.docker/config.json docker://... docker://...

# Separate source/dest credentials
skopeo copy \
  --src-authfile ~/.docker/source-config.json \
  --dest-authfile ~/.docker/dest-config.json \
  docker://source/image:tag docker://dest/image:tag
```

## Common Patterns

### Registry Migration

```bash
# Export image list
skopeo list-tags docker://old-registry/myapp | jq -r '.Tags[]' > tags.txt

# Copy all tags
while read tag; do
  skopeo copy \
    docker://old-registry/myapp:$tag \
    docker://new-registry/myapp:$tag
done < tags.txt
```

### Air-gapped Transfer

```bash
# On connected system: save to archive
skopeo copy docker://alpine:3.18 docker-archive:./alpine-3.18.tar

# Transfer file to air-gapped system
# ...

# On air-gapped system: load to registry
skopeo copy docker-archive:./alpine-3.18.tar docker://internal-registry/alpine:3.18
```

### Verify Image Integrity

```bash
# Get digest from source
SOURCE_DIGEST=$(skopeo inspect --format '{{.Digest}}' docker://source/image:tag)

# Copy and verify
skopeo copy docker://source/image:tag docker://dest/image:tag

# Verify destination
DEST_DIGEST=$(skopeo inspect --format '{{.Digest}}' docker://dest/image:tag)

[ "$SOURCE_DIGEST" = "$DEST_DIGEST" ] && echo "Verified" || echo "Mismatch"
```

### Image Comparison

```bash
# Compare manifests
diff <(skopeo inspect --raw docker://image:v1 | jq -S .) \
     <(skopeo inspect --raw docker://image:v2 | jq -S .)
```

## TLS and Security

```bash
# Skip TLS verification (insecure registries)
skopeo inspect --tls-verify=false docker://insecure-registry:5000/image:tag

# Custom CA certificate
skopeo copy --src-cert-dir /etc/docker/certs.d/registry.io docker://... docker://...

# Disable credential helpers
skopeo copy --src-no-creds docker://public/image:tag docker://...
```

## Integration

For image layer analysis, use `/dive`.
For vulnerability scanning, use `/trivy` or `/grype`.
For SBOM generation, use `/syft`.
For image manipulation, use `/crane`.
