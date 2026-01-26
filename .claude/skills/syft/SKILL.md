---
name: syft
description: "SBOM generator for container images, filesystems, and archives. Supports SPDX, CycloneDX, and native formats. Use for: (1) generating software bill of materials, (2) cataloging dependencies, (3) license compliance, (4) supply chain security. Triggers: syft, sbom, software bill of materials, dependency catalog, cyclonedx, spdx, package list."
---

# Syft

Generate Software Bill of Materials (SBOM) from container images, filesystems, and archives.

## Quick Start

```bash
# SBOM for container image
syft <image:tag>

# SBOM for directory
syft dir:.

# SBOM in CycloneDX format
syft -o cyclonedx-json <image:tag>

# SBOM in SPDX format
syft -o spdx-json <image:tag>
```

## Scan Sources

### Container Images

```bash
# From registry
syft alpine:3.18
syft ghcr.io/org/app:latest

# Local Docker image
syft docker:myapp:latest

# Local Podman image
syft podman:myapp:latest

# OCI archive
syft oci-archive:./image.tar

# OCI directory
syft oci-dir:./oci-layout

# Docker archive
syft docker-archive:./image.tar

# Singularity
syft singularity:./image.sif
```

### Filesystem

```bash
# Directory
syft dir:/path/to/project

# Current directory
syft dir:.

# Specific file
syft file:./go.mod
```

### Archives

```bash
# Tar archive
syft ./archive.tar.gz

# Zip file
syft ./archive.zip
```

## Output Formats

### Standard Formats

```bash
# Table (default, human-readable)
syft alpine:3.18

# JSON (syft native)
syft -o json alpine:3.18 > sbom.json

# Text (simple list)
syft -o text alpine:3.18
```

### SPDX Formats

```bash
# SPDX JSON
syft -o spdx-json alpine:3.18 > sbom.spdx.json

# SPDX Tag-Value
syft -o spdx-tag-value alpine:3.18 > sbom.spdx
```

### CycloneDX Formats

```bash
# CycloneDX JSON
syft -o cyclonedx-json alpine:3.18 > sbom.cdx.json

# CycloneDX XML
syft -o cyclonedx-xml alpine:3.18 > sbom.cdx.xml
```

### GitHub Dependency Format

```bash
syft -o github alpine:3.18 > dependencies.json
```

### Multiple Outputs

```bash
syft alpine:3.18 \
  -o json=sbom.json \
  -o spdx-json=sbom.spdx.json \
  -o cyclonedx-json=sbom.cdx.json
```

## Package Catalogers

### Supported Ecosystems

| Language/System | Files Detected |
|-----------------|----------------|
| Alpine | apk database |
| Debian/Ubuntu | dpkg database |
| RHEL/CentOS | rpm database |
| Go | go.mod, go.sum, binaries |
| Java | pom.xml, JAR, WAR |
| JavaScript | package.json, yarn.lock |
| Python | requirements.txt, Pipfile |
| Ruby | Gemfile.lock |
| Rust | Cargo.lock |
| .NET | *.deps.json, packages.config |
| PHP | composer.lock |

### Cataloger Selection

```bash
# List available catalogers
syft cataloger list

# Use specific catalogers
syft --catalogers python,javascript dir:.

# Exclude catalogers
syft --catalogers=-javascript dir:.
```

## Filtering Output

### By Package Type

```bash
# Show only OS packages
syft alpine:3.18 -o json | jq '.artifacts[] | select(.type == "apk")'

# Show only language packages
syft myapp:latest -o json | jq '.artifacts[] | select(.type == "npm" or .type == "python")'
```

### By Metadata

```bash
# Packages with licenses
syft alpine:3.18 -o json | jq '.artifacts[] | select(.licenses != null)'

# Packages from specific location
syft myapp:latest -o json | jq '.artifacts[] | select(.locations[].path | contains("/app"))'
```

## Configuration

### syft.yaml

```yaml
# Output format
output: json

# Cataloger settings
catalogers:
  - python
  - javascript
  - go

# Package settings
package:
  cataloger:
    enabled: true
    scope: all-layers  # or squashed

# File settings
file:
  metadata:
    selection: owned-by-package
    digests:
      - sha256
```

### Scope Options

```bash
# All layers (comprehensive)
syft --scope all-layers alpine:3.18

# Squashed (final filesystem only)
syft --scope squashed alpine:3.18
```

## CI Integration

### GitHub Actions

```yaml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    image: myapp:${{ github.sha }}
    format: cyclonedx-json
    output-file: sbom.cdx.json

- name: Upload SBOM
  uses: actions/upload-artifact@v3
  with:
    name: sbom
    path: sbom.cdx.json
```

### GitLab CI

```yaml
sbom:
  script:
    - syft -o cyclonedx-json myapp:latest > sbom.json
  artifacts:
    paths:
      - sbom.json
```

## Common Patterns

### Full SBOM Pipeline

```bash
# Generate SBOM
syft myapp:latest -o cyclonedx-json > sbom.json

# Scan for vulnerabilities
grype sbom:sbom.json -o json > vulns.json

# Generate report
jq -s '{
  sbom: .[0],
  vulnerabilities: .[1].matches | length,
  critical: [.[1].matches[] | select(.vulnerability.severity == "Critical")] | length
}' sbom.json vulns.json
```

### Compare SBOMs

```bash
# Generate SBOMs for two versions
syft myapp:v1 -o json > sbom-v1.json
syft myapp:v2 -o json > sbom-v2.json

# Find added packages
diff <(jq -r '.artifacts[].name' sbom-v1.json | sort) \
     <(jq -r '.artifacts[].name' sbom-v2.json | sort)
```

### License Extraction

```bash
# List all licenses
syft myapp:latest -o json | jq -r '.artifacts[].licenses[]?.value' | sort -u

# Find packages with specific license
syft myapp:latest -o json | jq '.artifacts[] | select(.licenses[]?.value == "GPL-3.0")'
```

### Dependency Tree

```bash
# Export to JSON and analyze
syft myapp:latest -o json > sbom.json

# Count by type
jq '.artifacts | group_by(.type) | map({type: .[0].type, count: length})' sbom.json

# Count by language
jq '.artifacts | group_by(.language) | map({language: .[0].language, count: length})' sbom.json
```

## Attestation

### SBOM Attestation

```bash
# Sign SBOM with cosign
syft myapp:latest -o cyclonedx-json > sbom.json
cosign attest --predicate sbom.json --type cyclonedx myapp:latest
```

### Verify Attestation

```bash
cosign verify-attestation --type cyclonedx myapp:latest
```

## Integration

For vulnerability scanning of SBOM, use `/grype` or `/trivy`.
For image layer analysis, use `/dive`.
For image inspection, use `/skopeo` or `/crane`.
For Python-specific auditing, use `/pip-audit`.
