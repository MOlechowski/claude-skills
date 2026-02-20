---
name: sec-grype
description: "Fast vulnerability scanner for container images and filesystems using SBOM input. Use for: (1) container vulnerability scanning, (2) SBOM vulnerability matching, (3) CI/CD security gates, (4) multi-format output. Triggers: grype, vulnerability scan, CVE scan, sbom scan, container vulnerabilities, security scan."
---

# Grype

Fast vulnerability scanner for container images and filesystems. Works directly or from SBOM input.

## Quick Start

```bash
# Scan container image
grype <image:tag>

# Scan directory
grype dir:.

# Scan SBOM
grype sbom:./sbom.json

# Scan with severity filter
grype --fail-on high <image:tag>
```

## Scan Sources

### Container Images

```bash
# From registry
grype alpine:3.18
grype ghcr.io/org/app:latest

# Local Docker image
grype docker:myapp:latest

# Local Podman image
grype podman:myapp:latest

# OCI archive
grype oci-archive:./image.tar

# OCI directory
grype oci-dir:./oci-layout

# Docker archive
grype docker-archive:./image.tar

# Singularity
grype singularity:./image.sif
```

### Filesystem

```bash
# Directory
grype dir:/path/to/project

# Current directory
grype dir:.

# Specific file
grype file:./package-lock.json
```

### SBOM Input

```bash
# From syft JSON
grype sbom:./sbom.json

# From CycloneDX
grype sbom:./bom.json

# From SPDX
grype sbom:./spdx.json

# Piped from syft
syft alpine:3.18 -o json | grype
```

## Output Formats

```bash
# Table (default)
grype alpine:3.18

# JSON
grype -o json alpine:3.18 > results.json

# CycloneDX
grype -o cyclonedx-json alpine:3.18 > results.cdx.json

# SARIF (GitHub Security)
grype -o sarif alpine:3.18 > results.sarif

# Template
grype -o template -t ./custom.tmpl alpine:3.18
```

## Severity Filtering

| Level | Description |
|-------|-------------|
| Critical | CVSS 9.0-10.0 |
| High | CVSS 7.0-8.9 |
| Medium | CVSS 4.0-6.9 |
| Low | CVSS 0.1-3.9 |
| Negligible | Minimal risk |
| Unknown | Not scored |

```bash
# Show only high and critical
grype --only-fixed --fail-on high alpine:3.18

# Fail CI on specific severity
grype --fail-on critical alpine:3.18 && echo "No critical vulnerabilities"
```

## Ignore Patterns

### .grype.yaml Configuration

```yaml
ignore:
  # Ignore specific CVE
  - vulnerability: CVE-2023-12345

  # Ignore CVE in specific package
  - vulnerability: CVE-2023-67890
    package:
      name: openssl
      version: 1.1.1

  # Ignore by fix state
  - fix-state: not-fixed

  # Ignore by path
  - vulnerability: CVE-2023-11111
    package:
      location: /usr/lib/
```

### Ignore File (.grype-ignore)

```
# One CVE per line
CVE-2023-12345
CVE-2023-67890
GHSA-xxxx-yyyy-zzzz
```

## CI Integration

### Exit Codes

```bash
# Exit 1 if any vulnerabilities found
grype --fail-on low alpine:3.18

# Exit 1 only for high/critical
grype --fail-on high alpine:3.18

# Custom exit codes
grype alpine:3.18; [ $? -eq 0 ] && echo "Clean" || echo "Vulnerabilities found"
```

### GitHub Actions

```yaml
- name: Scan image
  uses: anchore/scan-action@v3
  with:
    image: myapp:${{ github.sha }}
    fail-build: true
    severity-cutoff: high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  script:
    - grype --fail-on high -o json myapp:latest > grype-report.json
  artifacts:
    reports:
      container_scanning: grype-report.json
```

## Database Management

```bash
# Check database status
grype db status

# Update database
grype db update

# Delete database
grype db delete

# Import database from file
grype db import ./vulnerability-db.tar.gz

# List available databases
grype db list
```

## Common Patterns

### Full Vulnerability Report

```bash
grype alpine:3.18 \
  -o json \
  --add-cpes-if-none \
  > full-report.json
```

### SBOM-Based Scanning

```bash
# Generate SBOM first
syft alpine:3.18 -o json > sbom.json

# Scan SBOM for vulnerabilities
grype sbom:sbom.json -o json > vulns.json

# Combine with jq
jq -s '.[0] as $sbom | .[1] as $vulns | {sbom: $sbom, vulnerabilities: $vulns}' \
  sbom.json vulns.json > combined.json
```

### Compare Two Images

```bash
# Scan both images
grype -o json image1:latest > vulns1.json
grype -o json image2:latest > vulns2.json

# Find differences
diff <(jq -r '.matches[].vulnerability.id' vulns1.json | sort) \
     <(jq -r '.matches[].vulnerability.id' vulns2.json | sort)
```

### Monitor for New Vulnerabilities

```bash
# Update database and rescan
grype db update
grype --only-notfixed myapp:production -o json > current-vulns.json

# Compare with previous scan
diff previous-vulns.json current-vulns.json
```

## Advanced Configuration

### grype.yaml

```yaml
# Database settings
db:
  auto-update: true
  cache-dir: ~/.cache/grype/db

# Output settings
output: table
quiet: false

# Matching settings
match:
  java:
    using-cpes: true
  javascript:
    using-cpes: false
  python:
    using-cpes: true

# Ignore rules
ignore:
  - vulnerability: CVE-2023-12345
```

## Integration

For SBOM generation, use `/syft`.
For comprehensive scanning (including misconfigs), use `/trivy`.
For image layer analysis, use `/dive`.
For image inspection without Docker, use `/skopeo`.
