---
name: sec-trivy
description: "Comprehensive vulnerability and misconfiguration scanner for containers, filesystems, repos, and Kubernetes. Use for: (1) container image scanning, (2) filesystem vulnerability detection, (3) IaC misconfiguration scanning, (4) Kubernetes security audits, (5) SBOM vulnerability matching. Triggers: trivy, vulnerability scan, container security, CVE scan, image scan, misconfiguration, security scanner."
---

# Trivy

Comprehensive security scanner for vulnerabilities, misconfigurations, secrets, and licenses.

## Quick Start

```bash
# Scan container image
trivy image <image:tag>

# Scan local filesystem
trivy fs .

# Scan repository
trivy repo https://github.com/org/repo

# Scan Kubernetes cluster
trivy k8s --report summary cluster
```

## Scan Targets

### Container Images

```bash
# From registry
trivy image alpine:3.18
trivy image ghcr.io/org/app:latest

# Local image
trivy image myapp:local

# Image archive
trivy image --input ./image.tar

# OCI layout
trivy image --input ./oci-layout
```

### Filesystem

```bash
# Current directory
trivy fs .

# Specific path
trivy fs /path/to/project

# With secret scanning
trivy fs --scanners vuln,secret,config .
```

### Git Repository

```bash
# Remote repository
trivy repo https://github.com/org/repo

# Specific branch
trivy repo --branch develop https://github.com/org/repo

# Specific commit
trivy repo --commit abc123 https://github.com/org/repo
```

### Kubernetes

```bash
# Cluster scan
trivy k8s --report summary cluster

# Specific namespace
trivy k8s -n production --report all all

# Workload vulnerabilities
trivy k8s --scanners vuln deployment/myapp

# RBAC analysis
trivy k8s --scanners rbac cluster
```

## Scanner Types

### Vulnerability Scanner

```bash
# OS packages + language packages
trivy image --scanners vuln alpine:3.18

# Severity filtering
trivy image --severity CRITICAL,HIGH alpine:3.18

# Ignore unfixed
trivy image --ignore-unfixed alpine:3.18

# Show fixed version
trivy image --show-suppressed alpine:3.18
```

### Misconfiguration Scanner

```bash
# Dockerfile checks
trivy config Dockerfile

# Terraform scanning
trivy config --tf-vars terraform.tfvars ./iac-terraform

# Kubernetes manifests
trivy config ./k8s-manifests/

# Helm charts
trivy config ./charts/myapp
```

### Secret Scanner

```bash
# Find secrets in filesystem
trivy fs --scanners secret .

# Find secrets in image
trivy image --scanners secret myapp:latest

# Custom secret patterns
trivy fs --secret-config ./trivy-secret.yaml .
```

### License Scanner

```bash
# Detect licenses
trivy image --scanners license alpine:3.18

# Forbidden licenses
trivy image --license-full --ignored-licenses MIT,Apache-2.0 alpine:3.18
```

## Severity Levels

| Level | Description |
|-------|-------------|
| CRITICAL | Must fix immediately |
| HIGH | Fix as soon as possible |
| MEDIUM | Fix in next release |
| LOW | Fix when convenient |
| UNKNOWN | Severity not determined |

```bash
# Only critical and high
trivy image --severity CRITICAL,HIGH alpine:3.18

# Exit code on severity
trivy image --exit-code 1 --severity CRITICAL alpine:3.18
```

## Output Formats

```bash
# Table (default)
trivy image alpine:3.18

# JSON
trivy image -f json -o results.json alpine:3.18

# SARIF (for GitHub Security)
trivy image -f sarif -o results.sarif alpine:3.18

# CycloneDX SBOM
trivy image -f cyclonedx -o sbom.json alpine:3.18

# SPDX SBOM
trivy image -f spdx-json -o sbom.spdx.json alpine:3.18

# Template
trivy image -f template --template "@contrib/html.tpl" alpine:3.18
```

## Filtering Results

### Ignore File (.trivyignore)

```
# Ignore specific CVEs
CVE-2023-12345
CVE-2023-67890

# Ignore by package
exp:golang.org/x/text

# Ignore with expiration
CVE-2023-11111 exp:2024-01-01
```

### Ignore Policy (.trivyignore.yaml)

```yaml
vulnerabilities:
  - id: CVE-2023-12345
    statement: "Not exploitable in our context"

  - id: CVE-2023-67890
    paths:
      - /usr/lib/x86_64-linux-gnu/libcrypto.so.3
    statement: "Fixed in next release"

misconfigurations:
  - id: DS002
    statement: "Root user required for this container"
```

## CI Integration

### GitHub Actions

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'myapp:${{ github.sha }}'
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'

- name: Upload Trivy scan results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: 'trivy-results.sarif'
```

### Exit Codes

```bash
# Exit 1 if vulnerabilities found
trivy image --exit-code 1 myapp:latest

# Exit 1 only for CRITICAL
trivy image --exit-code 1 --severity CRITICAL myapp:latest
```

## Common Patterns

### Full Image Audit

```bash
trivy image \
  --scanners vuln,secret,config \
  --severity CRITICAL,HIGH,MEDIUM \
  -f json \
  -o full-audit.json \
  myapp:latest
```

### Terraform Security Check

```bash
trivy config \
  --severity CRITICAL,HIGH \
  --exit-code 1 \
  ./iac-terraform
```

### Kubernetes Pre-deploy

```bash
trivy k8s \
  --report all \
  --severity CRITICAL,HIGH \
  --exit-code 1 \
  -n staging \
  all
```

### SBOM Vulnerability Check

```bash
# Generate SBOM
trivy image -f cyclonedx -o sbom.json myapp:latest

# Check SBOM for vulnerabilities
trivy sbom sbom.json
```

## Database Management

```bash
# Download/update database
trivy image --download-db-only

# Skip database update
trivy image --skip-db-update alpine:3.18

# Use offline database
trivy image --offline-scan alpine:3.18

# Clear cache
trivy clean --all
```

## Integration

For SBOM generation, use `/syft`.
For alternative vulnerability scanning, use `/grype`.
For image layer analysis, use `/dive`.
For dependency auditing in Python, use `/pip-audit`.
