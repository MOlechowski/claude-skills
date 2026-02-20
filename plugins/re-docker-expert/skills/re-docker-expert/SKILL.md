---
name: re-docker-expert
description: "Container forensics and security analysis expertise: layer analysis, secret extraction, build reconstruction, image forensics. Delegates to tool skills (dive, crane, skopeo, syft, trivy, grype). Use for: container security audits, finding secrets in images, reconstructing Dockerfiles, incident response on containers, supply chain analysis. Triggers: docker forensics, container analysis, image layers, find secrets in container, reconstruct dockerfile, container incident response, image security audit."
---

# Container Forensics Expert

Domain expertise for Docker/container security analysis and forensics. Provides methodology, tool selection guidance, and analysis strategies.

**Delegate to tool-specific skills:** `/dive`, `/crane`, `/skopeo`, `/syft`, `/trivy`, `/grype`

## Analysis Methodology

### Phase 1: Triage

Quick identification before deep analysis:

```bash
# Get image metadata
docker inspect <image>

# Get manifest (without pulling)
crane manifest <image>

# Quick config check
crane config <image> | jq '.config'
```

### Phase 2: Static Analysis

Analyze without running:

1. **Manifest examination** - Image structure, layers, platforms
2. **Configuration review** - Env vars, entrypoint, user, labels
3. **Layer inspection** - What each layer adds/removes
4. **SBOM generation** - Software inventory
5. **Vulnerability scanning** - Known CVEs

### Phase 3: Deep Forensics

Detailed investigation:

1. **Layer extraction** - Pull individual layers as tarballs
2. **Filesystem reconstruction** - Rebuild full filesystem
3. **Secret hunting** - Find credentials, keys, tokens
4. **Build reconstruction** - Reverse engineer Dockerfile
5. **Timeline analysis** - Correlate timestamps with events

### When to Use Each Phase

| Scenario | Phase | Start With |
|----------|-------|------------|
| Security audit | 2 + 3 | Vulnerability scan |
| Secret leak investigation | 3 | Layer exploration |
| Unknown image triage | 1 | Manifest inspection |
| Incident response | 1 + 2 + 3 | Full forensic workflow |
| Supply chain analysis | 2 | SBOM generation |
| Compliance check | 2 | Vulnerability + license scan |

## Tool Selection

### Decision Matrix

| Task | Best Tool | Alternative | Notes |
|------|-----------|-------------|-------|
| Layer exploration | dive | crane blob | dive is interactive |
| Vulnerability scan | trivy | grype | trivy is more comprehensive |
| SBOM generation | syft | trivy -f cyclonedx | syft is SBOM-focused |
| Manifest inspection | crane manifest | skopeo inspect | crane is simpler |
| Layer extraction | crane blob | skopeo copy oci: | crane extracts single layers |
| Registry operations | skopeo | crane | skopeo works without daemon |
| Secret detection | trivy --scanners secret | dive manual | trivy is automated |
| Image copy/mirror | skopeo copy | crane copy | skopeo handles more formats |
| Config analysis | crane config | docker inspect | crane works remotely |

### Tool Capabilities

**oci-dive** - Interactive layer explorer
- Visual layer-by-layer filesystem diff
- Wasted space identification
- File filtering and search
- Efficiency scoring

**oci-crane** - Registry manipulation
- Manifest/config inspection
- Individual layer extraction
- Image mutation (labels, env, entrypoint)
- Multi-platform handling

**oci-skopeo** - Daemon-less operations
- Format conversion (OCI, Docker archive, dir)
- Registry mirroring and sync
- Air-gapped transfers
- No Docker daemon required

**oci-syft** - SBOM generator
- Multi-format output (SPDX, CycloneDX)
- All major package managers
- License extraction
- Attestation support

**sec-trivy** - Comprehensive scanner
- Vulnerabilities, secrets, misconfigs
- Multiple targets (images, fs, repos, k8s)
- SARIF output for CI
- Offline scanning support

**sec-grype** - Fast vulnerability scanner
- SBOM-based scanning
- Minimal false positives
- Quick CI/CD integration
- Focused scope

## Use Case Workflows

### Layer Analysis

**Goal:** Understand what each layer contains and how image was built.

```bash
# Interactive exploration
dive <image>
# Tab: switch views, Ctrl+U: show unmodified, Ctrl+F: filter

# Extract specific layer
crane blob <image>@sha256:<layer_digest> | tar -tzf -

# Get layer history
crane config <image> | jq '.history'
```

**Layer status indicators (dive):**
- `+` Added in this layer
- `-` Removed in this layer
- `M` Modified in this layer

**What to look for:**
- Large unexplained files
- Configuration files added late
- Files removed but still in earlier layers (secrets!)
- Unnecessary build artifacts

### Secret Extraction

**Goal:** Find hardcoded credentials, keys, tokens.

| Secret Type | Common Paths | Detection Method |
|-------------|--------------|------------------|
| Environment secrets | .env, .env.* | Layer exploration |
| Private keys | *.pem, *.key, *.p12 | trivy secret scan |
| SSH keys | .ssh/, id_rsa | Path filtering |
| Cloud credentials | .aws/, .gcp/, .azure/ | Path filtering |
| Git credentials | .git-credentials, .netrc | Layer exploration |
| Build args (exposed) | Image config | crane config |

**Automated scan:**
```bash
trivy image --scanners secret <image>
```

**Manual exploration:**
```bash
dive <image>
# Filter: .env, .key, .pem, .git, config, secret, credential
```

**Check for secrets in removed files:**
```bash
# Secrets might be deleted in later layers but exist in earlier ones
crane config <image> | jq '.history[] | select(.created_by | contains("rm"))'
```

### Build Reconstruction

**Goal:** Reverse engineer the Dockerfile.

```bash
# Get build history
crane config <image> | jq -r '.history[].created_by' | grep -v '#(nop)'

# Full history with timestamps
crane config <image> | jq '.history[] | {created, created_by}'
```

**Reconstruct Dockerfile:**
1. Extract base image from first layer
2. Map history entries to Dockerfile instructions
3. Note: ARG values and multi-stage builds may be hidden

**History to Dockerfile mapping:**
| History Pattern | Dockerfile Instruction |
|-----------------|----------------------|
| `/bin/sh -c #(nop) ADD file:...` | ADD or COPY |
| `/bin/sh -c #(nop) ENV ...` | ENV |
| `/bin/sh -c #(nop) WORKDIR ...` | WORKDIR |
| `/bin/sh -c #(nop) EXPOSE ...` | EXPOSE |
| `/bin/sh -c #(nop) CMD ...` | CMD |
| `/bin/sh -c #(nop) ENTRYPOINT ...` | ENTRYPOINT |
| `/bin/sh -c <command>` | RUN |

### Forensic Analysis

**Goal:** Incident response, evidence preservation, attribution.

See [references/forensic-workflow.md](references/forensic-workflow.md) for detailed procedures.

**Quick forensic triage:**
```bash
# 1. Preserve evidence (immutable copy)
skopeo copy docker://<image> oci:./evidence:latest
sha256sum evidence/index.json > evidence.sha256

# 2. Extract all layers
crane pull <image> image.tar
mkdir layers && tar -xf image.tar -C layers

# 3. Scan for IOCs
trivy image --scanners vuln,secret,misconfig <image>

# 4. Analyze build timeline
crane config <image> | jq '.history'
```

## Container Image Structure

### Manifest Types

| Format | Media Type | Use Case |
|--------|------------|----------|
| Docker v2 | application/vnd.docker.distribution.manifest.v2+json | Standard Docker |
| OCI | application/vnd.oci.image.manifest.v1+json | OCI-compliant |
| Manifest list | application/vnd.docker.distribution.manifest.list.v2+json | Multi-arch Docker |
| OCI index | application/vnd.oci.image.index.v1+json | Multi-arch OCI |

### Image Components

```
Image
├── Manifest (references config + layers)
├── Config (metadata, env, entrypoint, history)
└── Layers (filesystem tarballs, ordered)
    ├── Layer 1 (base)
    ├── Layer 2
    └── Layer N (top)
```

### Layer Filesystem

Layers use overlay filesystem:
- Each layer is a tarball of changes
- Upper layers override lower layers
- Deleted files marked with whiteout files (`.wh.<filename>`)
- Opaque directories marked with `.wh..wh..opq`

## Common Patterns

### Security Audit Workflow

```bash
# 1. Generate SBOM
syft <image> -o cyclonedx-json > sbom.json

# 2. Vulnerability scan
trivy image --severity CRITICAL,HIGH <image>
# Or SBOM-based
grype sbom:sbom.json

# 3. Secret scan
trivy image --scanners secret <image>

# 4. Layer analysis
dive <image>
# Look for: secrets, build artifacts, unnecessary files

# 5. Configuration review
crane config <image> | jq '.config'
# Check: user (root?), exposed ports, env vars
```

### Incident Response Workflow

```bash
# 1. Preserve evidence
skopeo copy docker://<image> oci:./evidence:$(date +%Y%m%d)
sha256sum evidence/* > checksums.txt

# 2. Document image details
crane manifest <image> > manifest.json
crane config <image> > config.json

# 3. Scan for malware indicators
trivy image --scanners vuln,secret,misconfig <image> -f json > scan.json

# 4. Layer-by-layer analysis
dive <image>
# Document suspicious files, timestamps, modifications

# 5. Extract suspicious layers for deep analysis
crane blob <image>@sha256:<suspicious_layer> > layer.tar.gz
```

### Supply Chain Analysis

```bash
# 1. Identify base image
crane config <image> | jq '.history[0]'

# 2. Generate SBOM
syft <image> -o spdx-json > sbom.json

# 3. Check for known vulnerabilities
grype sbom:sbom.json

# 4. Verify image signatures (if signed)
cosign verify <image>

# 5. Check provenance (if attested)
cosign verify-attestation <image>
```

## Red Flags and Indicators

### Suspicious Patterns

| Indicator | Risk Level | Investigation |
|-----------|------------|---------------|
| Large unexplained layers | Medium | Extract and analyze contents |
| Empty/minimal history | High | Image may be tampered |
| Network tools (curl, wget, nc) | Medium | Check if needed |
| Root user configured | Medium | Verify necessity |
| Unusual entrypoint/cmd | High | Analyze startup behavior |
| Recent base image change | Medium | Compare with previous |
| Crypto mining packages | Critical | Likely compromised |
| Reverse shell tools | Critical | Likely compromised |

### Secret Indicators

| Path/Pattern | Type | Risk |
|--------------|------|------|
| .env, .env.* | Environment file | High |
| *.pem, *.key, *.p12, *.pfx | Private keys | Critical |
| .git/ | Git history | High (may contain secrets in commits) |
| .aws/, .ssh/, .kube/, .azure/ | Cloud/SSH creds | Critical |
| *_history, .*_history | Shell history | Medium |
| config.json, secrets.*, credentials.* | Config files | High |
| id_rsa, id_ed25519 | SSH private keys | Critical |
| .npmrc, .pypirc | Package manager creds | High |

### Malware Indicators

| Indicator | Description |
|-----------|-------------|
| /tmp or /var/tmp executables | Common malware staging |
| Cron jobs in image | Persistence mechanism |
| Modified system binaries | Rootkit behavior |
| Base64-encoded scripts | Obfuscation |
| Outbound network config | C2 communication |

## Skill Delegation

| Task | Delegate To |
|------|-------------|
| Interactive layer exploration | `/dive` |
| Manifest and config inspection | `/crane` |
| Daemon-less image operations | `/skopeo` |
| SBOM generation | `/syft` |
| Comprehensive scanning | `/trivy` |
| SBOM-based vulnerability scan | `/grype` |

## Quick Reference

### Triage Commands

```bash
crane manifest <image>                    # Get manifest
crane config <image> | jq '.config'       # Get runtime config
crane config <image> | jq '.history'      # Get build history
skopeo inspect docker://<image>           # Inspect without pull
```

### Forensic Commands

```bash
crane pull <image> image.tar              # Download image
crane blob <image>@sha256:<digest>        # Extract single layer
skopeo copy docker://<image> oci:./dir    # Convert to OCI
dive <image>                              # Interactive exploration
```

### Security Commands

```bash
trivy image <image>                       # Full security scan
trivy image --scanners secret <image>     # Secret scan only
syft <image> -o cyclonedx-json            # Generate SBOM
grype <image>                             # Vulnerability scan
```
