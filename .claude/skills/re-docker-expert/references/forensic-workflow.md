# Container Forensic Workflow

Detailed procedures for container incident response and forensic analysis.

## Evidence Preservation

### Immediate Actions

**Priority 1: Preserve the image**
```bash
# Create immutable copy with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p evidence/$TIMESTAMP

# Copy to OCI format (portable, preserves all metadata)
skopeo copy docker://<image> oci:evidence/$TIMESTAMP/image:latest

# Generate checksums for chain of custody
cd evidence/$TIMESTAMP
find . -type f -exec sha256sum {} \; > checksums.sha256
```

**Priority 2: Document current state**
```bash
# Capture all metadata
crane manifest <image> > manifest.json
crane config <image> > config.json
docker inspect <image> > docker_inspect.json 2>/dev/null || true

# Record image digests
crane digest <image> > image_digest.txt
```

**Priority 3: Capture running container (if applicable)**
```bash
# If container is running, capture its state
docker export <container_id> > container_filesystem.tar
docker logs <container_id> > container_logs.txt 2>&1
docker inspect <container_id> > container_inspect.json
```

### Chain of Custody

Document for each evidence item:
- Date/time of acquisition
- Source (registry URL, container ID)
- SHA256 hash at acquisition
- Analyst name
- Storage location

```bash
# Create custody log
cat > evidence/$TIMESTAMP/custody.txt << EOF
Evidence Acquisition Log
========================
Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Image: <image>
Digest: $(cat image_digest.txt)
Analyst: [YOUR NAME]
Tool versions:
  - crane: $(crane version 2>&1 | head -1)
  - skopeo: $(skopeo --version)
  - trivy: $(trivy --version | head -1)
EOF
```

## Layer-by-Layer Analysis

### Extraction Process

**Extract all layers:**
```bash
# Pull image as tarball
crane pull <image> image.tar

# Extract tarball
mkdir extracted
tar -xf image.tar -C extracted

# List layers (in order)
cat extracted/manifest.json | jq -r '.[0].Layers[]'
```

**Extract individual layer:**
```bash
# Get layer digests from manifest
crane manifest <image> | jq -r '.layers[].digest'

# Extract specific layer
crane blob <image>@sha256:<layer_digest> > layer.tar.gz
mkdir layer_contents
tar -xzf layer.tar.gz -C layer_contents
```

### Filesystem Reconstruction

**Reconstruct full filesystem from layers:**
```bash
# Create reconstruction directory
mkdir -p reconstructed

# Apply layers in order (simulating overlay)
for layer in $(cat extracted/manifest.json | jq -r '.[0].Layers[]'); do
  tar -xf "extracted/$layer" -C reconstructed 2>/dev/null || true
done

# Note: This doesn't handle whiteout files properly
# For accurate reconstruction, use oci-dive or manual processing
```

**Handle whiteout files:**
```bash
# Find whiteout markers (deleted files)
find reconstructed -name '.wh.*' -type f

# Whiteout format:
# .wh.<filename> = file was deleted
# .wh..wh..opq = directory is opaque (contents replaced)
```

### Diff Analysis

**Compare layers:**
```bash
# Extract two consecutive layers
crane blob <image>@sha256:<layer1> | tar -tzf - > layer1_files.txt
crane blob <image>@sha256:<layer2> | tar -tzf - > layer2_files.txt

# Find differences
diff layer1_files.txt layer2_files.txt
```

**Use dive for visual diff:**
```bash
dive <image>
# Navigate with arrow keys
# Tab to switch between layer view and file tree
# Space to collapse/expand directories
```

## Timeline Reconstruction

### Build History Analysis

**Extract timeline from image history:**
```bash
# Get history with timestamps
crane config <image> | jq '.history[] | {created, created_by, empty_layer}' > history_timeline.json

# Sort by timestamp
crane config <image> | jq -r '.history[] | "\(.created)\t\(.created_by)"' | sort
```

**Identify build patterns:**
```bash
# Find RUN commands (actual build steps)
crane config <image> | jq -r '.history[].created_by' | grep -v '#(nop)'

# Find metadata-only layers
crane config <image> | jq -r '.history[] | select(.empty_layer == true) | .created_by'
```

### Timestamp Correlation

**Key timestamps to extract:**
```bash
# Image creation time
crane config <image> | jq -r '.created'

# Layer creation times
crane config <image> | jq -r '.history[].created'

# File modification times within layers
crane blob <image>@sha256:<layer> | tar -tzvf - | awk '{print $4, $5, $6}'
```

**Correlate with incident timeline:**
1. Identify incident timeframe
2. Find layers created during that period
3. Extract and analyze those specific layers
4. Document file changes with timestamps

## Attribution and Origin

### Registry Provenance

**Identify image source:**
```bash
# Check labels for build info
crane config <image> | jq '.config.Labels'

# Common provenance labels:
# org.opencontainers.image.source
# org.opencontainers.image.revision
# com.docker.official-images
# maintainer
```

**Verify image authenticity:**
```bash
# Check for signatures
cosign verify <image> 2>&1 || echo "Not signed or signature invalid"

# Check for attestations
cosign verify-attestation <image> 2>&1 || echo "No attestations"

# Compare with known good digest
crane digest <image>
# Compare against documented/expected value
```

### Base Image Analysis

**Identify base image:**
```bash
# First history entry usually reveals base
crane config <image> | jq '.history[0].created_by'

# Look for FROM instruction pattern
crane config <image> | jq -r '.history[].created_by' | head -5
```

**Verify base image integrity:**
```bash
# Get base image layers
crane manifest <base_image> | jq -r '.layers[].digest' > base_layers.txt

# Compare with target image layers
crane manifest <image> | jq -r '.layers[].digest' > image_layers.txt

# First N layers should match
head -n $(wc -l < base_layers.txt) image_layers.txt | diff - base_layers.txt
```

### Build Metadata

**Extract builder information:**
```bash
# Check for build tool markers
crane config <image> | jq '.config.Labels | to_entries[] | select(.key | contains("build"))'

# Docker BuildKit markers
crane config <image> | jq '.history[] | select(.created_by | contains("buildkit"))'

# CI/CD markers
crane config <image> | jq '.config.Labels | to_entries[] | select(.key | test("ci|jenkins|github|gitlab"))'
```

## Malware Detection Patterns

### Known Bad Indicators

**Crypto miners:**
```bash
# Common miner binaries
trivy image --scanners vuln <image> | grep -i "miner\|xmrig\|crypto"

# Mining pool connections in config
crane config <image> | jq -r '.config.Cmd, .config.Entrypoint' | grep -i "pool\|stratum"
```

**Backdoors and shells:**
```bash
# Reverse shell tools
find reconstructed -name "nc" -o -name "ncat" -o -name "socat" 2>/dev/null

# Unusual network binaries
find reconstructed -type f -executable -exec file {} \; | grep -i "network\|socket"
```

**Rootkits:**
```bash
# Modified system binaries (compare hashes with known good)
find reconstructed/bin reconstructed/usr/bin -type f -exec sha256sum {} \; > binaries.sha256

# Suspicious library preloading
grep -r "LD_PRELOAD" reconstructed/etc/ 2>/dev/null
cat reconstructed/etc/ld.so.preload 2>/dev/null
```

### Persistence Mechanisms

**Container-specific persistence:**
```bash
# Entrypoint/CMD manipulation
crane config <image> | jq '.config.Entrypoint, .config.Cmd'

# Startup scripts
ls -la reconstructed/docker-entrypoint.d/ 2>/dev/null
cat reconstructed/docker-entrypoint.sh 2>/dev/null

# Cron jobs
ls -la reconstructed/etc/cron.* 2>/dev/null
cat reconstructed/var/spool/cron/crontabs/* 2>/dev/null
```

### Network Indicators

**Suspicious network configuration:**
```bash
# Hardcoded IPs/domains
grep -rE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' reconstructed/ 2>/dev/null
grep -rE '[a-zA-Z0-9.-]+\.(xyz|top|tk|ml|ga|cf)' reconstructed/ 2>/dev/null

# C2 indicators
trivy image --scanners secret <image> | grep -i "url\|endpoint\|server"
```

## Report Template

### Executive Summary

```markdown
# Container Forensic Analysis Report

## Summary
- Image: [image reference]
- Analysis Date: [date]
- Analyst: [name]
- Verdict: [Clean / Suspicious / Compromised]

## Key Findings
1. [Finding 1]
2. [Finding 2]
3. [Finding 3]

## Risk Level: [Low / Medium / High / Critical]
```

### Technical Findings

```markdown
## Image Details
- Digest: sha256:xxx
- Created: [timestamp]
- Base Image: [identified base]
- Layer Count: [N]

## Vulnerability Summary
- Critical: [N]
- High: [N]
- Medium: [N]
- Low: [N]

## Secrets Found
| Type | Location | Risk |
|------|----------|------|
| [type] | [path] | [level] |

## Suspicious Artifacts
| Artifact | Layer | Description |
|----------|-------|-------------|
| [file] | [N] | [description] |
```

### Evidence Documentation

```markdown
## Evidence Chain of Custody
| Item | Hash | Acquired | By |
|------|------|----------|-----|
| image.tar | sha256:xxx | [date] | [name] |

## Tools Used
- crane [version]
- trivy [version]
- dive [version]

## Methodology
1. Evidence preservation
2. Layer extraction
3. Timeline reconstruction
4. IOC scanning
5. Manual analysis
```

### Recommendations

```markdown
## Immediate Actions
- [ ] [Action 1]
- [ ] [Action 2]

## Remediation Steps
1. [Step 1]
2. [Step 2]

## Prevention Measures
- [Measure 1]
- [Measure 2]
```
