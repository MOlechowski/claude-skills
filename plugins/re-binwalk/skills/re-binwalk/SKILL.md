---
name: re-binwalk
description: "binwalk firmware analysis: signature scanning, entropy analysis, file extraction, embedded filesystem analysis. Use for: firmware reverse engineering, extracting embedded files, IoT analysis, finding hidden data, analyzing binary blobs. Triggers: binwalk, firmware analysis, extract firmware, find signatures, entropy analysis, embedded filesystem, IoT reversing."
---

# binwalk

Firmware analysis and extraction tool.

## Quick Start

```bash
# Install
pip install binwalk

# Scan for signatures
binwalk firmware.bin

# Extract files
binwalk -e firmware.bin

# Entropy analysis
binwalk -E firmware.bin
```

## Signature Scanning

```bash
# Default scan
binwalk firmware.bin

# Verbose output
binwalk -v firmware.bin

# Include invalid results
binwalk -I firmware.bin

# Opcodes scan (find code)
binwalk -A firmware.bin

# Raw strings
binwalk -R firmware.bin
```

### Custom Signatures

```bash
# Use custom signature file
binwalk -m custom.magic firmware.bin

# Magic file format:
# offset    type    match    description
# 0         string  ANDROID! Android boot image
```

## Extraction

```bash
# Auto extract
binwalk -e firmware.bin

# Extract to specific directory
binwalk -e -C output/ firmware.bin

# Matryoshka (recursive extract)
binwalk -Me firmware.bin

# Limit recursion depth
binwalk -Me -d 3 firmware.bin

# Extract specific signatures only
binwalk -D 'gzip:gz' firmware.bin
binwalk -D 'filesystem:fs:squashfs' firmware.bin
```

### Extraction Format

```bash
binwalk -D 'type:ext:handler'

# type: signature type (from scan)
# ext: output file extension
# handler: extraction command (optional)

# Examples
binwalk -D 'gzip:gz:gzip -d %e' firmware.bin
binwalk -D 'zip archive:zip:unzip %e' firmware.bin
```

## Entropy Analysis

Entropy helps identify compressed/encrypted data.

```bash
# Generate entropy plot
binwalk -E firmware.bin

# Save plot
binwalk -E -J firmware.bin  # JSON
binwalk -E -Q firmware.bin  # Quiet (save only)

# Combined with scan
binwalk -BE firmware.bin
```

### Interpreting Entropy

| Entropy | Meaning |
|---------|---------|
| 0.0-0.3 | Sparse data, nulls |
| 0.3-0.6 | Text, code |
| 0.6-0.8 | Compressed data |
| 0.8-1.0 | Encrypted or compressed |

## Filesystem Analysis

```bash
# Common firmware filesystems
# squashfs, cramfs, jffs2, romfs, yaffs2

# After extraction
unsquashfs filesystem.squashfs
jefferson filesystem.jffs2  # JFFS2
```

## Common Patterns

### Router Firmware

```bash
# 1. Scan headers
binwalk router.bin

# 2. Extract
binwalk -Me router.bin

# 3. Find filesystem
find _router.bin.extracted -name "*.squashfs"

# 4. Extract filesystem
unsquashfs squashfs-root
```

### IoT Device

```bash
# Check for common signatures
binwalk firmware.bin | grep -E 'ELF|uImage|gzip|squashfs|jffs2'

# Look for keys/certs
strings _firmware.bin.extracted/squashfs-root/* | grep -E 'BEGIN|PRIVATE|password'
```

### Bootloader Analysis

```bash
# Find U-Boot
binwalk -A firmware.bin | grep -i u-boot

# Extract uImage
binwalk -D 'uimage:uboot' firmware.bin
```

## Comparison

```bash
# Compare two firmwares
binwalk -W firmware1.bin firmware2.bin

# Hexdiff
binwalk -W -H firmware1.bin firmware2.bin
```

## Python API

```python
import binwalk

# Scan
for module in binwalk.scan('firmware.bin', signature=True):
    for result in module.results:
        print(f"{result.offset:#x}: {result.description}")

# Extract
binwalk.scan('firmware.bin', signature=True, extract=True)

# Entropy
for module in binwalk.scan('firmware.bin', entropy=True):
    print(module.results)
```

## Integration

For binary patching, use `/re-xxd`.
For ELF analysis, use `/re-radare2` or `/re-ghidra`.
For dynamic analysis, use `/re-frida` or `/re-gdb`.
