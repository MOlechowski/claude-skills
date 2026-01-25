---
name: re-patchelf
description: "ELF binary modification with patchelf: RPATH, interpreter, dependencies, SONAME. Use for: changing library paths, modifying ELF dynamic info, fixing binary dependencies. Triggers: patchelf, rpath, runpath, change interpreter, elf modify, add needed."
---

# patchelf

Modify ELF binaries: RPATH, interpreter, dependencies.

## Installation

```bash
# Ubuntu/Debian
sudo apt install patchelf

# macOS (for cross-compilation)
brew install patchelf

# From source
git clone https://github.com/NixOS/patchelf
cd patchelf && ./bootstrap.sh && ./configure && make && sudo make install
```

## View Current Settings

```bash
# Show RPATH
patchelf --print-rpath binary

# Show interpreter
patchelf --print-interpreter binary

# Show SONAME (for libraries)
patchelf --print-soname libfoo.so

# Show needed libraries
patchelf --print-needed binary
```

## RPATH / RUNPATH

Library search path embedded in binary.

### Set RPATH

```bash
# Absolute path
patchelf --set-rpath /custom/lib/path binary

# Relative to binary location
patchelf --set-rpath '$ORIGIN/lib' binary
patchelf --set-rpath '$ORIGIN/../lib' binary

# Multiple paths
patchelf --set-rpath '$ORIGIN/lib:/usr/local/lib' binary
```

### Remove RPATH

```bash
patchelf --remove-rpath binary
```

### Add to Existing RPATH

```bash
# Get current, append, set
CURRENT=$(patchelf --print-rpath binary)
patchelf --set-rpath "${CURRENT}:/new/path" binary
```

## Interpreter

The dynamic linker (ld-linux.so).

### Change Interpreter

```bash
# Standard 64-bit Linux
patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 binary

# Custom location
patchelf --set-interpreter /custom/ld-linux.so.2 binary

# 32-bit
patchelf --set-interpreter /lib/ld-linux.so.2 binary32
```

## Dependencies (DT_NEEDED)

### Add Library Dependency

```bash
patchelf --add-needed libcustom.so binary
```

### Remove Library Dependency

```bash
patchelf --remove-needed libunused.so binary
```

### Replace Library

```bash
patchelf --replace-needed libold.so libnew.so binary
```

## SONAME (Libraries)

```bash
# Set SONAME
patchelf --set-soname libfoo.so.1 libfoo.so

# View SONAME
patchelf --print-soname libfoo.so
```

## Common Workflows

### Relocatable Binary

Make binary work from any directory:

```bash
# 1. Copy binary and libs
mkdir -p myapp/bin myapp/lib
cp binary myapp/bin/
cp /path/to/libs/*.so myapp/lib/

# 2. Set relative RPATH
patchelf --set-rpath '$ORIGIN/../lib' myapp/bin/binary
```

### Bundle with Custom Libraries

```bash
# Use specific library versions
patchelf --set-rpath '$ORIGIN/lib' binary
patchelf --replace-needed libssl.so.1.1 libssl.so.3 binary
```

### Fix Library Not Found

```bash
# Check what's missing
ldd binary | grep "not found"

# Add search path
patchelf --set-rpath '$ORIGIN:/opt/custom/lib' binary
```

### Use Custom Loader

For analysis or instrumentation:

```bash
patchelf --set-interpreter ./my_loader.so binary
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "cannot find section" | Binary may be statically linked |
| RPATH too long | May need to shrink first |
| Interpreter not found | Verify path exists on target |
| Library still not found | Check `ldd`, verify RPATH |

### Debug Library Loading

```bash
# See what ld.so searches
LD_DEBUG=libs ./binary

# See all library resolution
LD_DEBUG=all ./binary 2>&1 | head -100
```

## Quick Reference

| Command | Purpose |
|---------|---------|
| `--print-rpath` | Show RPATH |
| `--set-rpath PATH` | Set RPATH |
| `--remove-rpath` | Remove RPATH |
| `--print-interpreter` | Show interpreter |
| `--set-interpreter PATH` | Set interpreter |
| `--print-needed` | Show dependencies |
| `--add-needed LIB` | Add dependency |
| `--remove-needed LIB` | Remove dependency |
| `--replace-needed OLD NEW` | Replace dependency |
| `--print-soname` | Show SONAME |
| `--set-soname NAME` | Set SONAME |

## Integration

For section manipulation, use `/re-objcopy`.
For hex-level patching, use `/re-xxd`.
