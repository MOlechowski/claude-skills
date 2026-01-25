---
name: re-xxd
description: "Hex dump and binary patching with xxd/hexdump: view hex, patch bytes, reverse hex to binary. Use for: viewing binary in hex, patching specific bytes, hex editing workflow. Triggers: xxd, hexdump, hex dump, hex edit, patch bytes, view hex."
---

# xxd

Hex dump and binary patching with xxd and hexdump.

## Hex Dump

### View Entire File

```bash
xxd binary | less
xxd binary | head -50
```

### View at Offset

```bash
# Start at offset 0x1000, show 256 bytes
xxd -s 0x1000 -l 256 binary

# Decimal offset
xxd -s 4096 -l 256 binary
```

### Output Formats

```bash
# Standard (default)
xxd binary
# 00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............

# Plain hex only
xxd -p binary
# 7f454c4602010100...

# Binary (bits)
xxd -b binary
# 00000000: 01111111 01000101 01001100 01000110  .ELF

# C array format
xxd -i binary
# unsigned char binary[] = { 0x7f, 0x45, 0x4c, ...
```

### Column Width

```bash
# 8 bytes per line
xxd -c 8 binary

# 32 bytes per line
xxd -c 32 binary
```

## Binary Patching

### Patch Single Byte

```bash
# Create patch file
echo "00001234: 90" | xxd -r - binary

# Or with printf and dd
printf '\x90' | dd of=binary bs=1 seek=$((0x1234)) conv=notrunc
```

### Patch Multiple Bytes

```bash
# Patch at offset 0x1234 with 4 NOPs
echo "00001234: 90 90 90 90" | xxd -r - binary

# Patch at offset 0x400 with specific bytes
echo "00000400: 48 31 c0 c3" | xxd -r - binary
```

### Patch Workflow

```bash
# 1. Backup original
cp binary binary.orig

# 2. Find target (example: find JNZ instruction)
xxd binary | grep -n "75"

# 3. Create patch
echo "00001234: eb" | xxd -r - binary  # Change JNZ (75) to JMP (eb)

# 4. Verify
xxd -s 0x1234 -l 4 binary
diff <(xxd binary.orig) <(xxd binary)
```

### Reverse Mode

```bash
# Convert hex dump back to binary
xxd -r hexdump.txt output.bin

# From plain hex
xxd -r -p hexonly.txt output.bin
```

## hexdump Alternative

```bash
# Canonical format (like xxd)
hexdump -C binary | head -20

# Custom format
hexdump -e '16/1 "%02x " "\n"' binary
```

## Common Patterns

### NOP Instruction

```bash
# x86/x64 NOP = 0x90
echo "00001234: 90" | xxd -r - binary

# NOP sled (5 bytes for CALL replacement)
echo "00001234: 90 90 90 90 90" | xxd -r - binary
```

### Change Jump Condition

```bash
# JZ (74) -> JNZ (75)
# JNZ (75) -> JZ (74)
# JZ (74) -> JMP short (eb)
# Any conditional -> NOP NOP (90 90)
```

### Force Return Value

```bash
# mov eax, 1; ret (return true)
# b8 01 00 00 00 c3
echo "00001234: b8 01 00 00 00 c3" | xxd -r - binary

# xor eax, eax; ret (return 0/false)
# 31 c0 c3
echo "00001234: 31 c0 c3" | xxd -r - binary
```

## Useful Combinations

### Find and Patch

```bash
# Find pattern
xxd binary | grep "48 89 e5"

# Get exact offset from output, then patch
echo "0000XXXX: 90 90 90" | xxd -r - binary
```

### Extract Section

```bash
# Extract 1024 bytes starting at 0x1000
xxd -s 0x1000 -l 1024 binary | xxd -r > section.bin
```

### Compare Binaries

```bash
diff <(xxd binary1) <(xxd binary2)

# Or side by side
diff -y <(xxd binary1) <(xxd binary2) | head -50
```

## Quick Reference

| Command | Purpose |
|---------|---------|
| `xxd file` | Hex dump |
| `xxd -s N file` | Start at offset N |
| `xxd -l N file` | Limit to N bytes |
| `xxd -p file` | Plain hex only |
| `xxd -r` | Reverse (hex to binary) |
| `xxd -r -p` | Reverse plain hex |
| `xxd -c N` | N bytes per line |
| `hexdump -C` | Canonical hex dump |

## Integration

For ELF header/section changes, use `/re-patchelf` or `/re-objcopy`.
For instruction-level patching with disassembly, use `/re-radare2`.
