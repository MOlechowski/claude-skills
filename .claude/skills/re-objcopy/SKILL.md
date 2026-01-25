---
name: re-objcopy
description: "Binary manipulation with objcopy: sections, symbols, format conversion. Use for: adding/removing sections, stripping symbols, converting binary formats, extracting sections. Triggers: objcopy, add section, remove section, strip symbols, binary conversion."
---

# objcopy

GNU binutils tool for binary manipulation: sections, symbols, format conversion.

## Section Operations

### Add Section

```bash
# Add data file as new section
objcopy --add-section .mydata=data.bin binary

# Add with specific flags
objcopy --add-section .mydata=data.bin \
        --set-section-flags .mydata=noload,readonly binary
```

### Remove Section

```bash
# Remove single section
objcopy --remove-section .note.gnu.build-id binary

# Remove multiple sections
objcopy --remove-section .comment \
        --remove-section .note binary
```

### Rename Section

```bash
objcopy --rename-section .text=.code binary
objcopy --rename-section .old=.new binary
```

### Extract Section

```bash
# Dump section contents to file
objcopy --dump-section .text=text.bin binary
objcopy --dump-section .rodata=rodata.bin binary
```

### Update Section

```bash
# Replace section contents
objcopy --update-section .data=newdata.bin binary
```

### Section Flags

```bash
# Make section writable
objcopy --set-section-flags .rodata=alloc,load,data binary

# Available flags: alloc, load, readonly, data, code, rom, share, contents, noload
```

## Symbol Operations

### Strip All Symbols

```bash
objcopy --strip-all binary
# Or use strip command
strip binary
```

### Strip Debug Only

```bash
objcopy --strip-debug binary
# Or
strip --strip-debug binary
```

### Keep Specific Symbols

```bash
# Keep only listed symbols
objcopy --strip-all --keep-symbol=main --keep-symbol=init binary

# Keep symbols matching pattern
objcopy --strip-all --keep-symbols=keep_list.txt binary
```

### Remove Specific Symbols

```bash
objcopy --strip-symbol=debug_func binary
```

### Localize Symbols

Make global symbols local (hidden):

```bash
objcopy --localize-symbol=internal_func binary
objcopy --localize-hidden binary  # Localize all hidden
```

### Weaken Symbols

```bash
objcopy --weaken-symbol=malloc binary
objcopy --weaken binary  # Weaken all globals
```

### Redefine Symbols

```bash
# Rename symbol
objcopy --redefine-sym old_name=new_name binary

# From file (old=new per line)
objcopy --redefine-syms=renames.txt binary
```

## Format Conversion

### ELF to Raw Binary

```bash
objcopy -O binary input.elf output.bin
```

### Binary to ELF

```bash
objcopy -I binary -O elf64-x86-64 input.bin output.elf

# With specific architecture
objcopy -I binary -O elf32-i386 -B i386 input.bin output.elf
```

### List Supported Formats

```bash
objcopy --info
```

### Common Formats

| Format | Description |
|--------|-------------|
| `elf64-x86-64` | 64-bit x86 ELF |
| `elf32-i386` | 32-bit x86 ELF |
| `elf64-littleaarch64` | 64-bit ARM ELF |
| `binary` | Raw binary |
| `ihex` | Intel HEX |
| `srec` | Motorola S-record |

## Common Workflows

### Create Minimal Binary

```bash
objcopy --strip-all \
        --remove-section=.comment \
        --remove-section=.note.gnu.build-id \
        --remove-section=.note.ABI-tag \
        binary binary.min
```

### Embed Data in Binary

```bash
# Create data section
objcopy --add-section .config=config.json \
        --set-section-flags .config=noload,readonly \
        binary

# Access in code via linker symbols:
# extern char _binary_config_json_start[];
# extern char _binary_config_json_end[];
```

### Extract Code Section

```bash
objcopy --dump-section .text=code.bin binary
# Or extract as raw binary
objcopy -O binary -j .text binary code.bin
```

### Convert for Firmware

```bash
# ELF to Intel HEX
objcopy -O ihex firmware.elf firmware.hex

# ELF to raw binary (for flashing)
objcopy -O binary firmware.elf firmware.bin
```

### Separate Debug Info

```bash
# Extract debug info
objcopy --only-keep-debug binary binary.debug

# Strip original
objcopy --strip-debug binary

# Link debug info
objcopy --add-gnu-debuglink=binary.debug binary
```

## Quick Reference

| Command | Purpose |
|---------|---------|
| `--add-section .name=file` | Add section |
| `--remove-section .name` | Remove section |
| `--rename-section .old=.new` | Rename section |
| `--dump-section .name=file` | Extract section |
| `--update-section .name=file` | Replace section |
| `--set-section-flags` | Change section flags |
| `--strip-all` | Remove all symbols |
| `--strip-debug` | Remove debug symbols |
| `--keep-symbol=name` | Keep specific symbol |
| `--localize-symbol=name` | Make symbol local |
| `--redefine-sym old=new` | Rename symbol |
| `-O format` | Output format |
| `-I format` | Input format |
| `-j .section` | Only copy section |

## Related Commands

```bash
# View sections
readelf -S binary
objdump -h binary

# View symbols
nm binary
readelf -s binary
objdump -t binary
```

## Integration

For dynamic linking changes (RPATH, interpreter), use `/re-patchelf`.
For hex-level patching, use `/re-xxd`.
