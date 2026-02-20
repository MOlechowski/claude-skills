# Binary Format Reference

Detailed structures for ELF, PE, and Mach-O formats.

## ELF Format (Linux/Unix)

### Header Structure

```
Offset  Size  Field
0x00    4     Magic: 0x7F 'E' 'L' 'F'
0x04    1     Class: 1=32-bit, 2=64-bit
0x05    1     Data: 1=LE, 2=BE
0x06    1     Version
0x07    1     OS/ABI
0x08    8     Padding
0x10    2     Type: 1=REL, 2=EXEC, 3=DYN, 4=CORE
0x12    2     Machine: 0x03=x86, 0x3E=x86-64, 0xB7=ARM64
0x14    4     Version
0x18    4/8   Entry point address
0x1C/20 4/8   Program header offset
0x20/28 4/8   Section header offset
```

### Program Header Types

| Type | Value | Purpose |
|------|-------|---------|
| PT_NULL | 0 | Unused |
| PT_LOAD | 1 | Loadable segment |
| PT_DYNAMIC | 2 | Dynamic linking info |
| PT_INTERP | 3 | Interpreter path |
| PT_NOTE | 4 | Auxiliary info |
| PT_PHDR | 6 | Program header table |
| PT_GNU_STACK | 0x6474e551 | Stack permissions |
| PT_GNU_RELRO | 0x6474e552 | Read-only after reloc |

### Common Sections

| Section | Purpose |
|---------|---------|
| .text | Executable code |
| .data | Initialized writable data |
| .bss | Uninitialized data |
| .rodata | Read-only data |
| .plt | Procedure Linkage Table |
| .got | Global Offset Table |
| .got.plt | GOT for PLT |
| .dynsym | Dynamic symbols |
| .dynstr | Dynamic string table |
| .symtab | Symbol table |
| .strtab | String table |
| .init | Initialization code |
| .fini | Finalization code |

### Security Features

```bash
# Check NX (non-executable stack)
readelf -l binary | grep "GNU_STACK"
# RW = NX enabled, RWE = NX disabled

# Check PIE
readelf -h binary | grep Type
# DYN = PIE, EXEC = no PIE

# Check RELRO
readelf -l binary | grep "GNU_RELRO"
# Present = Partial RELRO
readelf -d binary | grep BIND_NOW
# Present = Full RELRO

# Check stack canary
readelf -s binary | grep "__stack_chk"
```

## PE Format (Windows)

### DOS Header

```
Offset  Size  Field
0x00    2     Magic: 'MZ' (0x5A4D)
0x3C    4     e_lfanew: Offset to PE header
```

### PE Signature and COFF Header

```
Offset  Size  Field
0x00    4     Signature: 'PE\0\0'
0x04    2     Machine: 0x14C=i386, 0x8664=AMD64
0x06    2     NumberOfSections
0x08    4     TimeDateStamp
0x0C    4     PointerToSymbolTable
0x10    4     NumberOfSymbols
0x14    2     SizeOfOptionalHeader
0x16    2     Characteristics
```

### Optional Header (PE32+)

```
Offset  Size  Field
0x00    2     Magic: 0x10B=PE32, 0x20B=PE32+
0x10    4     AddressOfEntryPoint (RVA)
0x18    8     ImageBase
0x20    4     SectionAlignment
0x24    4     FileAlignment
0x38    4     SizeOfImage
0x3C    4     SizeOfHeaders
0x5C    4     NumberOfRvaAndSizes
0x60    ...   Data Directories (16 entries)
```

### Data Directories

| Index | Name | Purpose |
|-------|------|---------|
| 0 | Export | Exported functions |
| 1 | Import | Imported functions |
| 2 | Resource | Resources (icons, strings) |
| 3 | Exception | Exception handling |
| 4 | Security | Digital signatures |
| 5 | BaseReloc | Relocation info |
| 6 | Debug | Debug info |
| 12 | IAT | Import Address Table |
| 13 | DelayImport | Delay-loaded imports |
| 14 | CLR | .NET metadata |

### Address Conversion

```
RVA = Relative Virtual Address (offset from ImageBase)
VA = Virtual Address = ImageBase + RVA
FileOffset = RVA - Section.VirtualAddress + Section.PointerToRawData
```

## Mach-O Format (macOS/iOS)

### Header

```
Offset  Size  Field
0x00    4     Magic: 0xFEEDFACF (64-bit), 0xFEEDFACE (32-bit)
0x04    4     CPU Type
0x08    4     CPU Subtype
0x0C    4     File Type
0x10    4     Number of Load Commands
0x14    4     Size of Load Commands
0x18    4     Flags
```

### Common Load Commands

| Command | Purpose |
|---------|---------|
| LC_SEGMENT_64 | Memory segment |
| LC_SYMTAB | Symbol table |
| LC_DYSYMTAB | Dynamic symbols |
| LC_LOAD_DYLIB | Dylib dependency |
| LC_MAIN | Entry point |
| LC_CODE_SIGNATURE | Code signature |

### Segments

| Segment | Purpose |
|---------|---------|
| __TEXT | Code and read-only data |
| __DATA | Writable data |
| __LINKEDIT | Linking information |
| __PAGEZERO | Null page guard |

### Analysis Commands

```bash
otool -h binary        # Header
otool -l binary        # Load commands
otool -L binary        # Libraries
otool -tv binary       # Disassembly
codesign -dvvv binary  # Signature info
```

## Common Patterns

### Calling Conventions

**x86-64 Linux (System V ABI):**
- Args: RDI, RSI, RDX, RCX, R8, R9
- Return: RAX
- Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11

**x86-64 Windows:**
- Args: RCX, RDX, R8, R9
- Return: RAX
- Shadow space: 32 bytes

**ARM64:**
- Args: X0-X7
- Return: X0
- Frame pointer: X29
- Link register: X30
