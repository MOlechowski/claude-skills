# pwntools API Reference

## Tubes (I/O)

### tube Base Class

All connection types (process, remote, ssh) inherit from tube.

```python
# Sending
t.send(data)              # Send raw bytes
t.sendline(data)          # Send with newline
t.sendafter(delim, data)  # Send after receiving delim
t.sendlineafter(delim, data)
t.sendthen(delim, data)   # Send then wait for delim

# Receiving
t.recv(n)                 # Receive n bytes (may be less)
t.recvn(n)                # Receive exactly n bytes
t.recvline()              # Receive until newline
t.recvlines(n)            # Receive n lines
t.recvuntil(delim)        # Receive until delimiter
t.recvregex(pattern)      # Receive until regex matches
t.recvall()               # Receive until EOF
t.recvrepeat(timeout)     # Keep receiving until timeout

# Buffer management
t.clean(timeout)          # Discard buffered data
t.clean_and_log()         # Discard and log
t.unrecv(data)            # Push data back to buffer

# Interactive
t.interactive()           # Interactive mode
t.close()                 # Close connection

# Properties
t.can_recv(timeout)       # Check if data available
t.connected()             # Check if connected
t.timeout                 # Get/set timeout
```

### process

```python
p = process(argv, shell=False, env=None, cwd=None,
            stdin=PIPE, stdout=PIPE, stderr=PIPE,
            aslr=None, setuid=None)

# argv: string or list
# shell: use shell for execution
# env: environment dict
# aslr: enable/disable ASLR

p.pid                     # Process ID
p.poll()                  # Check if exited
p.wait()                  # Wait for exit
p.kill()                  # Send SIGKILL
p.libs()                  # Get loaded libraries
p.libc                    # Get libc ELF
```

### remote

```python
r = remote(host, port, ssl=False, sock=None,
           ssl_context=None, sni=None)

# host: hostname or IP
# port: port number
# ssl: use SSL/TLS
# sock: existing socket

r.sock                    # Underlying socket
r.lhost                   # Local host
r.lport                   # Local port
r.rhost                   # Remote host
r.rport                   # Remote port
```

### ssh

```python
s = ssh(user, host, port=22, password=None, key=None,
        keyfile=None, proxy_command=None, raw=False)

shell = s.shell()         # Get shell
proc = s.process(argv)    # Run process
s.run(cmd)                # Run command
s.run_to_end(cmd)         # Run and get output
s.download_data(path)     # Download file as bytes
s.download_file(remote, local)
s.upload_data(data, path) # Upload bytes
s.upload_file(local, remote)
s.which(name)             # Find binary path
s.libs(path)              # Get process libs
s.set_working_directory(path)
```

## Packing

```python
# 8-bit
p8(n) / u8(s)

# 16-bit
p16(n) / u16(s)
p16(n, endian='big') / u16(s, endian='big')

# 32-bit
p32(n) / u32(s)
p32(n, endian='big') / u32(s, endian='big')
p32(n, sign='signed')

# 64-bit
p64(n) / u64(s)
p64(n, endian='big') / u64(s, endian='big')

# Arbitrary width
pack(n, word_size, endian='little', sign='unsigned')
unpack(s, word_size, endian='little', sign='unsigned')

# Flat - combine multiple values
flat([addr1, addr2, b'AAAA', 0x1234])
flat({0: b'A', 8: addr}, length=100)  # With offsets
```

## ELF

```python
elf = ELF(path, checksec=True)

# Addresses
elf.address               # Base address
elf.symbols               # Dict of symbols
elf.got                   # GOT entries
elf.plt                   # PLT entries
elf.functions             # Function objects

# Sections
elf.sections              # All sections
elf.get_section_by_name(name)
elf.section(name)         # Section data

# Segments
elf.segments              # All segments
elf.executable_segments   # Executable segments
elf.writable_segments     # Writable segments

# Searching
elf.search(needle, writable=False, executable=False)
elf.bss(offset=0)         # BSS address

# Properties
elf.arch                  # Architecture
elf.bits                  # 32 or 64
elf.endian                # 'little' or 'big'
elf.statically_linked     # Boolean
elf.pie                   # Boolean
elf.nx                    # Boolean
elf.canary                # Boolean
elf.relro                 # 'No', 'Partial', 'Full'
elf.rpath                 # RPATH
elf.runpath               # RUNPATH

# Methods
elf.checksec()            # Print security info
elf.asm(address, assembly) # Patch with assembly
elf.write(address, data)  # Write bytes
elf.read(address, count)  # Read bytes
elf.save(path)            # Save modified ELF
elf.disasm(address, n)    # Disassemble n bytes
```

## ROP

```python
rop = ROP(elfs, base=None, badchars=b'')

# Building chains
rop.call(symbol_or_addr, args)
rop.raw(value)            # Add raw value
rop.ret                   # Return gadget

# Gadget finding
rop.find_gadget(instructions)  # ['pop rax', 'ret']
rop.search(move=0, regs=None, order='size')

# Syscall helpers (Linux)
rop.execve(path, argv, envp)
rop.open(path, flags, mode)
rop.read(fd, buf, count)
rop.write(fd, buf, count)
rop.mprotect(addr, length, prot)

# Output
rop.chain()               # Get bytes
rop.dump()                # Show chain
rop.gadgets               # All gadgets
rop.setRegisters(regs)    # Set register values
```

## Shellcraft

```python
# Set architecture
context.arch = 'amd64'  # or 'i386', 'arm', 'aarch64'

# Common shellcodes
shellcraft.sh()           # execve("/bin/sh")
shellcraft.cat(path)      # Read file
shellcraft.echo(string)   # Print string
shellcraft.exit(code)     # Exit

# Network
shellcraft.connect(host, port, network='ipv4')
shellcraft.listen(port, network='ipv4')
shellcraft.findpeer(port) # Find connected socket
shellcraft.dupsh(fd)      # Dup shell to fd

# Syscalls
shellcraft.syscall(name, *args)
shellcraft.open(path, flags, mode)
shellcraft.read(fd, buf, count)
shellcraft.write(fd, buf, count)
shellcraft.mmap(addr, length, prot, flags, fd, offset)
shellcraft.mprotect(addr, length, prot)

# Shellcode operations
shellcraft.pushstr(string)
shellcraft.mov(dest, src)
shellcraft.setregs(regs)

# Encoders
shellcraft.encoder.xor(data, key)
shellcraft.encoder.alphanumeric(data)
```

## Assembly

```python
# Assemble
asm(code, vma=0)
asm('mov rax, 1; ret')

# Disassemble
disasm(bytes, vma=0)
disasm(b'\x48\x89\xe5', vma=0x401000)

# Architecture
context.arch = 'amd64'
context.bits = 64
context.endian = 'little'
```

## Format Strings

```python
# Automatic exploitation
fmtstr = FmtStr(execute_fmt, offset=None, padlen=0,
                numbwritten=0)
fmtstr.write(addr, data)
fmtstr.execute_writes()

# Payload generation
fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')
# writes: {addr: value, addr2: value2}
# write_size: 'byte', 'short', 'int'

# Split writes for constrained buffers
fmtstr_split(offset, writes, numbwritten=0, write_size='byte')
```

## Cyclic Patterns

```python
# Generate pattern
cyclic(length, alphabet=None, n=None)
cyclic(100)               # 100-byte pattern
cyclic(100, n=8)          # 64-bit pattern

# Find offset
cyclic_find(subseq, alphabet=None, n=None)
cyclic_find(0x61616167)   # Returns offset
cyclic_find(b'gaaa')

# Metasploit compatibility
cyclic_metasploit(length)
cyclic_metasploit_find(subseq)
```

## Utilities

### Logging

```python
context.log_level = 'debug'  # Most verbose
context.log_level = 'info'
context.log_level = 'warn'
context.log_level = 'error'

log.debug(msg)
log.info(msg)
log.success(msg)
log.warn(msg)
log.error(msg)            # Raises exception
log.failure(msg)
```

### Encoding

```python
# Hex
enhex(data)               # Bytes to hex string
unhex(s)                  # Hex string to bytes

# Base64
b64e(data)                # Encode
b64d(s)                   # Decode

# URL
urlencode(data)
urldecode(s)

# XOR
xor(data, key)
xor_pair(data)            # Find key that xors to data

# Bit manipulation
bits(n, endian='big')     # Int to bits
unbits(s, endian='big')   # Bits to int
ror(n, k, word_size)      # Rotate right
rol(n, k, word_size)      # Rotate left
```

### Crypto

```python
# MD5/SHA
md5sum(data)
md5file(path)
sha1sum(data)
sha256sum(data)

# CRC
crc.crc_32(data)
```

### Files

```python
read(path)                # Read file
write(path, data)         # Write file

# Temporary files
tempfile_with_data(data)  # Create temp file
```

## Context

```python
# Architecture
context.arch = 'amd64'    # amd64, i386, arm, aarch64, mips
context.bits = 64         # 32 or 64
context.endian = 'little' # little or big
context.os = 'linux'      # linux, windows, freebsd

# Logging
context.log_level = 'info'
context.log_file = 'log.txt'

# Terminal
context.terminal = ['tmux', 'splitw', '-h']

# Binary
context.binary = ELF('./binary')  # Auto-set arch/bits

# Timeout
context.timeout = 10

# Temporary context
with context.local(arch='i386'):
    # 32-bit code here
    pass
```

## GDB Integration

```python
# Debug new process
p = gdb.debug(argv, gdbscript=None, exe=None,
              sysroot=None, api=False)

gdb.debug('./binary', '''
    break main
    continue
''')

# Attach to running
gdb.attach(target, gdbscript=None, exe=None,
           gdb_args=None, api=False)

gdb.attach(p, 'break *0x401234')
gdb.attach(1234)          # PID

# Symbols
gdb.find_module_addresses(binary, ssh)
gdb.corefile(core_path)   # Analyze core dump
```
