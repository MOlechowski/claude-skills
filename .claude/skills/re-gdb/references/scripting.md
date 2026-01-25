# GDB Python Scripting Reference

Python scripting for GDB automation and extension.

## Basics

### Enable Python

GDB must be compiled with Python support (most distributions include this).

```bash
# Check Python support
gdb -batch -ex "python print('ok')"
```

### Running Python in GDB

```bash
# Interactive
(gdb) python print(gdb.execute("info registers", to_string=True))

# Multi-line
(gdb) python
>import gdb
>print(gdb.selected_frame().name())
>end

# From file
(gdb) source script.py
```

## GDB Python API

### Basic Operations

```python
import gdb

# Execute GDB command
gdb.execute("break main")
output = gdb.execute("info registers", to_string=True)

# Parse output
result = gdb.parse_and_eval("$rax")
print(int(result))

# Get current frame
frame = gdb.selected_frame()
print(frame.name())
print(frame.pc())

# Get inferior (debugged process)
inf = gdb.selected_inferior()
print(inf.pid)
```

### Reading Memory

```python
import gdb

def read_bytes(addr, size):
    """Read bytes from memory."""
    inf = gdb.selected_inferior()
    return inf.read_memory(addr, size)

def read_string(addr, max_len=256):
    """Read null-terminated string."""
    inf = gdb.selected_inferior()
    result = b""
    for i in range(max_len):
        byte = inf.read_memory(addr + i, 1)
        if byte == b"\x00":
            break
        result += bytes(byte)
    return result.decode("utf-8", errors="replace")

def read_int(addr, size=8):
    """Read integer from memory."""
    data = read_bytes(addr, size)
    return int.from_bytes(data, "little")
```

### Writing Memory

```python
import gdb

def write_bytes(addr, data):
    """Write bytes to memory."""
    inf = gdb.selected_inferior()
    inf.write_memory(addr, data)

def patch_nop(addr, count=1):
    """Write NOPs at address."""
    write_bytes(addr, b"\x90" * count)

def patch_ret(addr):
    """Patch address to just return."""
    write_bytes(addr, b"\xc3")

def patch_ret_value(addr, value):
    """Patch to return specific value."""
    if value == 0:
        # xor eax, eax; ret
        write_bytes(addr, b"\x31\xc0\xc3")
    elif value == 1:
        # mov eax, 1; ret
        write_bytes(addr, b"\xb8\x01\x00\x00\x00\xc3")
```

### Registers

```python
import gdb

def get_register(name):
    """Get register value."""
    return int(gdb.parse_and_eval(f"${name}"))

def set_register(name, value):
    """Set register value."""
    gdb.execute(f"set ${name} = {value}")

def get_all_registers():
    """Get all general purpose registers."""
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
            "rbp", "rsp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15", "rip"]
    return {r: get_register(r) for r in regs}
```

### Breakpoints

```python
import gdb

class MyBreakpoint(gdb.Breakpoint):
    def __init__(self, location):
        super().__init__(location)

    def stop(self):
        """Called when breakpoint hit. Return True to stop."""
        rax = int(gdb.parse_and_eval("$rax"))
        print(f"Hit at {self.location}, rax = {hex(rax)}")
        return True  # Stop execution

# Create breakpoint
bp = MyBreakpoint("main")

# Conditional breakpoint
class ConditionalBP(gdb.Breakpoint):
    def __init__(self, location, condition_func):
        super().__init__(location)
        self.condition_func = condition_func

    def stop(self):
        return self.condition_func()

# Only stop if rax > 100
ConditionalBP("*0x401234", lambda: get_register("rax") > 100)
```

### Custom Commands

```python
import gdb

class HexdumpCommand(gdb.Command):
    """Hexdump memory: hexdump ADDR [SIZE]"""

    def __init__(self):
        super().__init__("hexdump", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = arg.split()
        addr = int(gdb.parse_and_eval(args[0]))
        size = int(args[1]) if len(args) > 1 else 64

        inf = gdb.selected_inferior()
        data = bytes(inf.read_memory(addr, size))

        for i in range(0, len(data), 16):
            line = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in line)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in line)
            print(f"{addr+i:08x}  {hex_part:<48}  {ascii_part}")

HexdumpCommand()
```

### Event Handlers

```python
import gdb

def on_stop(event):
    """Called when execution stops."""
    if isinstance(event, gdb.BreakpointEvent):
        print(f"Breakpoint {event.breakpoints[0].number}")
    elif isinstance(event, gdb.SignalEvent):
        print(f"Signal: {event.stop_signal}")

def on_exit(event):
    """Called when inferior exits."""
    print(f"Exit code: {event.exit_code}")

def on_new_objfile(event):
    """Called when new shared library loaded."""
    print(f"Loaded: {event.new_objfile.filename}")

# Register handlers
gdb.events.stop.connect(on_stop)
gdb.events.exited.connect(on_exit)
gdb.events.new_objfile.connect(on_new_objfile)
```

### Finish Breakpoint

```python
import gdb

class ReturnBreakpoint(gdb.FinishBreakpoint):
    """Break when function returns."""

    def __init__(self, frame=None):
        super().__init__(frame or gdb.selected_frame())

    def stop(self):
        print(f"Function returned: {self.return_value}")
        return False  # Don't stop, just log

# Usage: set breakpoint at function, then:
class FunctionLogger(gdb.Breakpoint):
    def stop(self):
        ReturnBreakpoint()
        return False  # Continue to function
```

## Complete Scripts

### Function Tracer

```python
import gdb

class FunctionTracer:
    def __init__(self, functions):
        self.bps = []
        for func in functions:
            bp = TraceBP(func, self)
            self.bps.append(bp)
        self.calls = []

    def log(self, func, args):
        depth = len([f for f in self.calls if f])
        print("  " * depth + f"-> {func}({args})")
        self.calls.append(func)

class TraceBP(gdb.Breakpoint):
    def __init__(self, func, tracer):
        super().__init__(func)
        self.tracer = tracer
        self.func = func

    def stop(self):
        rdi = hex(int(gdb.parse_and_eval("$rdi")))
        rsi = hex(int(gdb.parse_and_eval("$rsi")))
        self.tracer.log(self.func, f"rdi={rdi}, rsi={rsi}")
        return False

# Usage
tracer = FunctionTracer(["malloc", "free", "strcpy"])
```

### Memory Search

```python
import gdb

def search_memory(pattern, start=None, end=None):
    """Search memory for byte pattern."""
    if start is None:
        # Search all writable memory
        output = gdb.execute("info proc mappings", to_string=True)
        regions = []
        for line in output.split("\n")[4:]:
            parts = line.split()
            if len(parts) >= 5 and "w" in parts[4]:
                regions.append((int(parts[0], 16), int(parts[1], 16)))
    else:
        regions = [(start, end)]

    inf = gdb.selected_inferior()
    results = []

    if isinstance(pattern, str):
        pattern = pattern.encode()

    for region_start, region_end in regions:
        try:
            data = bytes(inf.read_memory(region_start, region_end - region_start))
            idx = 0
            while True:
                idx = data.find(pattern, idx)
                if idx == -1:
                    break
                results.append(region_start + idx)
                idx += 1
        except:
            pass

    return results

# Usage
addrs = search_memory(b"flag{")
for addr in addrs:
    print(f"Found at {hex(addr)}")
```

### Heap Analyzer

```python
import gdb

def analyze_heap():
    """Basic heap chunk analysis."""
    # Get heap base from /proc/pid/maps
    output = gdb.execute("info proc mappings", to_string=True)
    heap_start = None
    heap_end = None

    for line in output.split("\n"):
        if "[heap]" in line:
            parts = line.split()
            heap_start = int(parts[0], 16)
            heap_end = int(parts[1], 16)
            break

    if not heap_start:
        print("Heap not found")
        return

    print(f"Heap: {hex(heap_start)} - {hex(heap_end)}")

    inf = gdb.selected_inferior()
    ptr = heap_start

    chunks = []
    while ptr < heap_end - 16:
        try:
            prev_size = int.from_bytes(inf.read_memory(ptr, 8), "little")
            size_field = int.from_bytes(inf.read_memory(ptr + 8, 8), "little")
            size = size_field & ~0x7
            flags = size_field & 0x7

            if size == 0 or size > heap_end - ptr:
                break

            chunks.append({
                "addr": ptr + 16,
                "size": size,
                "prev_inuse": flags & 1,
                "is_mmap": flags & 2,
            })
            ptr += size
        except:
            break

    for chunk in chunks[:20]:
        print(f"  {hex(chunk['addr'])}: size={chunk['size']}, "
              f"prev_inuse={chunk['prev_inuse']}")

    return chunks
```

## .gdbinit Integration

```python
# ~/.gdbinit or script loaded on startup

import gdb

# Load custom commands
class MyCommands:
    @staticmethod
    def setup():
        HexdumpCommand()
        # Add more commands...

MyCommands.setup()

# Auto-attach to common patterns
def auto_analyze():
    """Run on binary load."""
    try:
        gdb.execute("break main")
        print("Breakpoint set at main")
    except:
        pass

# Set up event for binary load
gdb.events.new_objfile.connect(lambda e: auto_analyze())
```

## Tips

### Error Handling

```python
def safe_read(addr, size):
    try:
        inf = gdb.selected_inferior()
        return bytes(inf.read_memory(addr, size))
    except gdb.MemoryError:
        return None
```

### Performance

```python
# Cache inferior reference
_inf = None
def get_inferior():
    global _inf
    if _inf is None:
        _inf = gdb.selected_inferior()
    return _inf

# Batch memory reads
def read_pointers(base, count):
    data = get_inferior().read_memory(base, count * 8)
    return [int.from_bytes(data[i:i+8], "little") for i in range(0, len(data), 8)]
```

### Debug Output

```python
import sys

def debug(msg):
    """Print to stderr (visible even with redirected output)."""
    print(msg, file=sys.stderr)
```
