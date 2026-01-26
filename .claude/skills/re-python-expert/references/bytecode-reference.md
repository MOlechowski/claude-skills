# Python Bytecode Reference

Detailed bytecode structures, opcodes, and code object information by Python version.

## Header Structures

### Python 2.7

```
Offset  Size  Field
0x00    4     Magic number (03 F3 0D 0A)
0x04    4     Timestamp (Unix time, little-endian)
0x08    ...   Code object (marshalled)
```

### Python 3.0-3.2

```
Offset  Size  Field
0x00    4     Magic number
0x04    4     Timestamp
0x08    ...   Code object (marshalled)
```

### Python 3.3-3.6

```
Offset  Size  Field
0x00    4     Magic number
0x04    4     Timestamp
0x08    4     Source file size
0x0C    ...   Code object (marshalled)
```

### Python 3.7+

```
Offset  Size  Field
0x00    4     Magic number
0x04    4     Bit field (flags)
        	    bit 0: 0 = timestamp, 1 = hash-based
0x08    4     Timestamp OR source hash part 1
0x0C    4     Source size OR source hash part 2
0x10    ...   Code object (marshalled)
```

## Magic Numbers Reference

| Python | Magic (hex) | Magic (decimal) | Header Size |
|--------|-------------|-----------------|-------------|
| 2.5 | D1 F2 0D 0A | 62131 | 8 |
| 2.6 | D1 F2 0D 0A | 62161 | 8 |
| 2.7 | 03 F3 0D 0A | 62211 | 8 |
| 3.0 | 3B 0C 0D 0A | 3131 | 8 |
| 3.1 | 4F 0C 0D 0A | 3151 | 8 |
| 3.2 | 6C 0C 0D 0A | 3180 | 8 |
| 3.3 | 9E 0C 0D 0A | 3230 | 12 |
| 3.4 | EE 0C 0D 0A | 3310 | 12 |
| 3.5 | 17 0D 0D 0A | 3351 | 12 |
| 3.6 | 33 0D 0D 0A | 3379 | 12 |
| 3.7 | 42 0D 0D 0A | 3394 | 16 |
| 3.8 | 55 0D 0D 0A | 3413 | 16 |
| 3.9 | 61 0D 0D 0A | 3425 | 16 |
| 3.10 | 6F 0D 0D 0A | 3439 | 16 |
| 3.11 | A7 0D 0D 0A | 3495 | 16 |
| 3.12 | CB 0D 0D 0A | 3531 | 16 |

## Common Opcodes

### Load Operations

| Opcode | Name | Operand | Description |
|--------|------|---------|-------------|
| 100 | LOAD_CONST | index | Push co_consts[index] |
| 101 | LOAD_NAME | index | Push co_names[index] value |
| 116 | LOAD_GLOBAL | index | Push global co_names[index] |
| 124 | LOAD_FAST | index | Push local co_varnames[index] |
| 106 | LOAD_ATTR | index | Push getattr(TOS, co_names[index]) |
| 136 | LOAD_DEREF | index | Push cell/free variable |

### Store Operations

| Opcode | Name | Operand | Description |
|--------|------|---------|-------------|
| 90 | STORE_NAME | index | Store TOS in co_names[index] |
| 97 | STORE_GLOBAL | index | Store TOS in global |
| 125 | STORE_FAST | index | Store TOS in local |
| 95 | STORE_ATTR | index | setattr(TOS1, co_names[index], TOS) |
| 137 | STORE_DEREF | index | Store in cell/free variable |

### Function Calls

**Python 3.5 and earlier:**
| Opcode | Name | Description |
|--------|------|-------------|
| 131 | CALL_FUNCTION | Call with positional args |
| 140 | CALL_FUNCTION_VAR | Call with *args |
| 141 | CALL_FUNCTION_KW | Call with **kwargs |

**Python 3.6-3.10:**
| Opcode | Name | Description |
|--------|------|-------------|
| 131 | CALL_FUNCTION | Call with n positional args |
| 141 | CALL_FUNCTION_KW | Call with keyword args (names in TOS) |
| 142 | CALL_FUNCTION_EX | Call with *args and/or **kwargs |

**Python 3.11+:**
| Opcode | Name | Description |
|--------|------|-------------|
| 171 | CALL | Unified call instruction |
| 172 | KW_NAMES | Set keyword argument names |

### Control Flow

| Opcode | Name | Operand | Description |
|--------|------|---------|-------------|
| 110 | JUMP_FORWARD | delta | Jump forward by delta |
| 113 | JUMP_ABSOLUTE | target | Jump to absolute address (< 3.11) |
| 140 | JUMP_BACKWARD | delta | Jump backward (3.11+) |
| 114 | POP_JUMP_IF_FALSE | target | Jump if TOS is false |
| 115 | POP_JUMP_IF_TRUE | target | Jump if TOS is true |
| 93 | FOR_ITER | delta | Get next from iterator or jump |
| 83 | RETURN_VALUE | - | Return TOS from function |

### Comparison (Changed in 3.9)

**Python < 3.9:**
| Opcode | Name | Operand | Description |
|--------|------|---------|-------------|
| 107 | COMPARE_OP | op | Compare: <, <=, ==, !=, >, >=, in, not in, is, is not |

**Python >= 3.9:**
| Opcode | Name | Description |
|--------|------|-------------|
| 107 | COMPARE_OP | Compare: <, <=, ==, !=, >, >= |
| 118 | CONTAINS_OP | in / not in |
| 119 | IS_OP | is / is not |

### Binary Operations

| Opcode | Name | Description |
|--------|------|-------------|
| 20 | BINARY_MULTIPLY | TOS = TOS1 * TOS |
| 22 | BINARY_MODULO | TOS = TOS1 % TOS |
| 23 | BINARY_ADD | TOS = TOS1 + TOS |
| 24 | BINARY_SUBTRACT | TOS = TOS1 - TOS |
| 26 | BINARY_SUBSCR | TOS = TOS1[TOS] |
| 27 | BINARY_FLOOR_DIVIDE | TOS = TOS1 // TOS |
| 28 | BINARY_TRUE_DIVIDE | TOS = TOS1 / TOS |

### Stack Operations

| Opcode | Name | Description |
|--------|------|-------------|
| 1 | POP_TOP | Remove TOS |
| 2 | ROT_TWO | Swap TOS and TOS1 |
| 3 | ROT_THREE | Rotate top three |
| 4 | DUP_TOP | Duplicate TOS |
| 9 | NOP | No operation |

## Code Object Structure

### Python 3.8+ Code Object

```python
import types

code = types.CodeType(
    co_argcount,        # int: positional argument count
    co_posonlyargcount, # int: positional-only count (3.8+)
    co_kwonlyargcount,  # int: keyword-only count
    co_nlocals,         # int: number of local variables
    co_stacksize,       # int: required stack size
    co_flags,           # int: interpreter flags
    co_code,            # bytes: bytecode instructions
    co_consts,          # tuple: constants
    co_names,           # tuple: names used
    co_varnames,        # tuple: local variable names
    co_filename,        # str: source filename
    co_name,            # str: function/module name
    co_firstlineno,     # int: first source line number
    co_lnotab,          # bytes: line number table (< 3.10)
    co_linetable,       # bytes: line number table (3.10+)
    co_freevars,        # tuple: free variable names
    co_cellvars,        # tuple: cell variable names
)
```

### Code Flags

| Flag | Value | Meaning |
|------|-------|---------|
| CO_OPTIMIZED | 0x0001 | Uses fast locals |
| CO_NEWLOCALS | 0x0002 | Creates new locals dict |
| CO_VARARGS | 0x0004 | Has *args |
| CO_VARKEYWORDS | 0x0008 | Has **kwargs |
| CO_NESTED | 0x0010 | Nested function |
| CO_GENERATOR | 0x0020 | Generator function |
| CO_NOFREE | 0x0040 | No free/cell variables |
| CO_COROUTINE | 0x0080 | Coroutine (async def) |
| CO_ITERABLE_COROUTINE | 0x0100 | Iterable coroutine |
| CO_ASYNC_GENERATOR | 0x0200 | Async generator |

## Analysis with dis Module

### Basic Disassembly

```python
import dis

# Disassemble function
def example(x):
    return x + 1

dis.dis(example)
```

Output:
```
  2           0 LOAD_FAST                0 (x)
              2 LOAD_CONST               1 (1)
              4 BINARY_ADD
              6 RETURN_VALUE
```

### Disassemble .pyc File

```python
import dis
import marshal

def disassemble_pyc(filename):
    with open(filename, 'rb') as f:
        # Skip header (adjust size for Python version)
        magic = f.read(4)
        print(f"Magic: {magic.hex()}")

        # Python 3.7+ has 16-byte header
        f.read(12)

        code = marshal.load(f)
        dis.dis(code)

disassemble_pyc('example.pyc')
```

### Get Instruction List

```python
import dis

def get_instructions(code):
    for instr in dis.get_instructions(code):
        print(f"{instr.offset:4d} {instr.opname:20s} {instr.argrepr}")

# For nested code objects
def recursive_dis(code, indent=0):
    prefix = "  " * indent
    for instr in dis.get_instructions(code):
        print(f"{prefix}{instr.offset:4d} {instr.opname:20s} {instr.argrepr}")

    # Recurse into nested code objects
    for const in code.co_consts:
        if hasattr(const, 'co_code'):
            print(f"\n{prefix}Nested: {const.co_name}")
            recursive_dis(const, indent + 1)
```

### Show Code Details

```python
import dis

def show_code_info(code):
    print(f"Name: {code.co_name}")
    print(f"Filename: {code.co_filename}")
    print(f"First line: {code.co_firstlineno}")
    print(f"Arg count: {code.co_argcount}")
    print(f"Locals: {code.co_varnames}")
    print(f"Names: {code.co_names}")
    print(f"Constants: {code.co_consts}")
    print(f"Flags: {code.co_flags:#x}")
    print(f"Stack size: {code.co_stacksize}")

# Or use dis.show_code()
dis.show_code(code)
```

## Reconstructing Code Objects

### Patching Bytecode

```python
import marshal
import types

def patch_pyc(input_file, output_file, patch_func):
    with open(input_file, 'rb') as f:
        header = f.read(16)  # Adjust for Python version
        code = marshal.load(f)

    # Apply patch
    new_code = patch_func(code)

    with open(output_file, 'wb') as f:
        f.write(header)
        marshal.dump(new_code, f)

# Example: Replace a constant
def replace_constant(code, old_val, new_val):
    new_consts = tuple(
        new_val if c == old_val else c
        for c in code.co_consts
    )
    return code.replace(co_consts=new_consts)

# Example: NOP out instructions
def nop_range(code, start, end):
    bytecode = bytearray(code.co_code)
    for i in range(start, end):
        bytecode[i] = 9  # NOP
    return code.replace(co_code=bytes(bytecode))
```

### Creating Code Objects

```python
import types

# Create simple code object
bytecode = bytes([
    100, 1,     # LOAD_CONST 1 (value at index 1)
    83,         # RETURN_VALUE
])

code = types.CodeType(
    0,              # argcount
    0,              # posonlyargcount (3.8+)
    0,              # kwonlyargcount
    0,              # nlocals
    1,              # stacksize
    67,             # flags (CO_OPTIMIZED | CO_NEWLOCALS)
    bytecode,       # code
    (None, 42),     # consts (None at 0, 42 at 1)
    (),             # names
    (),             # varnames
    '<generated>',  # filename
    'answer',       # name
    1,              # firstlineno
    b'',            # lnotab
    (),             # freevars
    (),             # cellvars
)

# Execute it
exec(code)  # Returns 42
```

### Dumping to .pyc

```python
import marshal
import struct
import time

def write_pyc(code, filename, python_version=(3, 11)):
    with open(filename, 'wb') as f:
        # Magic number (example for 3.11)
        if python_version >= (3, 11):
            magic = 3495
        elif python_version >= (3, 10):
            magic = 3439
        else:
            magic = 3413  # 3.8

        f.write(struct.pack('<HH', magic, 0x0d0a))

        # Flags (0 = timestamp-based)
        f.write(struct.pack('<I', 0))

        # Timestamp
        f.write(struct.pack('<I', int(time.time())))

        # Source size (0 if unknown)
        f.write(struct.pack('<I', 0))

        # Code object
        marshal.dump(code, f)
```

## Version-Specific Opcode Changes

### Python 3.6

- Bytecode became word-aligned (2 bytes per instruction)
- `CALL_FUNCTION` semantics changed
- Added `FORMAT_VALUE`, `BUILD_STRING` for f-strings

### Python 3.8

- Added `LOAD_METHOD`, `CALL_METHOD` optimization
- Added `:=` walrus operator support
- Positional-only parameters

### Python 3.9

- Split `COMPARE_OP` into `COMPARE_OP`, `IS_OP`, `CONTAINS_OP`
- Removed `WITH_CLEANUP_START`, `WITH_CLEANUP_FINISH`

### Python 3.10

- Added pattern matching opcodes: `MATCH_CLASS`, `MATCH_MAPPING`, etc.
- `MATCH_SEQUENCE`, `MATCH_KEYS`

### Python 3.11

- Removed `JUMP_ABSOLUTE`, added `JUMP_BACKWARD`
- Replaced `CALL_FUNCTION*` with unified `CALL`
- Added specializing adaptive interpreter (hidden from dis)
- Changed exception handling model

### Python 3.12

- More inline caching
- Comprehension inlining
- Further opcode consolidation
