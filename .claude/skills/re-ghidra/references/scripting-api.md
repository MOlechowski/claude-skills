# Ghidra Scripting API Reference

## FlatProgramAPI (Available Globally)

### Address Operations

```python
# Create address
addr = toAddr(0x401000)
addr = toAddr("0x401000")

# Address arithmetic
next_addr = addr.add(4)
prev_addr = addr.subtract(4)

# Check validity
addr.isValidAddress()
```

### Program Access

```python
# Current program
program = getCurrentProgram()

# Program info
program.getName()
program.getImageBase()
program.getLanguage()
program.getCompilerSpec()
program.getAddressFactory()
```

### Function Operations

```python
# Get function manager
fm = currentProgram.getFunctionManager()

# Get functions
func = getFunctionAt(toAddr(0x401000))      # At exact address
func = getFunctionContaining(toAddr(0x401234))  # Containing address
func = getFunction("main")                   # By name

# Iterate functions
for func in fm.getFunctions(True):   # True = forward
    pass
for func in fm.getFunctions(False):  # False = backward
    pass

# Function properties
func.getName()
func.getEntryPoint()
func.getBody()              # AddressSetView
func.getParameters()        # Parameter[]
func.getReturnType()        # DataType
func.getCallingConventionName()
func.getStackFrame()
func.isThunk()
func.getThunkedFunction(True)  # Follow thunk chain

# Modify function
from ghidra.program.model.symbol import SourceType
func.setName("new_name", SourceType.USER_DEFINED)
func.setReturnType(IntegerDataType(), SourceType.USER_DEFINED)
```

### Memory Operations

```python
# Read memory
getByte(addr)           # int
getShort(addr)          # int
getInt(addr)            # int
getLong(addr)           # long
getBytes(addr, length)  # byte[]
getFloat(addr)          # float
getDouble(addr)         # double

# Memory object
mem = currentProgram.getMemory()
mem.getBlocks()         # MemoryBlock[]
mem.getBlock(addr)      # MemoryBlock at address
```

### Reference Operations

```python
# Get references
refs = getReferencesTo(addr)    # References TO address
refs = getReferencesFrom(addr)  # References FROM address

# Reference properties
for ref in refs:
    ref.getFromAddress()
    ref.getToAddress()
    ref.getReferenceType()  # RefType
    ref.isMemoryReference()
    ref.isStackReference()

# Add reference
from ghidra.program.model.symbol import RefType, SourceType
addMemoryReference(fromAddr, toAddr, RefType.DATA, SourceType.USER_DEFINED, 0)
```

### Symbol Operations

```python
# Symbol table
st = currentProgram.getSymbolTable()

# Find symbols
symbols = st.getSymbols("main")
symbol = st.getPrimarySymbol(addr)

# Create label
createLabel(addr, "my_label", True)  # True = make primary

# Iterate symbols
for sym in st.getAllSymbols(True):
    sym.getName()
    sym.getAddress()
    sym.getSymbolType()
```

### Data Operations

```python
# Get data at address
data = getDataAt(addr)
if data:
    data.getDataType()
    data.getValue()
    data.getLength()

# Create data types
from ghidra.program.model.data import *
createByte(addr)
createWord(addr)
createDWord(addr)
createQWord(addr)
createAsciiString(addr)
createData(addr, PointerDataType())

# Listing access
listing = currentProgram.getListing()
for data in listing.getDefinedData(True):
    pass
```

### Comments

```python
# Set comments
setPreComment(addr, "Before instruction")
setPostComment(addr, "After instruction")
setEOLComment(addr, "End of line")
setPlateComment(addr, "Plate comment")
setRepeatableComment(addr, "Repeatable")

# Get comments
getPreComment(addr)
getPostComment(addr)
getEOLComment(addr)
```

## Decompiler API

```python
from ghidra.app.decompiler import DecompInterface, DecompileOptions

# Initialize
decomp = DecompInterface()
decomp.openProgram(currentProgram)

# Configure options (optional)
opts = DecompileOptions()
decomp.setOptions(opts)

# Decompile function
results = decomp.decompileFunction(func, timeout_secs, getMonitor())

if results.decompileCompleted():
    # C code string
    c_code = results.getDecompiledFunction().getC()

    # High-level function
    high_func = results.getHighFunction()

    # High-level symbols (variables)
    lsm = high_func.getLocalSymbolMap()
    for sym in lsm.getSymbols():
        sym.getName()
        sym.getDataType()

# Cleanup
decomp.dispose()
```

## Script Utilities

```python
# Script arguments (headless mode)
args = getScriptArgs()

# User interaction (GUI)
choice = askChoice("Title", "Message", ["Option1", "Option2"], "Option1")
text = askString("Title", "Enter value:")
addr = askAddress("Title", "Enter address:")
file = askFile("Title", "Choose file")
yesno = askYesNo("Title", "Continue?")

# Monitor for long operations
monitor = getMonitor()
monitor.setMessage("Processing...")
monitor.setProgress(50)
if monitor.isCancelled():
    return

# Print output
print("Message")           # To console
println("Message")         # Same
printerr("Error message")  # To error console
```

## Data Types

```python
from ghidra.program.model.data import *

# Primitive types
ByteDataType()
WordDataType()        # 2 bytes
DWordDataType()       # 4 bytes
QWordDataType()       # 8 bytes
FloatDataType()
DoubleDataType()
CharDataType()
UnsignedCharDataType()
IntegerDataType()
UnsignedIntegerDataType()
LongDataType()
UnsignedLongDataType()

# Pointer
PointerDataType()
PointerDataType(IntegerDataType())  # int*

# Array
ArrayDataType(ByteDataType(), 32, 1)  # byte[32]

# String types
StringDataType()
TerminatedStringDataType()
UnicodeDataType()

# Get from data type manager
dtm = currentProgram.getDataTypeManager()
dt = dtm.getDataType("/my_struct")
```

## Transaction Handling

For modifications in scripts:

```python
# Automatic (FlatProgramAPI handles this)
# Most operations auto-wrap in transaction

# Manual transaction
from ghidra.program.model.listing import Program
tx = currentProgram.startTransaction("My Changes")
try:
    # Make modifications
    func.setName("new_name", SourceType.USER_DEFINED)
    currentProgram.endTransaction(tx, True)  # True = commit
except:
    currentProgram.endTransaction(tx, False)  # False = rollback
```

## Common Imports

```python
from ghidra.program.model.symbol import SourceType, RefType, SymbolType
from ghidra.program.model.listing import CodeUnit, Function, Data
from ghidra.program.model.data import *
from ghidra.program.model.address import Address, AddressSet
from ghidra.program.model.block import BasicBlockModel
from ghidra.app.decompiler import DecompInterface
```
