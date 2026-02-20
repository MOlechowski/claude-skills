# Frida JavaScript API Reference

## Core Objects

### Process

```javascript
Process.id                          // Process ID
Process.arch                        // Architecture (ia32, x64, arm, arm64)
Process.platform                    // Platform (windows, darwin, linux)
Process.pointerSize                 // 4 or 8
Process.pageSize                    // Page size
Process.codeSigningPolicy           // optional, required, disabled
Process.isDebuggerAttached()        // Boolean
Process.getCurrentThreadId()        // Current thread ID
Process.enumerateThreads()          // Array of Thread objects
Process.findModuleByName(name)      // Module or null
Process.findModuleByAddress(addr)   // Module or null
Process.enumerateModules()          // Array of Module objects
Process.findRangeByAddress(addr)    // RangeDetails or null
Process.enumerateRanges(prot)       // Array of RangeDetails
```

### Module

```javascript
Module.findExportByName(module, name)    // NativePointer or null
Module.findBaseAddress(name)             // NativePointer or null
Module.enumerateExports(name)            // Array of exports
Module.enumerateImports(name)            // Array of imports
Module.enumerateSymbols(name)            // Array of symbols
Module.enumerateSections(name)           // Array of sections
Module.load(path)                        // Load module

// Module object properties
module.name                              // Module name
module.base                              // Base address (NativePointer)
module.size                              // Size in bytes
module.path                              // Full path
```

### Memory

```javascript
// Allocation
Memory.alloc(size)                       // NativePointer
Memory.allocUtf8String(str)              // NativePointer
Memory.allocAnsiString(str)              // NativePointer (Windows)
Memory.allocUtf16String(str)             // NativePointer

// Reading
Memory.readPointer(addr)
Memory.readS8(addr) / Memory.readU8(addr)
Memory.readS16(addr) / Memory.readU16(addr)
Memory.readS32(addr) / Memory.readU32(addr)
Memory.readS64(addr) / Memory.readU64(addr)
Memory.readFloat(addr) / Memory.readDouble(addr)
Memory.readByteArray(addr, length)
Memory.readUtf8String(addr, [maxLength])
Memory.readUtf16String(addr, [maxLength])
Memory.readAnsiString(addr, [maxLength])
Memory.readCString(addr, [maxLength])

// Writing
Memory.writePointer(addr, value)
Memory.writeS8(addr, value) / Memory.writeU8(addr, value)
Memory.writeS16(addr, value) / Memory.writeU16(addr, value)
Memory.writeS32(addr, value) / Memory.writeU32(addr, value)
Memory.writeS64(addr, value) / Memory.writeU64(addr, value)
Memory.writeFloat(addr, value) / Memory.writeDouble(addr, value)
Memory.writeByteArray(addr, bytes)
Memory.writeUtf8String(addr, str)
Memory.writeUtf16String(addr, str)

// Protection
Memory.protect(addr, size, protection)   // 'rwx', 'r--', etc.

// Scanning
Memory.scan(addr, size, pattern, callbacks)
Memory.scanSync(addr, size, pattern)     // Returns array of matches

// Pattern format: "48 89 e5 ?? 90"  (? = wildcard)
```

### Interceptor

```javascript
// Attach to function
Interceptor.attach(target, {
    onEnter: function(args) {
        // args[0], args[1], etc.
        // this.context - CPU registers
        // this.errno (POSIX) / this.lastError (Windows)
        // this.threadId, this.depth, this.returnAddress
    },
    onLeave: function(retval) {
        // retval.replace(newValue)
    }
});

// Replace function
Interceptor.replace(target, replacement)

// Revert
Interceptor.revert(target)

// Flush inline caches
Interceptor.flush()
```

### NativePointer

```javascript
ptr("0x401234")                     // Create from string
ptr(address)                        // Create from number
NULL                                // Null pointer

pointer.add(offset)                 // Add offset
pointer.sub(offset)                 // Subtract offset
pointer.and(mask)                   // Bitwise AND
pointer.or(mask)                    // Bitwise OR
pointer.xor(mask)                   // Bitwise XOR
pointer.shr(n)                      // Shift right
pointer.shl(n)                      // Shift left
pointer.not()                       // Bitwise NOT

pointer.equals(other)               // Compare
pointer.compare(other)              // -1, 0, 1
pointer.isNull()                    // Check if null

pointer.toInt32()                   // To signed 32-bit
pointer.toUInt32()                  // To unsigned 32-bit
pointer.toString([radix])           // To string

// Read/write shortcuts
pointer.readPointer()
pointer.readS32() / pointer.readU32()
pointer.readUtf8String()
pointer.readByteArray(length)
pointer.writePointer(value)
pointer.writeS32(value) / pointer.writeU32(value)
pointer.writeUtf8String(str)
pointer.writeByteArray(bytes)
```

### NativeFunction

```javascript
// Call native function
var func = new NativeFunction(address, returnType, argTypes);
var result = func(arg1, arg2);

// Types: void, pointer, int, uint, long, ulong, char, uchar,
//        float, double, int8, uint8, int16, uint16, int32, uint32,
//        int64, uint64, bool, size_t, ssize_t

// Example
var open = new NativeFunction(
    Module.findExportByName(null, "open"),
    'int',
    ['pointer', 'int']
);
var fd = open(Memory.allocUtf8String("/etc/passwd"), 0);
```

### NativeCallback

```javascript
// Create callback for native code to call
var callback = new NativeCallback(function(arg1, arg2) {
    console.log("Called with:", arg1, arg2);
    return 0;
}, 'int', ['pointer', 'int']);
```

## Thread

```javascript
Thread.backtrace([context], [backtracer])
Thread.sleep(delay)                 // Seconds (float)

// Backtracer: Backtracer.ACCURATE or Backtracer.FUZZY
```

## Debug Symbols

```javascript
DebugSymbol.fromAddress(addr)       // DebugSymbol or null
DebugSymbol.fromName(name)          // DebugSymbol or null
DebugSymbol.getFunctionByName(name) // NativePointer or null
DebugSymbol.findFunctionsNamed(name) // Array of NativePointer
DebugSymbol.findFunctionsMatching(glob) // Array of NativePointer

// DebugSymbol properties
symbol.address                      // NativePointer
symbol.name                         // String or null
symbol.moduleName                   // String or null
symbol.fileName                     // String or null
symbol.lineNumber                   // Number or null
```

## Stalker (Code Tracing)

```javascript
Stalker.follow([threadId], {
    events: {
        call: true,     // CALL instructions
        ret: true,      // RET instructions
        exec: true,     // All instructions
        block: true,    // Basic blocks
        compile: true   // Compilations
    },
    onReceive: function(events) {
        // Batch of events
    },
    onCallSummary: function(summary) {
        // Call statistics
    }
});

Stalker.unfollow([threadId])
Stalker.flush()
Stalker.garbageCollect()
```

## ObjC (iOS/macOS)

```javascript
ObjC.available                      // Boolean
ObjC.api                            // objc_* functions
ObjC.classes                        // All ObjC classes
ObjC.protocols                      // All ObjC protocols
ObjC.Object(handle)                 // Wrap native pointer
ObjC.implement(method, callback)    // Implement method
ObjC.registerClass(spec)            // Register new class
ObjC.schedule(queue, work)          // Schedule on queue

// Hook ObjC method
var NSString = ObjC.classes.NSString;
NSString["- isEqualToString:"].implementation = function(other) {
    var result = this.original(other);
    console.log(this.toString() + " == " + other.toString() + ": " + result);
    return result;
};
```

## Java (Android)

```javascript
Java.available                      // Boolean
Java.androidVersion                 // API level string

Java.perform(function() {
    // Access Java classes
    var Activity = Java.use("android.app.Activity");

    // Hook method
    Activity.onCreate.implementation = function(bundle) {
        console.log("onCreate called");
        this.onCreate(bundle);
    };

    // Hook overloaded method
    var String = Java.use("java.lang.String");
    String.valueOf.overload("int").implementation = function(i) {
        console.log("valueOf(" + i + ")");
        return this.valueOf(i);
    };

    // Create instance
    var StringBuilder = Java.use("java.lang.StringBuilder");
    var sb = StringBuilder.$new();
    sb.append("hello");
    console.log(sb.toString());
});

// Enumerate loaded classes
Java.enumerateLoadedClasses({
    onMatch: function(className) { console.log(className); },
    onComplete: function() {}
});

// Choose instances
Java.choose("com.example.MyClass", {
    onMatch: function(instance) {
        console.log("Found: " + instance);
    },
    onComplete: function() {}
});
```

## Utilities

```javascript
// Console
console.log(msg)
console.warn(msg)
console.error(msg)

// Hex dump
hexdump(target, [options])
// options: { offset: 0, length: 64, header: true, ansi: true }

// Send to Python
send(message, [data])               // Send JSON + optional binary

// Receive from Python
recv(type, callback)                // Receive specific type
recv(callback)                      // Receive any

// RPC exports
rpc.exports = {
    myFunction: function(arg) {
        return "result";
    }
};
```
