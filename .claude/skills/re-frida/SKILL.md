---
name: re-frida
description: "Frida dynamic instrumentation: hooking, tracing, memory manipulation, iOS/Android analysis. Use for: runtime hooking, function interception, mobile app analysis, bypassing protections. Triggers: frida, frida-trace, hook function, instrument binary, mobile reversing, intercept calls, bypass ssl pinning."
---

# Frida

Dynamic instrumentation toolkit for hooking and tracing.

## Quick Start

```bash
# Install
pip install frida-tools

# List processes
frida-ps
frida-ps -U              # USB-connected device (iOS/Android)

# Attach and spawn
frida ./binary           # Spawn new process
frida -p PID             # Attach to running
frida -U com.app.name    # Attach to mobile app
```

## frida-trace

Quick function tracing without writing scripts.

```bash
# Trace by function name
frida-trace -i "open" ./binary
frida-trace -i "recv*" ./binary       # Wildcard

# Trace by module
frida-trace -I "libssl*" ./binary     # All libssl functions

# Trace Objective-C methods (iOS)
frida-trace -U -m "-[NSURLSession *]" com.app

# Trace Java methods (Android)
frida-trace -U -j "javax.crypto.Cipher*" com.app
```

## JavaScript API

### Basic Hooking

```javascript
// Attach to function
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        console.log("open(" + args[0].readUtf8String() + ")");
    },
    onLeave: function(retval) {
        console.log("returned: " + retval);
    }
});
```

### Replace Function

```javascript
Interceptor.replace(ptr("0x401234"), new NativeCallback(function() {
    console.log("Function bypassed");
    return 1;  // Return success
}, 'int', []));
```

### Memory Operations

```javascript
// Read memory
Memory.readUtf8String(ptr("0x401234"));
Memory.readByteArray(ptr("0x401234"), 16);

// Write memory
Memory.writeUtf8String(ptr("0x401234"), "patched");
Memory.writeByteArray(ptr("0x401234"), [0x90, 0x90]);

// Search memory
Memory.scan(module.base, module.size, "48 89 e5", {
    onMatch: function(address, size) {
        console.log("Found at: " + address);
    }
});
```

## Run Scripts

```bash
# Run script file
frida -l script.js ./binary

# With arguments
frida -l script.js --runtime=v8 ./binary

# Mobile
frida -U -l script.js com.app
```

## iOS/Android

### iOS (Objective-C)

```javascript
// Hook ObjC method
ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation = function(req, handler) {
    console.log("URL: " + req.URL().absoluteString());
    return this.original(req, handler);
};

// Bypass jailbreak detection
ObjC.classes.SomeClass["- isJailbroken"].implementation = function() {
    return false;
};
```

### Android (Java)

```javascript
Java.perform(function() {
    var MainActivity = Java.use("com.app.MainActivity");
    MainActivity.checkRoot.implementation = function() {
        console.log("Root check bypassed");
        return false;
    };
});
```

### SSL Pinning Bypass

```javascript
// iOS
ObjC.classes.NSURLSessionConfiguration["- setURLCredentialStorage:"].implementation = function() {};

// Android (common patterns)
Java.perform(function() {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function() {};
});
```

## Common Tasks

### Trace all calls to function
```javascript
var targetFunc = Module.findExportByName(null, "strcmp");
Interceptor.attach(targetFunc, {
    onEnter: function(args) {
        console.log("strcmp(" + args[0].readUtf8String() + ", " + args[1].readUtf8String() + ")");
    }
});
```

### Dump function arguments
```javascript
Interceptor.attach(ptr("0x401234"), {
    onEnter: function(args) {
        console.log("arg0: " + args[0]);
        console.log("arg1: " + args[1].readUtf8String());
        console.log("stack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
    }
});
```

### Find and hook by pattern
```javascript
var module = Process.findModuleByName("target.so");
Memory.scan(module.base, module.size, "55 48 89 e5", {
    onMatch: function(address) {
        Interceptor.attach(address, { onEnter: function() { console.log("Hit"); }});
    }
});
```

For detailed API reference, see: [references/api.md](references/api.md)

## Integration

For syscall tracing, use `/re-strace`.
For static analysis, use `/re-ghidra` or `/re-radare2`.
For debugging, use `/re-gdb` or `/re-lldb`.
