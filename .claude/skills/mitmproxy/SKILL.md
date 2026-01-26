---
name: mitmproxy
description: "Interactive HTTPS proxy for intercepting, inspecting, and modifying HTTP/HTTPS traffic. Use for: (1) API debugging, (2) traffic interception, (3) request/response modification, (4) SSL/TLS inspection, (5) automated testing. Triggers: mitmproxy, mitmdump, mitmweb, https proxy, intercept traffic, ssl interception, http proxy, api debugging."
---

# mitmproxy

Interactive HTTPS proxy for intercepting, inspecting, and modifying traffic.

## Quick Start

```bash
# Interactive TUI
mitmproxy

# Web interface
mitmweb

# Non-interactive (scripting)
mitmdump

# Start on specific port
mitmproxy -p 8080

# Save traffic
mitmdump -w traffic.flow
```

## Components

| Tool | Interface | Use Case |
|------|-----------|----------|
| `mitmproxy` | Terminal UI | Interactive inspection |
| `mitmweb` | Web browser | Visual debugging |
| `mitmdump` | CLI output | Scripting, automation |

## Basic Operations

### Start Proxy

```bash
# Default port 8080
mitmproxy

# Custom port
mitmproxy -p 9090

# Listen on all interfaces
mitmproxy --listen-host 0.0.0.0

# With upstream proxy
mitmproxy --mode upstream:http://proxy:8080
```

### Proxy Modes

```bash
# Regular proxy (default)
mitmproxy --mode regular

# Transparent proxy
mitmproxy --mode transparent

# Reverse proxy
mitmproxy --mode reverse:https://api.example.com

# SOCKS proxy
mitmproxy --mode socks5

# Upstream proxy
mitmproxy --mode upstream:http://corporate-proxy:8080
```

## Certificate Setup

### Generate CA Certificate

```bash
# Certificates stored in ~/.mitmproxy/
ls ~/.mitmproxy/

# Files:
# mitmproxy-ca.pem - CA certificate (install this)
# mitmproxy-ca-cert.cer - Windows format
# mitmproxy-ca-cert.p12 - PKCS12 format
# mitmproxy-ca-cert.pem - PEM format
```

### Install on Systems

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem

# Linux (Debian/Ubuntu)
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates

# Firefox
# Import ~/.mitmproxy/mitmproxy-ca-cert.pem in Settings > Privacy > Certificates
```

### Custom Certificate

```bash
# Use custom CA
mitmproxy --set ssl_insecure=true --certs *=./my-cert.pem
```

## Filtering Traffic

### Host Filters

```bash
# Only specific hosts
mitmproxy --ignore-hosts '.*\.google\.com'

# Allow only specific hosts
mitmdump -w traffic.flow '~d api.example.com'
```

### Flow Filters

| Filter | Description |
|--------|-------------|
| `~d domain` | Match domain |
| `~u url` | Match URL |
| `~m method` | Match HTTP method |
| `~c code` | Match response code |
| `~h header` | Match header |
| `~b body` | Match body content |
| `~q` | Match request |
| `~s` | Match response |
| `~t content-type` | Match content type |

```bash
# Filter examples
mitmdump '~d api.example.com'
mitmdump '~u /api/v1'
mitmdump '~m POST'
mitmdump '~c 500'
mitmdump '~b password'
mitmdump '~q ~h Authorization'
```

## Interactive Commands (mitmproxy TUI)

| Key | Action |
|-----|--------|
| `?` | Help |
| `q` | Quit |
| `Enter` | View flow details |
| `Tab` | Switch request/response |
| `e` | Edit flow |
| `r` | Replay flow |
| `d` | Delete flow |
| `z` | Clear flow list |
| `f` | Set filter |
| `i` | Set intercept filter |
| `/` | Search |
| `w` | Save flows |

## Scripting (mitmdump)

### Basic Script

```python
# modify_requests.py
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Add header to all requests
    flow.request.headers["X-Custom-Header"] = "value"

def response(flow: http.HTTPFlow) -> None:
    # Log response codes
    print(f"{flow.request.url} -> {flow.response.status_code}")
```

```bash
# Run with script
mitmdump -s modify_requests.py
```

### Request Modification

```python
# modify_api.py
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Redirect API calls
    if "api.old.com" in flow.request.host:
        flow.request.host = "api.new.com"

    # Modify query parameters
    if flow.request.query.get("debug"):
        flow.request.query["debug"] = "true"

    # Add authentication
    if "api.example.com" in flow.request.host:
        flow.request.headers["Authorization"] = "Bearer token123"
```

### Response Modification

```python
# modify_response.py
from mitmproxy import http
import json

def response(flow: http.HTTPFlow) -> None:
    # Modify JSON response
    if "application/json" in flow.response.headers.get("content-type", ""):
        data = json.loads(flow.response.content)
        data["injected"] = True
        flow.response.content = json.dumps(data).encode()

    # Remove security headers
    flow.response.headers.pop("X-Frame-Options", None)
    flow.response.headers.pop("Content-Security-Policy", None)
```

### Filter in Script

```python
# filtered_logging.py
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # Only log API calls
    if "api.example.com" in flow.request.host:
        print(f"[{flow.response.status_code}] {flow.request.method} {flow.request.path}")

        # Log errors
        if flow.response.status_code >= 400:
            print(f"  Error: {flow.response.content[:200]}")
```

## Recording and Replay

### Save Traffic

```bash
# Save all traffic
mitmdump -w traffic.flow

# Save filtered traffic
mitmdump -w api.flow '~d api.example.com'

# Append to existing
mitmdump -a traffic.flow
```

### Replay Traffic

```bash
# Client replay (to server)
mitmdump -C traffic.flow

# Server replay (to client)
mitmdump -S traffic.flow

# Replay with modifications
mitmdump -C traffic.flow -s modify.py
```

### Export Formats

```bash
# Export as HAR
mitmdump -r traffic.flow --set hardump=./traffic.har

# Read HAR
mitmproxy -r traffic.har
```

## Common Patterns

### API Debugging

```bash
# Intercept specific API
mitmproxy -p 8080 '~d api.example.com'

# Configure application to use proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
```

### Mobile App Testing

```bash
# Start proxy accessible from network
mitmweb --listen-host 0.0.0.0 -p 8080

# On mobile device:
# 1. Set proxy to <your-ip>:8080
# 2. Visit mitm.it to install certificate
# 3. Trust certificate in settings
```

### Mock API Responses

```python
# mock_api.py
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    if flow.request.path == "/api/users":
        flow.response = http.Response.make(
            200,
            b'[{"id": 1, "name": "Mock User"}]',
            {"Content-Type": "application/json"}
        )
```

```bash
mitmdump -s mock_api.py
```

### Throttle Traffic

```python
# throttle.py
import time
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # Add 2 second delay
    time.sleep(2)
```

### Log Sensitive Data

```python
# log_sensitive.py
from mitmproxy import http
import re

def request(flow: http.HTTPFlow) -> None:
    # Log authorization headers
    if "Authorization" in flow.request.headers:
        print(f"Auth: {flow.request.headers['Authorization'][:50]}...")

    # Log cookies
    if "Cookie" in flow.request.headers:
        print(f"Cookies: {flow.request.headers['Cookie'][:100]}...")

    # Find passwords in body
    if flow.request.content:
        body = flow.request.content.decode('utf-8', errors='ignore')
        if re.search(r'password|passwd|pwd', body, re.I):
            print(f"Potential password in: {flow.request.url}")
```

## Integration

For packet-level capture, use `/tcpdump`.
For protocol analysis, use `/wireshark`.
For web security testing, combine with `/nuclei` or `/httpx`.
