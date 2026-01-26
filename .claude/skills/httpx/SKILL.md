---
name: httpx
description: "Fast HTTP toolkit for probing, technology detection, and web reconnaissance. Use for: (1) HTTP probing, (2) technology fingerprinting, (3) status code filtering, (4) web server enumeration, (5) bug bounty reconnaissance. Triggers: httpx, http probe, web probe, technology detection, http toolkit, web recon, status codes."
---

# httpx

Fast and multi-purpose HTTP toolkit for web reconnaissance.

## Quick Start

```bash
# Probe single URL
echo "example.com" | httpx

# Probe from file
httpx -l hosts.txt

# With status codes
httpx -l hosts.txt -sc

# With technology detection
httpx -l hosts.txt -tech-detect

# Full output
httpx -l hosts.txt -sc -cl -ct -title -tech-detect
```

## Input Methods

### From File

```bash
# Hosts file
httpx -l hosts.txt

# URLs file
httpx -l urls.txt
```

### From Stdin

```bash
# Single host
echo "example.com" | httpx

# Multiple hosts
cat hosts.txt | httpx

# From other tools
subfinder -d example.com | httpx
nmap -sn 192.168.1.0/24 -oG - | grep "Up" | cut -d" " -f2 | httpx
```

### Direct Input

```bash
# Single URL
httpx -u https://example.com

# Multiple URLs
httpx -u https://example.com -u https://example.org
```

## Probes and Detection

### Basic Probes

```bash
# Status code
httpx -l hosts.txt -sc

# Content length
httpx -l hosts.txt -cl

# Content type
httpx -l hosts.txt -ct

# Title
httpx -l hosts.txt -title

# Server header
httpx -l hosts.txt -server

# Web server
httpx -l hosts.txt -web-server

# Response time
httpx -l hosts.txt -rt

# All probes
httpx -l hosts.txt -sc -cl -ct -title -server -rt
```

### Technology Detection

```bash
# Wappalyzer-based detection
httpx -l hosts.txt -tech-detect

# With JSON output
httpx -l hosts.txt -tech-detect -json
```

### TLS/SSL Info

```bash
# TLS probe
httpx -l hosts.txt -tls-probe

# TLS grab (certificate info)
httpx -l hosts.txt -tls-grab

# Cipher suites
httpx -l hosts.txt -cipher
```

### Response Extraction

```bash
# Extract specific header
httpx -l hosts.txt -extract-regex 'Server: (.+)'

# Extract from body
httpx -l hosts.txt -extract-regex 'version[:\s]+([0-9.]+)'

# Response body hash
httpx -l hosts.txt -hash sha256
```

## Filtering

### By Status Code

```bash
# Match specific codes
httpx -l hosts.txt -mc 200,301,302

# Filter codes
httpx -l hosts.txt -fc 404,403,500

# Match ranges
httpx -l hosts.txt -mc 200-299
```

### By Content Length

```bash
# Match length
httpx -l hosts.txt -ml 1234

# Filter length
httpx -l hosts.txt -fl 0
```

### By Content

```bash
# Match string in body
httpx -l hosts.txt -ms "login"

# Filter string
httpx -l hosts.txt -fs "error"

# Match regex
httpx -l hosts.txt -mr "admin.*panel"
```

### By Technology

```bash
# Match technology
httpx -l hosts.txt -tech-detect -mt "WordPress"

# Filter technology
httpx -l hosts.txt -tech-detect -ft "nginx"
```

## Output Formats

```bash
# Standard output (default)
httpx -l hosts.txt

# JSON
httpx -l hosts.txt -json

# JSON lines
httpx -l hosts.txt -jsonl

# CSV
httpx -l hosts.txt -csv

# To file
httpx -l hosts.txt -o results.txt

# JSON to file
httpx -l hosts.txt -json -o results.json
```

### Output Fields

```bash
# Custom output format
httpx -l hosts.txt -o output.txt -no-color

# Store response
httpx -l hosts.txt -sr -srd ./responses/

# Store request
httpx -l hosts.txt -store-req -store-req-dir ./requests/

# Screenshot (requires chromium)
httpx -l hosts.txt -screenshot -srd ./screenshots/
```

## Request Options

### HTTP Methods

```bash
# GET (default)
httpx -l hosts.txt

# HEAD
httpx -l hosts.txt -x HEAD

# POST
httpx -l hosts.txt -x POST -body '{"key":"value"}'

# Custom method
httpx -l hosts.txt -x OPTIONS
```

### Headers

```bash
# Add header
httpx -l hosts.txt -H "Authorization: Bearer token"

# Multiple headers
httpx -l hosts.txt -H "Authorization: Bearer token" -H "X-Custom: value"

# User agent
httpx -l hosts.txt -H "User-Agent: Mozilla/5.0"
```

### Follow Redirects

```bash
# Follow redirects
httpx -l hosts.txt -follow-redirects

# Max redirects
httpx -l hosts.txt -follow-redirects -max-redirects 5

# Show redirect chain
httpx -l hosts.txt -follow-redirects -location
```

### Paths

```bash
# Append path
httpx -l hosts.txt -path /api/v1/health

# Multiple paths
httpx -l hosts.txt -path /admin -path /login -path /api
```

## Performance

### Rate Limiting

```bash
# Requests per second
httpx -l hosts.txt -rl 100

# Threads
httpx -l hosts.txt -threads 50
```

### Timeouts

```bash
# Timeout
httpx -l hosts.txt -timeout 10

# Retries
httpx -l hosts.txt -retries 2
```

## Proxy Support

```bash
# HTTP proxy
httpx -l hosts.txt -proxy http://127.0.0.1:8080

# SOCKS proxy
httpx -l hosts.txt -proxy socks5://127.0.0.1:1080

# For interception
httpx -l hosts.txt -proxy http://127.0.0.1:8080
```

## Common Patterns

### Basic Reconnaissance

```bash
httpx -l hosts.txt \
  -sc -cl -title -tech-detect \
  -json \
  -o recon.json
```

### Filter Live Hosts

```bash
# Only 200 OK
httpx -l hosts.txt -mc 200

# Only active web servers
httpx -l hosts.txt -fc 404,502,503
```

### Technology Survey

```bash
httpx -l hosts.txt \
  -tech-detect \
  -sc -title \
  -json \
  -o tech-survey.json
```

### Find Login Pages

```bash
httpx -l hosts.txt \
  -path /login -path /admin -path /signin \
  -mc 200 \
  -title \
  -ms "login\|sign in\|password"
```

### Full Asset Discovery

```bash
# From subdomain enumeration
subfinder -d example.com -silent | \
  httpx -sc -cl -title -tech-detect -json -o assets.json
```

### CI Health Check

```bash
httpx -u https://api.example.com/health \
  -mc 200 \
  -ms "healthy" \
  -silent

if [ $? -ne 0 ]; then
  echo "Health check failed"
  exit 1
fi
```

### Screenshot All Sites

```bash
httpx -l hosts.txt \
  -mc 200 \
  -screenshot \
  -srd ./screenshots/ \
  -threads 10
```

### Pipeline with Nuclei

```bash
# Probe first, then scan
httpx -l hosts.txt -mc 200 | nuclei -t cves/ -s critical,high
```

## Configuration

### ~/.config/httpx/config.yaml

```yaml
# Default settings
threads: 50
rate-limit: 150
timeout: 10
retries: 2
follow-redirects: true

# Default probes
status-code: true
content-length: true
title: true
tech-detect: true

# Output
json: true
```

## Integration

For vulnerability scanning, use `/nuclei`.
For port discovery, use `/nmap`.
For traffic interception, use `/mitmproxy`.
For detailed packet analysis, use `/wireshark`.
