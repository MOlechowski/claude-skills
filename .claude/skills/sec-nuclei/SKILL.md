---
name: sec-nuclei
description: "Fast vulnerability scanner based on templates. Scan for CVEs, misconfigurations, and security issues. Use for: (1) vulnerability scanning, (2) CVE detection, (3) security auditing, (4) custom security checks, (5) bug bounty reconnaissance. Triggers: nuclei, vulnerability scanner, cve scan, security templates, web vulnerability, bug bounty, security audit."
---

# Nuclei

Fast and customizable vulnerability scanner using templates.

## Quick Start

```bash
# Scan with all templates
nuclei -u https://example.com

# Scan with specific template
nuclei -u https://example.com -t cves/

# Scan multiple targets
nuclei -l targets.txt

# Update templates
nuclei -update-templates
```

## Target Specification

### Single Target

```bash
# URL
nuclei -u https://example.com

# With path
nuclei -u https://example.com/api/v1
```

### Multiple Targets

```bash
# From file
nuclei -l targets.txt

# From stdin
cat targets.txt | nuclei

# With httpx pipe
httpx -l hosts.txt | nuclei
```

### Target Filtering

```bash
# Scan specific paths
nuclei -u https://example.com -ept /login,/admin

# Exclude paths
nuclei -u https://example.com -ep /logout
```

## Template Selection

### Template Categories

```bash
# CVEs
nuclei -u https://example.com -t cves/

# Misconfigurations
nuclei -u https://example.com -t misconfiguration/

# Exposures
nuclei -u https://example.com -t exposures/

# Vulnerabilities
nuclei -u https://example.com -t vulnerabilities/

# Technologies
nuclei -u https://example.com -t technologies/

# Default login
nuclei -u https://example.com -t default-logins/

# Takeovers
nuclei -u https://example.com -t takeovers/

# File inclusion
nuclei -u https://example.com -t file/

# Network
nuclei -u 192.168.1.1:22 -t network/
```

### By Severity

```bash
# Critical only
nuclei -u https://example.com -s critical

# High and critical
nuclei -u https://example.com -s high,critical

# Exclude low
nuclei -u https://example.com -es low,info
```

### By Tags

```bash
# Specific tags
nuclei -u https://example.com -tags cve,rce

# Exclude tags
nuclei -u https://example.com -etags dos,fuzz

# Common tags
nuclei -u https://example.com -tags xss
nuclei -u https://example.com -tags sqli
nuclei -u https://example.com -tags ssrf
nuclei -u https://example.com -tags lfi
nuclei -u https://example.com -tags rce
nuclei -u https://example.com -tags cve2023
```

### By Author

```bash
nuclei -u https://example.com -author pdteam
```

### Specific Templates

```bash
# Single template
nuclei -u https://example.com -t cves/2023/CVE-2023-12345.yaml

# Multiple templates
nuclei -u https://example.com -t template1.yaml -t template2.yaml

# Template directory
nuclei -u https://example.com -t ./my-templates/

# Exclude templates
nuclei -u https://example.com -et cves/2020/
```

## Output Formats

```bash
# JSON
nuclei -u https://example.com -json -o results.json

# JSON lines
nuclei -u https://example.com -jsonl -o results.jsonl

# Markdown
nuclei -u https://example.com -me markdown -o results.md

# SARIF
nuclei -u https://example.com -sarif -o results.sarif

# CSV (with custom fields)
nuclei -u https://example.com -o results.csv -csv
```

### Output Options

```bash
# Verbose
nuclei -u https://example.com -v

# Debug
nuclei -u https://example.com -debug

# Silent (only results)
nuclei -u https://example.com -silent

# No color
nuclei -u https://example.com -nc
```

## Rate Limiting

```bash
# Requests per second
nuclei -u https://example.com -rl 150

# Concurrent templates
nuclei -l targets.txt -c 50

# Concurrent hosts
nuclei -l targets.txt -bs 25

# Timeout
nuclei -u https://example.com -timeout 10

# Retries
nuclei -u https://example.com -retries 3
```

## Authentication

```bash
# Headers
nuclei -u https://example.com -H "Authorization: Bearer token123"

# Cookies
nuclei -u https://example.com -H "Cookie: session=abc123"

# Multiple headers
nuclei -u https://example.com -H "Authorization: Bearer token" -H "X-Custom: value"
```

## Proxy Support

```bash
# HTTP proxy
nuclei -u https://example.com -proxy http://127.0.0.1:8080

# SOCKS proxy
nuclei -u https://example.com -proxy socks5://127.0.0.1:1080

# For interception (mitmproxy)
nuclei -u https://example.com -proxy http://127.0.0.1:8080
```

## Writing Custom Templates

### Basic Template

```yaml
id: custom-check

info:
  name: Custom Security Check
  author: your-name
  severity: medium
  description: Check for specific vulnerability
  tags: custom,web

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
```

### Template with Matchers

```yaml
id: exposed-config

info:
  name: Exposed Configuration File
  author: your-name
  severity: high
  tags: exposure,config

requests:
  - method: GET
    path:
      - "{{BaseURL}}/config.php"
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/config.json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
          - "API_KEY"
          - "SECRET_KEY"

      - type: status
        status:
          - 200
```

### Template with Extractors

```yaml
id: version-detect

info:
  name: Version Detection
  author: your-name
  severity: info
  tags: tech

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    extractors:
      - type: regex
        name: version
        regex:
          - 'Version[:\s]+([0-9.]+)'
        group: 1
```

### Workflow Template

```yaml
id: wordpress-workflow

info:
  name: WordPress Security Workflow
  author: your-name
  severity: info

workflows:
  - template: technologies/wordpress-detect.yaml
    subtemplates:
      - template: cves/wordpress/
      - template: vulnerabilities/wordpress/
```

## Common Patterns

### Full Security Scan

```bash
nuclei -l targets.txt \
  -s critical,high,medium \
  -c 50 \
  -rl 200 \
  -json \
  -o results.json
```

### CVE Scan

```bash
nuclei -u https://example.com \
  -t cves/ \
  -s critical,high \
  -json \
  -o cve-results.json
```

### Technology Detection

```bash
nuclei -u https://example.com \
  -t technologies/ \
  -json \
  -o tech-results.json
```

### Bug Bounty Recon

```bash
# Quick scan
nuclei -l targets.txt \
  -tags cve,rce,xss,sqli,ssrf,lfi \
  -s critical,high \
  -c 100

# Thorough scan
nuclei -l targets.txt \
  -automatic-scan \
  -rl 100
```

### CI Security Check

```bash
nuclei -u https://staging.example.com \
  -s critical,high \
  -sarif \
  -o nuclei.sarif \
  -silent

# Fail on findings
if [ -s nuclei.sarif ]; then
  exit 1
fi
```

## Template Management

```bash
# Update templates
nuclei -update-templates

# List templates
nuclei -tl

# Template stats
nuclei -stats

# Validate templates
nuclei -validate -t ./my-templates/

# Template info
nuclei -ti -t cves/2023/CVE-2023-12345.yaml
```

## Configuration File

### ~/.config/nuclei/config.yaml

```yaml
# Default settings
severity: high,critical
rate-limit: 150
concurrency: 50
retries: 2
timeout: 10

# Headers
header:
  - "User-Agent: Mozilla/5.0"

# Output
json: true
```

## Integration

For HTTP probing before scanning, use `/httpx`.
For port scanning, use `/nmap`.
For traffic interception during testing, use `/mitmproxy`.
For network packet analysis, use `/wireshark`.
