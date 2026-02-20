---
name: cf-ctl
description: "Cloudflare infrastructure CLI. Use for: DNS records, firewall rules, zone management, cache purging. Triggers: flarectl, cloudflare dns, cloudflare firewall."
---

# flarectl

Cloudflare infrastructure CLI for managing DNS, zones, firewall rules, and cache.

## Install

```bash
# Go
go install github.com/cloudflare/cloudflare-go/cmd/flarectl@latest

# Homebrew
brew install flarectl
```

## Authentication

```bash
# API Token (recommended)
export CF_API_TOKEN="your-token"

# Or API Key (legacy)
export CF_API_EMAIL="your-email"
export CF_API_KEY="your-global-api-key"
```

## Commands Overview

| Command | Alias | Purpose |
|---------|-------|---------|
| `zone` | `z` | Zone information |
| `dns` | `d` | DNS records |
| `firewall` | `f` | Firewall rules |
| `ips` | `i` | Cloudflare IP ranges |
| `user` | `u` | User information |
| `pagerules` | `p` | Page Rules |
| `railgun` | `r` | Railgun information |

## Zone Management

```bash
# List all zones
flarectl zone list

# Get zone info
flarectl zone info --zone example.com

# Purge cache (all files)
flarectl zone purge --zone example.com --everything

# Purge specific URLs
flarectl zone purge --zone example.com \
  --files "https://example.com/style.css,https://example.com/app.js"
```

## DNS Records

```bash
# List DNS records
flarectl dns list --zone example.com

# Create A record
flarectl dns create --zone example.com \
  --name app \
  --type A \
  --content 192.0.2.1 \
  --proxy

# Create CNAME record
flarectl dns create --zone example.com \
  --name www \
  --type CNAME \
  --content example.com \
  --proxy

# Create TXT record
flarectl dns create --zone example.com \
  --name _dmarc \
  --type TXT \
  --content "v=DMARC1; p=reject"

# Update DNS record
flarectl dns update --zone example.com \
  --id <record-id> \
  --content 192.0.2.2

# Delete DNS record
flarectl dns delete --zone example.com --id <record-id>
```

### DNS Record Options

| Flag | Description |
|------|-------------|
| `--name` | Record name (subdomain or @ for root) |
| `--type` | A, AAAA, CNAME, TXT, MX, etc. |
| `--content` | Record value |
| `--ttl` | TTL in seconds (1 = auto when proxied) |
| `--proxy` | Enable Cloudflare proxy (orange cloud) |
| `--priority` | MX/SRV priority |

## Firewall Rules

```bash
# List firewall rules
flarectl firewall rules list --zone example.com

# Block an IP
flarectl firewall rules create --zone example.com \
  --value 8.8.8.8 \
  --mode block \
  --notes "Block bad actor"

# Challenge an IP range
flarectl firewall rules create --zone example.com \
  --value 192.0.2.0/24 \
  --mode challenge \
  --notes "Suspicious range"

# Whitelist an IP
flarectl firewall rules create --zone example.com \
  --value 10.0.0.1 \
  --mode whitelist \
  --notes "Office IP"

# Delete firewall rule
flarectl firewall rules delete --zone example.com --id <rule-id>
```

### Firewall Modes

| Mode | Description |
|------|-------------|
| `block` | Block all requests |
| `challenge` | Present CAPTCHA challenge |
| `whitelist` | Allow without checks |
| `js_challenge` | JavaScript challenge |
| `managed_challenge` | Cloudflare managed challenge |

## Cloudflare IP Ranges

```bash
# List all Cloudflare IPs
flarectl ips

# Output includes IPv4 and IPv6 ranges used by Cloudflare
```

Useful for configuring firewall rules on origin servers.

## User Information

```bash
# Get current user info
flarectl user info
```

## Page Rules

```bash
# List page rules
flarectl pagerules list --zone example.com
```

## Common Workflows

### Add New Subdomain

```bash
# Create DNS record
flarectl dns create --zone example.com \
  --name api \
  --type A \
  --content 192.0.2.1 \
  --proxy

# Verify
flarectl dns list --zone example.com | grep api
```

### Block Malicious IPs

```bash
# Block single IP
flarectl firewall rules create --zone example.com \
  --value 203.0.113.50 \
  --mode block \
  --notes "Malicious traffic 2025-01-22"

# Block IP range
flarectl firewall rules create --zone example.com \
  --value 203.0.113.0/24 \
  --mode block \
  --notes "Malicious network"
```

### Clear Cache After Deploy

```bash
# Purge everything
flarectl zone purge --zone example.com --everything

# Or purge specific assets
flarectl zone purge --zone example.com \
  --files "https://example.com/js/app.js,https://example.com/css/style.css"
```
