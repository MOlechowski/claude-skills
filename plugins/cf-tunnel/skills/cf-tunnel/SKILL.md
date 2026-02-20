---
name: cf-tunnel
description: "Cloudflare Tunnel CLI for exposing local services. Use for: quick tunnels (dev), named tunnels (prod), DNS routing, system service setup. Triggers: cloudflared, tunnel, expose localhost."
---

# cloudflared

Cloudflare Tunnel CLI for securely exposing local services to the internet.

## Install

```bash
brew install cloudflared
```

## Quick Tunnels (Development)

Instant public URL without authentication:

```bash
cloudflared tunnel --url http://localhost:8080
# Output: https://random-words.trycloudflare.com
```

**Limitations:**
- URL changes on restart
- 200 in-flight request limit (returns 429)
- No Server-Sent Events (SSE) support
- Won't work if `~/.cloudflared/config.yml` exists

## Named Tunnels (Production)

### Setup

```bash
# 1. Authenticate
cloudflared tunnel login

# 2. Create tunnel
cloudflared tunnel create <tunnel-name>
# Creates: ~/.cloudflared/<tunnel-id>.json (credentials)

# 3. Route DNS
cloudflared tunnel route dns <tunnel-name> <hostname>
# Example: cloudflared tunnel route dns gh-runner webhook.example.com

# 4. Run tunnel
cloudflared tunnel run <tunnel-name>
```

## Commands Reference

```bash
# Authentication
tunnel login                    # Authenticate with Cloudflare

# Tunnel Management
tunnel create <name>            # Create named tunnel
tunnel list                     # List tunnels
tunnel list -d                  # Include deleted tunnels
tunnel info <name>              # Show tunnel details
tunnel delete <name>            # Delete tunnel
tunnel delete -f <name>         # Force delete (active connections)
tunnel cleanup <name>           # Remove stale connections
tunnel token <name>             # Get tunnel token

# Running
tunnel run <name>               # Run tunnel
tunnel --url http://localhost:PORT  # Quick tunnel

# DNS Routing
tunnel route dns <name> <hostname>      # Route DNS to tunnel
tunnel route dns <name> *.example.com   # Wildcard subdomain

# IP Routing (Private Networks)
tunnel route ip add <CIDR> <name>       # Route IP range
tunnel route ip show                    # List IP routes
tunnel route ip delete <CIDR> <name>    # Remove IP route
tunnel route ip get <IP>                # Check routing

# System Service
service install                 # Install as system service
```

## Configuration File

Location: `~/.cloudflared/config.yml` (default)

### Basic Config

```yaml
tunnel: <tunnel-id-or-name>
credentials-file: /Users/<user>/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: webhook.example.com
    service: http://localhost:8080
  - service: http_status:404  # Catch-all (required)
```

### Advanced Config

```yaml
tunnel: gh-runner
credentials-file: ~/.cloudflared/<id>.json

# Connection settings
protocol: quic              # quic (default), http2
no-tls-verify: false        # Verify origin TLS
origin-server-name: ""      # Override SNI

ingress:
  # Specific path
  - hostname: api.example.com
    path: /webhook
    service: http://localhost:8080
    originRequest:
      connectTimeout: 30s
      noTLSVerify: false

  # Wildcard hostname
  - hostname: "*.example.com"
    service: http://localhost:3000

  # TCP service
  - hostname: ssh.example.com
    service: ssh://localhost:22

  # Catch-all (required last)
  - service: http_status:404
```

### Origin Request Options

```yaml
originRequest:
  connectTimeout: 30s       # Connection timeout
  tlsTimeout: 10s           # TLS handshake timeout
  tcpKeepAlive: 30s         # TCP keepalive
  noHappyEyeballs: false    # Disable IPv4/IPv6 fallback
  keepAliveConnections: 100 # Connection pool size
  keepAliveTimeout: 90s     # Idle connection timeout
  httpHostHeader: ""        # Override Host header
  originServerName: ""      # TLS SNI override
  noTLSVerify: false        # Skip TLS verification
  disableChunkedEncoding: false
  proxyAddress: ""          # HTTP proxy
  proxyPort: 0
  proxyType: ""             # socks5, http
```

## System Service

### macOS

```bash
# Install service
sudo cloudflared service install

# Check status
launchctl list | grep cloudflared

# View logs
log show --predicate 'subsystem == "com.cloudflare.cloudflared"' --last 1h

# Uninstall
sudo cloudflared service uninstall
```

### Linux (systemd)

```bash
# Install service
sudo cloudflared service install

# Manage service
sudo systemctl status cloudflared
sudo systemctl start cloudflared
sudo systemctl stop cloudflared
sudo systemctl restart cloudflared
sudo systemctl enable cloudflared   # Start on boot

# View logs
journalctl -u cloudflared -f
```

### Service Config Location

- macOS: `/Library/LaunchDaemons/com.cloudflare.cloudflared.plist`
- Linux: `/etc/systemd/system/cf-tunnel.service`
- Config: `/etc/cloudflared/config.yml`

## Virtual Networks

Isolate overlapping IP ranges:

```bash
cloudflared tunnel vnet add my-vnet
cloudflared tunnel vnet add my-vnet -d  # Set as default
cloudflared tunnel vnet list
cloudflared tunnel vnet delete my-vnet

# Route with vnet
cloudflared tunnel route ip add --vnet my-vnet 10.0.0.0/8 my-tunnel
```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| 502 Bad Gateway | Origin not running | Start local service |
| Tunnel disconnects | Network instability | cloudflared auto-reconnects |
| DNS not resolving | Propagation delay | Wait 5-10 minutes, check with `dig` |
| Certificate errors | TLS misconfiguration | Check `noTLSVerify` setting |
| Config not loading | Wrong location | Specify `--config path/config.yml` |
| Quick tunnel 429 | 200 request limit | Use named tunnel |

### Logs and Debugging

```bash
# Tail tunnel logs
cloudflared tail <tunnel-id>

# Debug mode
cloudflared tunnel --loglevel debug run <name>

# Trace requests
cloudflared tunnel --loglevel trace run <name>
```
