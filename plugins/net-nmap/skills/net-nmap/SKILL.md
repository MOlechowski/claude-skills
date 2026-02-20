---
name: net-nmap
description: "Network scanner for port discovery, service detection, and OS fingerprinting. Use for: (1) port scanning, (2) service enumeration, (3) vulnerability detection, (4) network mapping, (5) security auditing. Triggers: nmap, port scan, service detection, network scan, os fingerprint, security scan, network discovery."
---

# Nmap

Network exploration and security auditing tool.

## Quick Start

```bash
# Basic port scan
nmap 192.168.1.1

# Scan common ports
nmap --top-ports 100 192.168.1.1

# Service version detection
nmap -sV 192.168.1.1

# OS detection
nmap -O 192.168.1.1

# Aggressive scan (version, scripts, OS, traceroute)
nmap -A 192.168.1.1
```

## Scan Types

### TCP Scans

```bash
# TCP SYN scan (default, requires root)
sudo nmap -sS 192.168.1.1

# TCP connect scan (no root needed)
nmap -sT 192.168.1.1

# TCP ACK scan (firewall detection)
sudo nmap -sA 192.168.1.1

# TCP Window scan
sudo nmap -sW 192.168.1.1

# TCP Maimon scan
sudo nmap -sM 192.168.1.1
```

### UDP Scans

```bash
# UDP scan (slow, requires root)
sudo nmap -sU 192.168.1.1

# Combined TCP and UDP
sudo nmap -sS -sU 192.168.1.1
```

### Other Scans

```bash
# Ping scan (host discovery only)
nmap -sn 192.168.1.0/24

# No ping (skip host discovery)
nmap -Pn 192.168.1.1

# List scan (DNS resolution only)
nmap -sL 192.168.1.0/24

# Protocol scan
sudo nmap -sO 192.168.1.1
```

## Port Specification

```bash
# Single port
nmap -p 80 192.168.1.1

# Port range
nmap -p 1-1000 192.168.1.1

# Specific ports
nmap -p 22,80,443,8080 192.168.1.1

# All ports
nmap -p- 192.168.1.1

# Top ports
nmap --top-ports 100 192.168.1.1

# UDP ports
nmap -sU -p 53,67,68,161 192.168.1.1

# Port by name
nmap -p http,https,ssh 192.168.1.1
```

## Target Specification

```bash
# Single host
nmap 192.168.1.1

# Multiple hosts
nmap 192.168.1.1 192.168.1.2 192.168.1.3

# IP range
nmap 192.168.1.1-50

# CIDR notation
nmap 192.168.1.0/24

# Hostname
nmap example.com

# From file
nmap -iL targets.txt

# Exclude hosts
nmap 192.168.1.0/24 --exclude 192.168.1.1

# Exclude from file
nmap 192.168.1.0/24 --excludefile exclude.txt
```

## Service Detection

```bash
# Version detection
nmap -sV 192.168.1.1

# Version intensity (0-9, default 7)
nmap -sV --version-intensity 9 192.168.1.1

# Light version detection
nmap -sV --version-light 192.168.1.1

# All version probes
nmap -sV --version-all 192.168.1.1
```

## OS Detection

```bash
# OS detection
sudo nmap -O 192.168.1.1

# Aggressive OS detection
sudo nmap -O --osscan-guess 192.168.1.1

# Limit OS detection
sudo nmap -O --max-os-tries 1 192.168.1.1
```

## NSE Scripts

### Script Categories

```bash
# Default scripts
nmap -sC 192.168.1.1

# Specific category
nmap --script auth 192.168.1.1
nmap --script vuln 192.168.1.1
nmap --script discovery 192.168.1.1
nmap --script safe 192.168.1.1
nmap --script intrusive 192.168.1.1

# Multiple categories
nmap --script "vuln,auth" 192.168.1.1

# Exclude category
nmap --script "default and not intrusive" 192.168.1.1
```

### Common Scripts

```bash
# HTTP enumeration
nmap --script http-enum 192.168.1.1

# SSL/TLS analysis
nmap --script ssl-enum-ciphers -p 443 192.168.1.1

# SMB vulnerabilities
nmap --script smb-vuln* 192.168.1.1

# DNS enumeration
nmap --script dns-brute example.com

# FTP anonymous
nmap --script ftp-anon 192.168.1.1

# MySQL info
nmap --script mysql-info 192.168.1.1

# SSH auth methods
nmap --script ssh-auth-methods 192.168.1.1
```

### Script Arguments

```bash
# With arguments
nmap --script http-brute --script-args http-brute.path=/admin 192.168.1.1

# Multiple arguments
nmap --script smb-enum-shares --script-args smbuser=admin,smbpass=password 192.168.1.1
```

## Timing and Performance

### Timing Templates

```bash
# T0 (paranoid) - IDS evasion
nmap -T0 192.168.1.1

# T1 (sneaky) - IDS evasion
nmap -T1 192.168.1.1

# T2 (polite) - less bandwidth
nmap -T2 192.168.1.1

# T3 (normal) - default
nmap -T3 192.168.1.1

# T4 (aggressive) - faster
nmap -T4 192.168.1.1

# T5 (insane) - fastest
nmap -T5 192.168.1.1
```

### Fine-tuning

```bash
# Parallel hosts
nmap --min-hostgroup 64 --max-hostgroup 256 192.168.1.0/24

# Parallel probes
nmap --min-parallelism 10 --max-parallelism 100 192.168.1.1

# Timing
nmap --min-rtt-timeout 100ms --max-rtt-timeout 500ms 192.168.1.1

# Retry limit
nmap --max-retries 2 192.168.1.1

# Host timeout
nmap --host-timeout 30m 192.168.1.0/24
```

## Output Formats

```bash
# Normal output
nmap -oN scan.txt 192.168.1.1

# XML output
nmap -oX scan.xml 192.168.1.1

# Grepable output
nmap -oG scan.gnmap 192.168.1.1

# All formats
nmap -oA scan 192.168.1.1

# Append
nmap --append-output -oN scan.txt 192.168.1.1

# Verbose
nmap -v 192.168.1.1

# Very verbose
nmap -vv 192.168.1.1

# Debug
nmap -d 192.168.1.1
```

## Firewall/IDS Evasion

```bash
# Fragment packets
nmap -f 192.168.1.1

# Specify MTU
nmap --mtu 24 192.168.1.1

# Decoy scan
nmap -D RND:10 192.168.1.1
nmap -D 192.168.1.2,192.168.1.3,ME 192.168.1.1

# Spoof source IP
nmap -S 192.168.1.100 192.168.1.1

# Spoof source port
nmap --source-port 53 192.168.1.1

# Random data
nmap --data-length 25 192.168.1.1

# Idle scan
nmap -sI zombie.example.com 192.168.1.1
```

## Common Patterns

### Quick Host Discovery

```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# ARP scan (local network)
sudo nmap -sn -PR 192.168.1.0/24

# Fast port check
nmap -F 192.168.1.1
```

### Full Port Scan

```bash
# All TCP ports with service detection
nmap -p- -sV 192.168.1.1

# Fast full scan
nmap -p- -T4 --min-rate 1000 192.168.1.1
```

### Vulnerability Assessment

```bash
# Vuln scripts
nmap --script vuln 192.168.1.1

# Safe vuln scripts
nmap --script "vuln and safe" 192.168.1.1

# Specific CVE check
nmap --script smb-vuln-ms17-010 192.168.1.1
```

### Web Server Scan

```bash
nmap -p 80,443,8080,8443 \
  -sV \
  --script http-enum,http-headers,ssl-enum-ciphers \
  192.168.1.1
```

### Comprehensive Scan

```bash
sudo nmap -sS -sV -O -A \
  --script "default,vuln,safe" \
  -p- \
  -T4 \
  -oA full-scan \
  192.168.1.1
```

## Integration

For web vulnerability scanning, use `/nuclei`.
For HTTP probing, use `/httpx`.
For traffic analysis, use `/tcpdump` or `/wireshark`.
