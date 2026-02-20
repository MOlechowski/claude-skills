---
name: net-tcpdump
description: "Network packet capture and analysis tool. Capture, filter, and inspect network traffic. Use for: (1) packet capture, (2) network debugging, (3) traffic analysis, (4) protocol inspection, (5) pcap file creation. Triggers: tcpdump, packet capture, network traffic, pcap, sniff packets, network debug."
---

# tcpdump

Command-line packet analyzer for capturing and analyzing network traffic.

## Quick Start

```bash
# Capture on interface
sudo tcpdump -i eth0

# Capture specific host
sudo tcpdump host 192.168.1.1

# Capture specific port
sudo tcpdump port 80

# Save to file
sudo tcpdump -i eth0 -w capture.pcap

# Read from file
tcpdump -r capture.pcap
```

## Interface Selection

```bash
# List interfaces
tcpdump -D

# Capture on specific interface
sudo tcpdump -i eth0
sudo tcpdump -i en0        # macOS
sudo tcpdump -i any        # All interfaces

# Capture on loopback
sudo tcpdump -i lo
```

## Capture Filters (BPF)

### Host Filters

```bash
# Specific host
sudo tcpdump host 192.168.1.1

# Source host
sudo tcpdump src host 192.168.1.1

# Destination host
sudo tcpdump dst host 192.168.1.1

# Network range
sudo tcpdump net 192.168.1.0/24

# Exclude host
sudo tcpdump not host 192.168.1.1
```

### Port Filters

```bash
# Specific port
sudo tcpdump port 80

# Source port
sudo tcpdump src port 443

# Destination port
sudo tcpdump dst port 22

# Port range
sudo tcpdump portrange 8000-9000

# Multiple ports
sudo tcpdump port 80 or port 443
```

### Protocol Filters

```bash
# TCP only
sudo tcpdump tcp

# UDP only
sudo tcpdump udp

# ICMP only
sudo tcpdump icmp

# ARP only
sudo tcpdump arp

# HTTP (port 80 TCP)
sudo tcpdump 'tcp port 80'

# DNS
sudo tcpdump 'udp port 53'

# HTTPS
sudo tcpdump 'tcp port 443'
```

### Combined Filters

```bash
# Host and port
sudo tcpdump 'host 192.168.1.1 and port 80'

# Multiple conditions
sudo tcpdump 'src host 192.168.1.1 and (dst port 80 or dst port 443)'

# Exclude traffic
sudo tcpdump 'not (port 22 or port 53)'

# Complex filter
sudo tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src net 192.168.0.0/16'
```

## Output Options

### Display Formats

```bash
# Verbose output
sudo tcpdump -v host 192.168.1.1

# More verbose
sudo tcpdump -vv host 192.168.1.1

# Maximum verbosity
sudo tcpdump -vvv host 192.168.1.1

# Show hex and ASCII
sudo tcpdump -X port 80

# Show hex only
sudo tcpdump -x port 80

# Show ASCII
sudo tcpdump -A port 80

# Don't resolve hostnames
sudo tcpdump -n port 80

# Don't resolve ports
sudo tcpdump -nn port 80

# Show absolute timestamps
sudo tcpdump -tttt port 80
```

### Packet Limiting

```bash
# Capture N packets
sudo tcpdump -c 100 port 80

# Limit packet size (snaplen)
sudo tcpdump -s 96 port 80

# Full packet capture
sudo tcpdump -s 0 port 80
```

## File Operations

### Writing Captures

```bash
# Write to pcap
sudo tcpdump -i eth0 -w capture.pcap

# Rotate files (100MB each, keep 5)
sudo tcpdump -i eth0 -w capture.pcap -C 100 -W 5

# Rotate by time (every 60 seconds)
sudo tcpdump -i eth0 -w 'capture_%Y%m%d_%H%M%S.pcap' -G 60

# Append timestamp to filename
sudo tcpdump -i eth0 -w "capture-$(date +%Y%m%d-%H%M%S).pcap"
```

### Reading Captures

```bash
# Read pcap file
tcpdump -r capture.pcap

# Read with filter
tcpdump -r capture.pcap 'port 80'

# Read with verbose output
tcpdump -r capture.pcap -vvv

# Count packets
tcpdump -r capture.pcap | wc -l
```

## Advanced Filters

### TCP Flags

```bash
# SYN packets
sudo tcpdump 'tcp[tcpflags] & tcp-syn != 0'

# SYN-ACK packets
sudo tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# FIN packets
sudo tcpdump 'tcp[tcpflags] & tcp-fin != 0'

# RST packets
sudo tcpdump 'tcp[tcpflags] & tcp-rst != 0'

# PUSH packets
sudo tcpdump 'tcp[tcpflags] & tcp-push != 0'
```

### Payload Matching

```bash
# HTTP GET requests
sudo tcpdump -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Match string in payload
sudo tcpdump -A 'tcp port 80' | grep -i 'password'

# HTTP Host header
sudo tcpdump -s 0 -A 'tcp port 80' | grep 'Host:'
```

### VLAN Traffic

```bash
# Capture VLAN traffic
sudo tcpdump -e vlan

# Specific VLAN
sudo tcpdump 'vlan 100'
```

## Common Patterns

### HTTP Traffic Analysis

```bash
# Capture HTTP requests/responses
sudo tcpdump -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | \
  grep -E '^(GET|POST|HTTP|Host:|Content-)'

# Save HTTP traffic
sudo tcpdump -w http.pcap 'tcp port 80 or tcp port 8080'
```

### DNS Analysis

```bash
# Capture DNS queries
sudo tcpdump -n 'udp port 53'

# Verbose DNS
sudo tcpdump -vvv -n 'udp port 53'
```

### Connection Tracking

```bash
# New TCP connections (SYN)
sudo tcpdump 'tcp[tcpflags] == tcp-syn'

# Connection problems (RST)
sudo tcpdump 'tcp[tcpflags] & tcp-rst != 0'
```

### Container Network Debug

```bash
# Capture on Docker bridge
sudo tcpdump -i docker0

# Capture container traffic (by IP)
sudo tcpdump -i docker0 host 172.17.0.2

# Capture on veth interface
sudo tcpdump -i veth123abc
```

### Performance Capture

```bash
# High-speed capture (reduce output)
sudo tcpdump -n -q -i eth0

# Buffer size increase
sudo tcpdump -B 4096 -i eth0 -w capture.pcap

# Kernel buffer (Linux)
sudo tcpdump --buffer-size=4096 -i eth0 -w capture.pcap
```

## Timestamps

```bash
# Unix timestamps
sudo tcpdump -tt

# Human readable with date
sudo tcpdump -tttt

# Microsecond precision
sudo tcpdump -ttttt

# Time since first packet
sudo tcpdump -ttttt -r capture.pcap
```

## Security Considerations

```bash
# Capture as non-root (with capabilities)
sudo setcap cap_net_raw,cap_net_admin+ep /usr/sbin/net-tcpdump

# Don't resolve names (faster, less leakage)
sudo tcpdump -nn

# Limit capture size
sudo tcpdump -s 96 -c 1000 -w limited.pcap
```

## Integration

For GUI analysis of captures, use `/wireshark`.
For HTTP/HTTPS interception, use `/mitmproxy`.
For application-layer protocol analysis, open pcap files in Wireshark.
