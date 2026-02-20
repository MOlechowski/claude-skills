---
name: net-wireshark
description: "Network protocol analyzer with GUI and CLI (tshark). Deep packet inspection, protocol dissection, and traffic analysis. Use for: (1) protocol analysis, (2) network troubleshooting, (3) pcap analysis, (4) extracting data from captures, (5) statistics generation. Triggers: wireshark, tshark, protocol analyzer, pcap analysis, packet analysis, network forensics, display filter."
---

# Wireshark / tshark

Network protocol analyzer for deep packet inspection and traffic analysis. Use tshark for CLI operations.

## Quick Start (tshark)

```bash
# Capture on interface
sudo tshark -i eth0

# Read pcap file
tshark -r capture.pcap

# Apply display filter
tshark -r capture.pcap -Y 'http'

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port
```

## Capture Operations

### Interface Capture

```bash
# List interfaces
tshark -D

# Capture on interface
sudo tshark -i eth0

# Capture with filter
sudo tshark -i eth0 -f 'port 80'

# Capture N packets
sudo tshark -i eth0 -c 100

# Save to file
sudo tshark -i eth0 -w capture.pcap

# Ring buffer (10 files, 100MB each)
sudo tshark -i eth0 -b filesize:102400 -b files:10 -w capture.pcap
```

### Read Captures

```bash
# Read pcap
tshark -r capture.pcap

# Summary only
tshark -r capture.pcap -q

# Packet count
tshark -r capture.pcap | wc -l
```

## Display Filters

### Basic Filters

```bash
# IP address
tshark -r capture.pcap -Y 'ip.addr == 192.168.1.1'

# Source IP
tshark -r capture.pcap -Y 'ip.src == 192.168.1.1'

# Destination IP
tshark -r capture.pcap -Y 'ip.dst == 192.168.1.1'

# Port
tshark -r capture.pcap -Y 'tcp.port == 80'

# Protocol
tshark -r capture.pcap -Y 'http'
tshark -r capture.pcap -Y 'dns'
tshark -r capture.pcap -Y 'tls'
```

### Combined Filters

```bash
# AND
tshark -r capture.pcap -Y 'ip.src == 192.168.1.1 and tcp.port == 80'

# OR
tshark -r capture.pcap -Y 'http or dns'

# NOT
tshark -r capture.pcap -Y 'not arp'

# Complex
tshark -r capture.pcap -Y '(http.request or http.response) and ip.addr == 192.168.1.1'
```

### Protocol-Specific Filters

```bash
# HTTP requests
tshark -r capture.pcap -Y 'http.request'

# HTTP methods
tshark -r capture.pcap -Y 'http.request.method == "POST"'

# HTTP status codes
tshark -r capture.pcap -Y 'http.response.code == 200'

# DNS queries
tshark -r capture.pcap -Y 'dns.flags.response == 0'

# TLS handshake
tshark -r capture.pcap -Y 'tls.handshake'

# TCP SYN
tshark -r capture.pcap -Y 'tcp.flags.syn == 1 and tcp.flags.ack == 0'

# TCP RST
tshark -r capture.pcap -Y 'tcp.flags.reset == 1'
```

## Field Extraction

### Common Fields

```bash
# IP addresses
tshark -r capture.pcap -T fields -e ip.src -e ip.dst

# TCP ports
tshark -r capture.pcap -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport

# HTTP hosts
tshark -r capture.pcap -Y 'http.request' -T fields -e http.host

# HTTP URIs
tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri

# DNS queries
tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name

# TLS SNI
tshark -r capture.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name
```

### Output Formats

```bash
# Tab-separated (default)
tshark -r capture.pcap -T fields -e ip.src -e ip.dst

# CSV
tshark -r capture.pcap -T fields -E separator=, -e ip.src -e ip.dst

# JSON
tshark -r capture.pcap -T json

# JSON with specific fields
tshark -r capture.pcap -T ek -e ip.src -e ip.dst

# PDML (XML)
tshark -r capture.pcap -T pdml

# Headers for CSV
tshark -r capture.pcap -T fields -E header=y -e ip.src -e ip.dst
```

## Statistics

### Protocol Hierarchy

```bash
tshark -r capture.pcap -q -z io,phs
```

### Conversations

```bash
# IP conversations
tshark -r capture.pcap -q -z conv,ip

# TCP conversations
tshark -r capture.pcap -q -z conv,tcp

# UDP conversations
tshark -r capture.pcap -q -z conv,udp
```

### Endpoints

```bash
# IP endpoints
tshark -r capture.pcap -q -z endpoints,ip

# TCP endpoints
tshark -r capture.pcap -q -z endpoints,tcp
```

### Protocol Statistics

```bash
# HTTP statistics
tshark -r capture.pcap -q -z http,tree

# HTTP requests
tshark -r capture.pcap -q -z http_req,tree

# DNS statistics
tshark -r capture.pcap -q -z dns,tree
```

### I/O Statistics

```bash
# Packets per second
tshark -r capture.pcap -q -z io,stat,1

# Bytes per second
tshark -r capture.pcap -q -z io,stat,1,"COUNT(frame)"

# Filtered statistics
tshark -r capture.pcap -q -z io,stat,1,"COUNT(frame)tcp","COUNT(frame)udp"
```

## Stream Extraction

### TCP Stream

```bash
# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Follow as hex
tshark -r capture.pcap -q -z follow,tcp,hex,0

# Follow specific stream
tshark -r capture.pcap -q -z follow,tcp,ascii,5
```

### HTTP Stream

```bash
# Follow HTTP stream
tshark -r capture.pcap -q -z follow,http,ascii,0
```

## Export Objects

```bash
# Export HTTP objects
tshark -r capture.pcap --export-objects http,./exported/

# Export DICOM objects
tshark -r capture.pcap --export-objects dicom,./exported/

# Export IMF (email)
tshark -r capture.pcap --export-objects imf,./exported/

# Export SMB objects
tshark -r capture.pcap --export-objects smb,./exported/
```

## TLS Decryption

```bash
# With pre-master secret log
tshark -r capture.pcap \
  -o tls.keylog_file:/path/to/keylog.txt \
  -Y 'http'

# With private key (RSA only)
tshark -r capture.pcap \
  -o "ssl.keys_list:192.168.1.1,443,http,/path/to/server.key"
```

## Common Patterns

### Find Suspicious Traffic

```bash
# Large DNS responses (potential exfiltration)
tshark -r capture.pcap -Y 'dns.resp.len > 512'

# HTTP with exe files
tshark -r capture.pcap -Y 'http.content_type contains "application/x-msdownload"'

# SMB traffic
tshark -r capture.pcap -Y 'smb or smb2'

# Unusual ports
tshark -r capture.pcap -Y 'tcp.port > 49151 and not tls'
```

### Extract Credentials

```bash
# HTTP Basic Auth
tshark -r capture.pcap -Y 'http.authorization' -T fields -e http.authorization

# FTP credentials
tshark -r capture.pcap -Y 'ftp.request.command == "USER" or ftp.request.command == "PASS"' -T fields -e ftp.request.arg
```

### Network Performance

```bash
# TCP retransmissions
tshark -r capture.pcap -Y 'tcp.analysis.retransmission'

# High latency (RTT > 100ms)
tshark -r capture.pcap -Y 'tcp.analysis.ack_rtt > 0.1'

# Zero window
tshark -r capture.pcap -Y 'tcp.analysis.zero_window'
```

### Top Talkers

```bash
# By packets
tshark -r capture.pcap -q -z endpoints,ip | sort -k3 -n -r | head

# By bytes
tshark -r capture.pcap -q -z endpoints,ip | sort -k5 -n -r | head
```

## Integration

For packet capture, use `/tcpdump`.
For HTTP/HTTPS interception, use `/mitmproxy`.
For container network debugging, capture with tcpdump and analyze in Wireshark.
