---
name: hcloud
description: "Hetzner Cloud CLI for managing cloud infrastructure. Use for: (1) server lifecycle (create, resize, rebuild, snapshots), (2) networking (VPCs, firewalls, floating IPs, load balancers), (3) storage (volumes), (4) multi-project context management. Triggers: hcloud, hetzner, hetzner cloud, hcloud server, hcloud network, hcloud firewall."
---

# hcloud

Hetzner Cloud CLI for managing servers, networking, storage, and infrastructure.

## Install

```bash
# Homebrew
brew install hcloud

# Go
go install github.com/hetznercloud/cli/cmd/hcloud@latest

# Binary (Linux amd64)
curl -sL https://github.com/hetznercloud/cli/releases/latest/download/hcloud-linux-amd64.tar.gz | tar xz
sudo mv hcloud /usr/local/bin/
```

## Authentication

```bash
# Create a context (interactive, prompts for token)
hcloud context create my-project

# List contexts
hcloud context list

# Switch context
hcloud context use my-project

# Show active context
hcloud context active

# Delete context
hcloud context delete old-project

# Or use env var (overrides context)
export HCLOUD_TOKEN="your-api-token"

# Or per-command flag
hcloud server list --token "your-api-token"
```

Config stored at `~/.config/hcloud/cli.toml`.

## Output Formats

```bash
# JSON output
hcloud server list -o json

# YAML output
hcloud server list -o yaml

# Custom columns
hcloud server list -o columns=id,name,status,ipv4

# Quiet mode (IDs only)
hcloud server list --quiet

# Label selectors
hcloud server list -l env=prod
hcloud server list -l role
hcloud server list -l 'env!=staging'
```

## Servers

### Create

```bash
# Basic server
hcloud server create --name web-1 --type cx22 --image ubuntu-24.04 --location fsn1

# With SSH key and labels
hcloud server create --name web-1 --type cx22 --image ubuntu-24.04 \
  --location fsn1 --ssh-key my-key --label env=prod --label role=web

# With cloud-init, network, and firewall
hcloud server create --name web-1 --type cx22 --image ubuntu-24.04 \
  --location fsn1 --ssh-key my-key \
  --user-data-from-file cloud-init.yaml \
  --network my-vpc --firewall web-fw

# With placement group, volume, no public IPv4
hcloud server create --name db-1 --type cx32 --image ubuntu-24.04 \
  --location fsn1 --ssh-key my-key \
  --placement-group my-spread --volume data-vol --without-ipv4
```

### Server Create Flags

| Flag | Description |
|------|-------------|
| `--name` | Server name (required) |
| `--type` | Server type: cx22, cx32, cx42, cpx11, cax11, etc. |
| `--image` | OS image: ubuntu-24.04, debian-12, rocky-9, etc. |
| `--location` | DC location: fsn1, nbg1, hel1, ash, hil, sin |
| `--ssh-key` | SSH key name or ID (repeatable) |
| `--user-data-from-file` | Cloud-init YAML file |
| `--label` | Key=value label (repeatable) |
| `--network` | Attach to network/VPC |
| `--firewall` | Apply firewall (repeatable) |
| `--placement-group` | Placement group name or ID |
| `--volume` | Attach volume |
| `--without-ipv4` | No public IPv4 address |

### List, Describe, Delete

```bash
# List all servers
hcloud server list

# Describe server details
hcloud server describe web-1

# Delete server
hcloud server delete web-1
```

### Power Operations

```bash
# Graceful shutdown (ACPI signal)
hcloud server shutdown web-1

# Force power off
hcloud server poweroff web-1

# Power on
hcloud server poweron web-1

# Reboot (graceful)
hcloud server reboot web-1

# Hard reset
hcloud server reset web-1
```

### Resize

```bash
# Resize server type (with disk upgrade)
hcloud server change-type web-1 --server-type cx32 --upgrade-disk

# Resize server type (without disk upgrade, allows downgrade later)
hcloud server change-type web-1 --server-type cx32
```

Server must be powered off before resizing.

### Rebuild

```bash
# Rebuild with new image (wipes data)
hcloud server rebuild web-1 --image ubuntu-24.04
```

### Snapshots and Backups

```bash
# Create snapshot
hcloud server create-image web-1 --type snapshot --description "pre-upgrade"

# Enable automatic backups
hcloud server enable-backup web-1

# Disable automatic backups
hcloud server disable-backup web-1
```

### SSH

```bash
# SSH into server
hcloud server ssh web-1

# SSH as specific user
hcloud server ssh web-1 --user deploy
```

### Labels and Protection

```bash
# Add label
hcloud server add-label web-1 env=prod

# Remove label
hcloud server remove-label web-1 env

# Enable delete protection
hcloud server enable-protection web-1 delete

# Disable delete protection
hcloud server disable-protection web-1 delete
```

## Networking

### Networks (VPC)

```bash
# Create network
hcloud network create --name my-vpc --ip-range 10.0.0.0/8

# Add subnet
hcloud network add-subnet my-vpc \
  --type cloud --network-zone eu-central --ip-range 10.0.1.0/24

# Add route
hcloud network add-route my-vpc --destination 172.16.0.0/12 --gateway 10.0.1.1

# Attach server to network
hcloud server attach-to-network web-1 --network my-vpc

# Detach server from network
hcloud server detach-from-network web-1 --network my-vpc

# List networks
hcloud network list

# Delete network
hcloud network delete my-vpc
```

### Firewalls

```bash
# Create firewall
hcloud firewall create --name web-fw

# Add inbound rules
hcloud firewall add-rule web-fw --direction in --protocol tcp \
  --port 22 --source-ips 10.0.0.0/8 --description "SSH internal"

hcloud firewall add-rule web-fw --direction in --protocol tcp \
  --port 80 --source-ips 0.0.0.0/0 --source-ips ::/0 --description "HTTP"

hcloud firewall add-rule web-fw --direction in --protocol tcp \
  --port 443 --source-ips 0.0.0.0/0 --source-ips ::/0 --description "HTTPS"

# Add outbound rule
hcloud firewall add-rule web-fw --direction out --protocol tcp \
  --port any --destination-ips 0.0.0.0/0 --destination-ips ::/0 \
  --description "All outbound TCP"

# Apply to specific server
hcloud firewall apply-to-resource web-fw --type server --server web-1

# Apply to servers by label
hcloud firewall apply-to-resource web-fw --type label_selector --label-selector role=web

# Remove from resource
hcloud firewall remove-from-resource web-fw --type server --server web-1

# Delete rule (by index from describe output)
hcloud firewall delete-rule web-fw --direction in --protocol tcp --port 22 \
  --source-ips 10.0.0.0/8

# List firewalls
hcloud firewall list

# Delete firewall
hcloud firewall delete web-fw
```

### Floating IPs

```bash
# Create floating IP
hcloud floating-ip create --type ipv4 --home-location fsn1 --description "prod-vip"

# Assign to server
hcloud floating-ip assign 12345 web-1

# Unassign
hcloud floating-ip unassign 12345

# List
hcloud floating-ip list

# Delete
hcloud floating-ip delete 12345
```

### Primary IPs

```bash
# Create primary IP
hcloud primary-ip create --name web-ip --type ipv4 --datacenter fsn1-dc14

# Assign to server
hcloud primary-ip assign 12345 --server web-1

# Unassign
hcloud primary-ip unassign 12345

# List
hcloud primary-ip list
```

## Load Balancers

```bash
# Create load balancer
hcloud load-balancer create --name lb-web --type lb11 --location fsn1

# Add server target
hcloud load-balancer add-target lb-web --server web-1

# Add label-based targets
hcloud load-balancer add-target lb-web --label-selector role=web

# Add HTTP service
hcloud load-balancer add-service lb-web \
  --protocol http --listen-port 80 --destination-port 8080

# Add HTTPS service with certificate
hcloud load-balancer add-service lb-web \
  --protocol https --listen-port 443 --destination-port 8080 \
  --http-certificates my-cert

# Update health check
hcloud load-balancer update-health-check lb-web \
  --protocol http --port 8080 --interval 10s --timeout 5s \
  --retries 3 --http-path /healthz

# Attach to network
hcloud load-balancer attach-to-network lb-web --network my-vpc

# Remove target
hcloud load-balancer remove-target lb-web --server web-1

# Remove service
hcloud load-balancer remove-service lb-web --listen-port 80

# List
hcloud load-balancer list

# Delete
hcloud load-balancer delete lb-web
```

## Volumes

```bash
# Create volume (attached to server, auto-mounted)
hcloud volume create --name data-vol --size 50 \
  --server web-1 --format ext4 --automount

# Create standalone volume
hcloud volume create --name data-vol --size 100 --location fsn1

# Attach to server
hcloud volume attach data-vol --server web-1 --automount

# Detach from server
hcloud volume detach data-vol

# Resize volume
hcloud volume resize data-vol --size 200

# List volumes
hcloud volume list

# Delete volume
hcloud volume delete data-vol
```

## Images and SSH Keys

```bash
# List images
hcloud image list

# List snapshots
hcloud image list --type snapshot

# Describe image
hcloud image describe ubuntu-24.04

# Delete snapshot
hcloud image delete 12345

# Add SSH key
hcloud ssh-key create --name my-key --public-key-from-file ~/.ssh/id_ed25519.pub

# List SSH keys
hcloud ssh-key list

# Delete SSH key
hcloud ssh-key delete my-key
```

## Common Workflows

### Deploy Server with Network and Firewall

```bash
# Create network
hcloud network create --name app-vpc --ip-range 10.0.0.0/8
hcloud network add-subnet app-vpc \
  --type cloud --network-zone eu-central --ip-range 10.0.1.0/24

# Create firewall
hcloud firewall create --name app-fw
hcloud firewall add-rule app-fw --direction in --protocol tcp \
  --port 22 --source-ips 10.0.0.0/8 --description "SSH internal"
hcloud firewall add-rule app-fw --direction in --protocol tcp \
  --port 443 --source-ips 0.0.0.0/0 --source-ips ::/0 --description "HTTPS"

# Create server
hcloud server create --name app-1 --type cx22 --image ubuntu-24.04 \
  --location fsn1 --ssh-key my-key \
  --network app-vpc --firewall app-fw --label env=prod --label role=app
```

### Scale / Resize Server

```bash
# Shutdown before resize
hcloud server shutdown web-1

# Upgrade type (keep disk resizable)
hcloud server change-type web-1 --server-type cx32

# Power back on
hcloud server poweron web-1
```

### Snapshot and Rebuild

```bash
# Snapshot current state
hcloud server create-image web-1 --type snapshot --description "before-rebuild"

# Rebuild from fresh image
hcloud server rebuild web-1 --image ubuntu-24.04

# Or rebuild from snapshot
hcloud server rebuild web-1 --image 12345
```

### Private Network Setup

```bash
# Create network and subnet
hcloud network create --name internal --ip-range 10.0.0.0/8
hcloud network add-subnet internal \
  --type cloud --network-zone eu-central --ip-range 10.0.0.0/24

# Attach servers
hcloud server attach-to-network web-1 --network internal
hcloud server attach-to-network db-1 --network internal

# Verify connectivity
hcloud server ssh web-1 -- ping -c 3 10.0.0.2
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `unauthorized` | Invalid or expired API token | Check token, recreate context |
| `rate_limit_exceeded` | Too many API requests | Wait and retry |
| `conflict` | Resource in use or locked | Check dependencies, wait for actions |
| `uniqueness_error` | Duplicate resource name | Use a different name |
| `resource_unavailable` | Location or type unavailable | Try a different location or type |
| `server_limit_exceeded` | Project quota reached | Request increase in Cloud Console |
| `placement_error` | Placement group constraint violated | Check group constraints |
| `action_failed` | Server action failed | Run `describe` to check status, retry |

## Resources

See [references/quick-reference.md](references/quick-reference.md) for condensed command reference.
