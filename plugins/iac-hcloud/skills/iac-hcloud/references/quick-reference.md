# hcloud CLI Quick Reference

## Global Flags

| Flag | Description |
|------|-------------|
| `--token` | API token (overrides active context) |
| `-o`, `--output` | Output format: `table` (default), `json`, `yaml`, `columns` |
| `--poll-interval` | Interval for polling action status (default: `500ms`) |
| `--quiet` | Suppress non-error output |
| `--debug` | Enable debug-level logging to stderr |

## Server Create Flags

| Flag | Description |
|------|-------------|
| `--name` | Server name (required) |
| `--type` | Server type, e.g. `cx22`, `cpx31`, `cax11` (required) |
| `--image` | OS image name or ID (required) |
| `--location` | Location: `fsn1`, `nbg1`, `hel1`, `ash`, `hil`, `sin` |
| `--datacenter` | Datacenter (more specific than location) |
| `--ssh-key` | SSH key name or ID (repeatable) |
| `--user-data-from-file` | Path to cloud-init user data file |
| `--label` | Label in `key=value` format (repeatable) |
| `--network` | Network name or ID to attach (repeatable) |
| `--firewall` | Firewall name or ID to apply (repeatable) |
| `--placement-group` | Placement group name or ID |
| `--volume` | Volume name or ID to attach (repeatable) |
| `--without-ipv4` | Do not assign a public IPv4 address |
| `--without-ipv6` | Do not assign a public IPv6 address |
| `--start-after-create` | Start server after creation (default: `true`) |
| `--automount` | Auto-mount attached volumes |
| `--public-net-ipv4` | Specific Primary IP for public IPv4 |
| `--public-net-ipv6` | Specific Primary IP for public IPv6 |

## Server Commands

| Command | Description |
|---------|-------------|
| `server list` | List all servers |
| `server describe <server>` | Show server details |
| `server create` | Create a new server |
| `server delete <server>` | Delete a server |
| `server poweron <server>` | Power on (hard start) |
| `server poweroff <server>` | Power off (hard stop, unsafe) |
| `server shutdown <server>` | Graceful ACPI shutdown |
| `server reboot <server>` | Graceful ACPI reboot |
| `server reset <server>` | Hard reset (power cycle) |
| `server ssh <server>` | SSH into server |
| `server change-type <server> --server-type <type>` | Resize server (must be off for upgrade) |
| `server rebuild <server> --image <image>` | Reinstall OS (destroys data) |
| `server create-image <server>` | Create snapshot from server |
| `server enable-backup <server>` | Enable automatic backups |
| `server disable-backup <server>` | Disable automatic backups |
| `server add-label <server> key=value` | Add label to server |
| `server remove-label <server> key` | Remove label from server |
| `server enable-protection <server> delete` | Enable delete protection |
| `server disable-protection <server> delete` | Disable delete protection |
| `server attach-to-network <server> --network <net>` | Attach to private network |
| `server detach-from-network <server> --network <net>` | Detach from private network |
| `server attach-iso <server> --iso <iso>` | Mount ISO image |
| `server detach-iso <server>` | Unmount ISO image |
| `server request-console <server>` | Get VNC console URL |
| `server reset-password <server>` | Reset root password |
| `server set-rdns <server> --ip <ip> --hostname <host>` | Set reverse DNS entry |
| `server metrics <server> --type <type>` | Get server metrics (cpu, disk, network) |

## Network Commands

| Command | Description |
|---------|-------------|
| `network create --name <n> --ip-range <cidr>` | Create network |
| `network list` | List all networks |
| `network describe <network>` | Show network details |
| `network delete <network>` | Delete network |
| `network update <network> --name <n>` | Rename network |
| `network change-ip-range <network> --ip-range <cidr>` | Expand IP range |
| `network add-subnet <network> --type <t> --network-zone <z> --ip-range <cidr>` | Add subnet |
| `network remove-subnet <network> --ip-range <cidr>` | Remove subnet |
| `network add-route <network> --destination <cidr> --gateway <ip>` | Add route |
| `network remove-route <network> --destination <cidr> --gateway <ip>` | Remove route |
| `network add-label <network> key=value` | Add label |
| `network remove-label <network> key` | Remove label |
| `network enable-protection <network> delete` | Enable delete protection |
| `network disable-protection <network> delete` | Disable delete protection |

## Firewall Commands

| Command | Description |
|---------|-------------|
| `firewall create --name <n>` | Create firewall |
| `firewall list` | List all firewalls |
| `firewall describe <firewall>` | Show firewall details |
| `firewall delete <firewall>` | Delete firewall |
| `firewall update <firewall> --name <n>` | Rename firewall |
| `firewall add-rule <firewall> --direction <in/out> --protocol <p> --port <port>` | Add rule |
| `firewall delete-rule <firewall> --direction <in/out> --protocol <p> --port <port>` | Remove rule |
| `firewall replace-rules <firewall> --rules-file <file>` | Replace all rules from JSON file |
| `firewall apply-to-resource <firewall> --type server --server <s>` | Apply to server |
| `firewall remove-from-resource <firewall> --type server --server <s>` | Remove from server |
| `firewall apply-to-resource <firewall> --type label_selector --label-selector <l>` | Apply to label selector |
| `firewall add-label <firewall> key=value` | Add label |
| `firewall remove-label <firewall> key` | Remove label |

## Load Balancer Commands

| Command | Description |
|---------|-------------|
| `load-balancer create --name <n> --type <t> --location <l>` | Create load balancer |
| `load-balancer list` | List all load balancers |
| `load-balancer describe <lb>` | Show details |
| `load-balancer delete <lb>` | Delete load balancer |
| `load-balancer update <lb> --name <n>` | Rename load balancer |
| `load-balancer add-target <lb> --server <s>` | Add server target |
| `load-balancer remove-target <lb> --server <s>` | Remove server target |
| `load-balancer add-target <lb> --label-selector <l>` | Add label selector target |
| `load-balancer add-target <lb> --ip <ip>` | Add IP target |
| `load-balancer add-service <lb> --protocol <p> --listen-port <lp> --destination-port <dp>` | Add service |
| `load-balancer update-service <lb> --protocol <p> --listen-port <lp>` | Update service |
| `load-balancer delete-service <lb> --listen-port <lp>` | Delete service |
| `load-balancer attach-to-network <lb> --network <n>` | Attach to network |
| `load-balancer detach-from-network <lb> --network <n>` | Detach from network |
| `load-balancer change-type <lb> --load-balancer-type <t>` | Change type |
| `load-balancer enable-protection <lb> delete` | Enable delete protection |
| `load-balancer disable-protection <lb> delete` | Disable delete protection |
| `load-balancer add-label <lb> key=value` | Add label |
| `load-balancer remove-label <lb> key` | Remove label |
| `load-balancer change-algorithm <lb> --algorithm-type <t>` | Set algorithm (round_robin, least_connections) |
| `load-balancer enable-public-interface <lb>` | Enable public interface |
| `load-balancer disable-public-interface <lb>` | Disable public interface |
| `load-balancer set-rdns <lb> --ip <ip> --hostname <h>` | Set reverse DNS |
| `load-balancer metrics <lb> --type <t>` | Get metrics |

## Volume Commands

| Command | Description |
|---------|-------------|
| `volume create --name <n> --size <gb>` | Create volume |
| `volume list` | List all volumes |
| `volume describe <volume>` | Show volume details |
| `volume delete <volume>` | Delete volume |
| `volume update <volume> --name <n>` | Rename volume |
| `volume resize <volume> --size <gb>` | Resize volume (grow only) |
| `volume attach <volume> --server <s>` | Attach to server |
| `volume detach <volume>` | Detach from server |
| `volume add-label <volume> key=value` | Add label |
| `volume remove-label <volume> key` | Remove label |
| `volume enable-protection <volume> delete` | Enable delete protection |
| `volume disable-protection <volume> delete` | Disable delete protection |

## Floating IP Commands

| Command | Description |
|---------|-------------|
| `floating-ip create --type <ipv4/ipv6> --home-location <l>` | Create floating IP |
| `floating-ip list` | List all floating IPs |
| `floating-ip describe <ip>` | Show details |
| `floating-ip delete <ip>` | Delete floating IP |
| `floating-ip update <ip> --name <n>` | Rename |
| `floating-ip assign <ip> --server <s>` | Assign to server |
| `floating-ip unassign <ip>` | Unassign from server |
| `floating-ip add-label <ip> key=value` | Add label |
| `floating-ip remove-label <ip> key` | Remove label |
| `floating-ip enable-protection <ip> delete` | Enable delete protection |
| `floating-ip disable-protection <ip> delete` | Disable delete protection |
| `floating-ip set-rdns <ip> --ip <addr> --hostname <h>` | Set reverse DNS |

## Primary IP Commands

| Command | Description |
|---------|-------------|
| `primary-ip create --name <n> --type <ipv4/ipv6> --datacenter <dc>` | Create primary IP |
| `primary-ip list` | List all primary IPs |
| `primary-ip describe <ip>` | Show details |
| `primary-ip delete <ip>` | Delete primary IP |
| `primary-ip update <ip> --name <n>` | Rename |
| `primary-ip assign <ip> --server <s>` | Assign to server |
| `primary-ip unassign <ip>` | Unassign from server |
| `primary-ip add-label <ip> key=value` | Add label |
| `primary-ip remove-label <ip> key` | Remove label |
| `primary-ip enable-protection <ip> delete` | Enable delete protection |
| `primary-ip disable-protection <ip> delete` | Disable delete protection |
| `primary-ip set-rdns <ip> --ip <addr> --hostname <h>` | Set reverse DNS |
| `primary-ip change-dns-ptr <ip> --ip <addr> --hostname <h>` | Change DNS pointer |

## Image Commands

| Command | Description |
|---------|-------------|
| `image list` | List all images (includes snapshots, backups) |
| `image list --type system` | List only OS images |
| `image list --type snapshot` | List only snapshots |
| `image list --type backup` | List only backups |
| `image describe <image>` | Show image details |
| `image delete <image>` | Delete snapshot or backup |
| `image update <image> --description <d>` | Update description |
| `image add-label <image> key=value` | Add label |
| `image remove-label <image> key` | Remove label |
| `image enable-protection <image> delete` | Enable delete protection |
| `image disable-protection <image> delete` | Disable delete protection |

## SSH Key Commands

| Command | Description |
|---------|-------------|
| `ssh-key create --name <n> --public-key-from-file <path>` | Create SSH key |
| `ssh-key list` | List all SSH keys |
| `ssh-key describe <key>` | Show key details |
| `ssh-key delete <key>` | Delete SSH key |
| `ssh-key update <key> --name <n>` | Rename SSH key |
| `ssh-key add-label <key> key=value` | Add label |
| `ssh-key remove-label <key> key` | Remove label |

## Placement Groups

| Command | Description |
|---------|-------------|
| `placement-group create --name <n> --type spread` | Create placement group |
| `placement-group list` | List all placement groups |
| `placement-group describe <pg>` | Show details |
| `placement-group delete <pg>` | Delete placement group |
| `placement-group update <pg> --name <n>` | Rename |
| `placement-group add-label <pg> key=value` | Add label |
| `placement-group remove-label <pg> key` | Remove label |

## Certificates

| Command | Description |
|---------|-------------|
| `certificate create --name <n> --cert-file <f> --key-file <f>` | Upload certificate |
| `certificate create --name <n> --type managed --domain <d>` | Create managed certificate |
| `certificate list` | List all certificates |
| `certificate describe <cert>` | Show details |
| `certificate delete <cert>` | Delete certificate |
| `certificate update <cert> --name <n>` | Rename certificate |
| `certificate add-label <cert> key=value` | Add label |
| `certificate remove-label <cert> key` | Remove label |

## ISOs, Datacenters, Locations, Server Types

| Command | Description |
|---------|-------------|
| `iso list` | List available ISO images |
| `iso describe <iso>` | Show ISO details |
| `datacenter list` | List all datacenters |
| `datacenter describe <dc>` | Show datacenter details |
| `location list` | List all locations |
| `location describe <location>` | Show location details |
| `server-type list` | List all server types |
| `server-type describe <type>` | Show server type details (pricing, specs) |

## Context Management

| Command | Description |
|---------|-------------|
| `context create <name>` | Create context (prompts for token) |
| `context use <name>` | Switch active context |
| `context active` | Show active context |
| `context list` | List all contexts |
| `context delete <name>` | Delete context |

## Label Selector Syntax

Used with `--selector` / `-l` on `list` commands to filter resources.

| Selector | Meaning |
|----------|---------|
| `key=value` | Exact match |
| `key!=value` | Negation |
| `key` | Key exists (any value) |
| `!key` | Key does not exist |
| `key in (v1,v2)` | Value in set |
| `key notin (v1,v2)` | Value not in set |
| `key=v1,other=v2` | Multiple selectors (AND logic) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HCLOUD_TOKEN` | API token (overrides active context) |
| `HCLOUD_CONFIG` | Config file path (default: `~/.config/hcloud/cli.toml`) |
| `HCLOUD_CONTEXT` | Active context name (overrides config) |

## Common List Flags

| Flag | Description |
|------|-------------|
| `-l`, `--selector` | Filter by label selector |
| `-o`, `--output` | Output format: `table`, `json`, `yaml`, `columns` |
| `--sort` | Sort by field (e.g. `name`, `created`) |
