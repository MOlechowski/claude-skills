---
name: aws-localstack
description: "LocalStack CLI for managing local AWS emulation containers. Use for: starting/stopping LocalStack, status checks, log viewing, container updates, configuration profiles. Triggers: localstack, localstack start, localstack stop, localstack status, local aws emulator, start localstack."
---

# LocalStack CLI

CLI for managing LocalStack containers that emulate AWS services locally.

## Install

```bash
# Homebrew (recommended)
brew install localstack/tap/localstack-cli

# pip
pip install localstack

# Verify
localstack --version
```

Binary downloads available at https://github.com/localstack/localstack-cli/releases

## Quick Start

```bash
# Start in background
localstack start -d

# Wait until ready
localstack wait -t 30

# Check status
localstack status services

# View logs
localstack logs

# Stop
localstack stop
```

## Core Commands

### start

```bash
localstack start              # Start in foreground
localstack start -d           # Start detached (background)
localstack start --docker     # Force Docker mode (default)
localstack start --host       # Host mode (no container)
localstack start --no-banner  # Suppress startup banner
```

### stop

```bash
localstack stop               # Stop running container
```

### status

```bash
localstack status             # Container status
localstack status services    # List running services with status
```

### wait

```bash
localstack wait               # Wait until LocalStack is ready
localstack wait -t 60         # Custom timeout (seconds)
```

### logs

```bash
localstack logs               # Stream container logs
localstack logs -f            # Follow logs (continuous)
```

### update

```bash
localstack update all             # Update everything
localstack update docker-images   # Pull latest Docker images
localstack update localstack-cli  # Update CLI (pip only)
```

### config

```bash
localstack config validate    # Validate docker-compose config
localstack config show        # Show current configuration
```

## Configuration

### Environment Variables

Set before `localstack start`:

```bash
# Core
DEBUG=1                           # Enable debug logging
SERVICES=s3,dynamodb,lambda       # Limit to specific services
PERSISTENCE=1                     # Enable state persistence
LS_LOG=debug                      # Log level: trace|debug|info|warn|error

# Networking
GATEWAY_LISTEN=0.0.0.0:4566      # Bind address (default in Docker)
LOCALSTACK_HOST=localhost:4566   # Returned in URLs

# Lambda
LAMBDA_DOCKER_NETWORK=my-network  # Network for Lambda containers
LAMBDA_KEEPALIVE_MS=600000        # Lambda warm time (10 min default)

# Pro
LOCALSTACK_AUTH_TOKEN=xxx         # Pro authentication token
```

### Profiles

Store configuration in `~/.localstack/<profile>.env`:

```bash
# ~/.localstack/dev.env
DEBUG=1
SERVICES=s3,dynamodb,sqs
PERSISTENCE=1
```

```bash
# Use profile
localstack start --profile dev

# Or via environment
CONFIG_PROFILE=dev localstack start
```

Default profile (`~/.localstack/default.env`) loads automatically.

### Docker Compose

```yaml
# docker-compose.yml
services:
  localstack:
    image: localstack/aws-localstack
    ports:
      - "4566:4566"
      - "4510-4559:4510-4559"
    environment:
      - DEBUG=1
      - PERSISTENCE=1
    volumes:
      - "./volume:/var/lib/aws-localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
```

```bash
docker compose up -d
```

## Port Reference

| Port | Service |
|------|---------|
| 4566 | Gateway (all services) |
| 4510-4559 | External services |
| 443 | HTTPS Gateway (Pro) |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Container won't start | Check Docker running: `docker ps` |
| Port already in use | Stop other LocalStack or change `GATEWAY_LISTEN` |
| Services not available | Check `SERVICES` env var, use `localstack status services` |
| Slow startup | First run pulls images; subsequent starts faster |
| Permission denied | Don't run with `sudo`; use non-root user |
| DNS issues | Set `DNS_ADDRESS=0` |

### Diagnostics

```bash
# Generate diagnostic report
curl localhost:4566/_localstack/diagnose | gzip > diagnose.json.gz

# Health check
curl localhost:4566/_localstack/health
```

## Integration

- For AWS CLI commands against LocalStack, use the `aws-local` skill
- For architecture patterns and testing strategies, use the `aws-localstack-expert` skill
