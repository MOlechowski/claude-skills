# {{ project_name }} Infrastructure

Infrastructure as Code for {{ project_name }}.

## Structure

```
.
├── environments/         # Environment-specific configurations
│   ├── dev/
│   ├── staging/
│   └── prod/
├── modules/              # Reusable modules
│   ├── networking/
│   ├── compute/
│   └── database/
├── .github/              # CI/CD workflows
│   └── workflows/
├── Makefile              # Common operations
└── README.md
```

## Quick Start

```bash
# Initialize environment
make init ENV=dev

# Plan changes
make plan ENV=dev

# Apply changes
make apply ENV=dev
```

## Environments

| Environment | Account | Region | Purpose |
|-------------|---------|--------|---------|
| dev | 111111111111 | us-east-1 | Development |
| staging | 222222222222 | us-east-1 | Pre-production testing |
| prod | 333333333333 | us-east-1 | Production |

## Modules

| Module | Description | Version |
|--------|-------------|---------|
| networking | VPC, subnets, NAT | v1.0.0 |
| compute | ECS, ALB | v1.0.0 |
| database | RDS PostgreSQL | v1.0.0 |

## CI/CD

- **Pull Request** → Terraform Plan → Review
- **Merge to main** → Apply to staging
- **Tag release** → Apply to prod (manual approval)

## Documentation

- [Architecture Diagrams](docs/diagrams/)
- [Architecture Decision Records](docs/adr/)
