# Environment Patterns

## Contents
- [Directory-Based Environments](#directory-based-environments) - Structure, config, modules
- [Workspace-Based Environments](#workspace-based-environments) - Configuration, commands
- [Tfvars-Based Environments](#tfvars-based-environments) - Structure, partial backend
- [Environment Promotion](#environment-promotion) - GitOps flow, checklist
- [Drift Detection](#drift-detection) - Scheduled, manual
- [Environment Parity](#environment-parity) - Naming, scaling differences
- [Feature Environments](#feature-environments) - Dynamic, cleanup
- [Comparison Table](#comparison-table) - Patterns compared
- [Anti-patterns](#anti-patterns) - Common mistakes

## Directory-Based Environments

### Structure

```
infrastructure/
├── modules/
│   ├── networking/
│   ├── compute/
│   └── database/
├── environments/
│   ├── dev/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── backend.tf
│   │   └── terraform.tfvars
│   ├── staging/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── backend.tf
│   │   └── terraform.tfvars
│   └── prod/
│       ├── main.tf
│       ├── variables.tf
│       ├── backend.tf
│       └── terraform.tfvars
```

### Environment-Specific Config

```hcl
# environments/dev/terraform.tfvars
environment        = "dev"
instance_type      = "t3.small"
instance_count     = 1
enable_multi_az    = false
enable_deletion_protection = false

# environments/prod/terraform.tfvars
environment        = "prod"
instance_type      = "t3.large"
instance_count     = 3
enable_multi_az    = true
enable_deletion_protection = true
```

### Shared Module Reference

```hcl
# environments/prod/main.tf
module "networking" {
  source = "../../modules/networking"

  environment = var.environment
  cidr_block  = var.cidr_block
  # ... other variables
}
```

## Workspace-Based Environments

### Configuration

```hcl
# main.tf
locals {
  environment = terraform.workspace

  config = {
    dev = {
      instance_type  = "t3.small"
      instance_count = 1
      multi_az       = false
    }
    staging = {
      instance_type  = "t3.medium"
      instance_count = 2
      multi_az       = false
    }
    prod = {
      instance_type  = "t3.large"
      instance_count = 3
      multi_az       = true
    }
  }

  current = local.config[local.environment]
}

resource "aws_instance" "web" {
  count         = local.current.instance_count
  instance_type = local.current.instance_type
  # ...
}
```

### Workspace Commands

```bash
# Create workspaces
terraform workspace new dev
terraform workspace new staging
terraform workspace new prod

# Switch workspace
terraform workspace select prod

# List workspaces
terraform workspace list

# Show current
terraform workspace show
```

## Tfvars-Based Environments

### Structure

```
infrastructure/
├── main.tf
├── variables.tf
├── backend.tf
└── environments/
    ├── dev.tfvars
    ├── staging.tfvars
    └── prod.tfvars
```

### Usage

```bash
terraform plan -var-file=environments/prod.tfvars
terraform apply -var-file=environments/prod.tfvars
```

### Partial Backend Config

```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket = "myorg-terraform-state"
    region = "us-east-1"
    # key is set via -backend-config
  }
}
```

```bash
terraform init -backend-config="key=prod/terraform.tfstate"
```

## Environment Promotion

### GitOps Flow

```
feature-branch → dev → staging → prod
     │            │       │        │
     └──────────────────────────────
              Pull Requests
```

1. Feature branch deploys to dev on push
2. PR to main triggers staging deployment
3. Manual approval promotes to prod
4. Tag release for audit trail

### Promotion Checklist

- [ ] All tests pass in lower environment
- [ ] Drift detection shows no unexpected changes
- [ ] Plan reviewed and approved
- [ ] Rollback plan documented
- [ ] Monitoring alerts configured

## Drift Detection

### Scheduled Detection

```yaml
# GitHub Actions
name: Drift Detection
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM

jobs:
  detect:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [dev, staging, prod]
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: Terraform Plan
        run: |
          cd environments/${{ matrix.environment }}
          terraform init
          terraform plan -detailed-exitcode
        continue-on-error: true
      - name: Alert on Drift
        if: steps.plan.outcome == 'failure'
        run: |
          # Send Slack/email notification
```

### Manual Check

```bash
terraform plan -detailed-exitcode
# Exit code 0: No changes
# Exit code 1: Error
# Exit code 2: Changes detected (drift)
```

## Environment Parity

### Consistent Naming

```hcl
locals {
  name_prefix = "${var.project}-${var.environment}"
}

resource "aws_vpc" "main" {
  tags = {
    Name        = "${local.name_prefix}-vpc"
    Environment = var.environment
    Project     = var.project
  }
}
```

### Scaling Differences

```hcl
locals {
  is_prod = var.environment == "prod"

  rds_config = {
    instance_class    = local.is_prod ? "db.r5.large" : "db.t3.small"
    multi_az          = local.is_prod
    backup_retention  = local.is_prod ? 30 : 7
    deletion_protection = local.is_prod
  }
}
```

## Feature Environments

### Dynamic Environments

```hcl
# Create environment per feature branch
variable "branch_name" {
  type = string
}

locals {
  environment = replace(var.branch_name, "/", "-")
}

resource "aws_ecs_service" "app" {
  name = "app-${local.environment}"
  # ...
}
```

### Cleanup

```yaml
# GitHub Actions - cleanup on branch delete
on:
  delete:
    branches:
      - 'feature/*'

jobs:
  cleanup:
    runs-on: ubuntu-latest
    steps:
      - name: Destroy Feature Environment
        run: |
          terraform destroy -auto-approve \
            -var="branch_name=${{ github.event.ref }}"
```

## Comparison Table

| Aspect | Directory-Based | Workspace-Based | Tfvars-Based |
|--------|-----------------|-----------------|--------------|
| Code duplication | Minimal (shared modules) | None | None |
| Config flexibility | Full | Limited | Moderate |
| State isolation | Complete | Shared backend | Partial |
| Visibility | Explicit structure | Implicit | Implicit |
| CI/CD complexity | Medium | Simple | Simple |
| Best for | Divergent envs | Similar envs | Simple projects |

## Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| Prod/dev in same state | Accidental destruction | Isolate state |
| No drift detection | Silent configuration drift | Schedule checks |
| Manual promotions | Error-prone, no audit | GitOps automation |
| Copy-paste between envs | Drift, maintenance | Use modules |
| Same credentials all envs | Security risk | Per-env credentials |
