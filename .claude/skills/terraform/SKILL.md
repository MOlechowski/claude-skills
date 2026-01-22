---
name: terraform
description: "Terraform infrastructure as code by HashiCorp. Use for: (1) provisioning cloud infrastructure (AWS, GCP, Azure), (2) managing infrastructure state, (3) multi-environment deployments, (4) module development, (5) Terraform Cloud/Enterprise workflows. Triggers: terraform plan, terraform apply, provision infrastructure, IaC, infrastructure as code, HCP Terraform."
---

# Terraform Expertise Skill

Terraform is HashiCorp's infrastructure as code tool for provisioning and managing cloud resources declaratively.

## Core Workflow

```bash
terraform init      # Initialize providers and modules
terraform plan      # Preview changes
terraform apply     # Apply changes
terraform destroy   # Tear down infrastructure
```

## Basic Usage

```bash
terraform init                           # Initialize working directory
terraform plan -out=plan.tfplan          # Save plan to file
terraform apply plan.tfplan              # Apply saved plan
terraform plan -target=aws_instance.web  # Plan specific resource
terraform apply -auto-approve            # Skip confirmation (CI only)
```

## Command Reference

### Init

```bash
terraform init                           # Standard init
terraform init -upgrade                  # Upgrade providers
terraform init -reconfigure              # Reconfigure backend
terraform init -backend-config=prod.hcl  # Dynamic backend config
terraform init -migrate-state            # Migrate state between backends
terraform init -get=false                # Skip module download
```

### Plan

```bash
terraform plan                           # Standard plan
terraform plan -out=plan.tfplan          # Save plan (recommended)
terraform plan -var="env=prod"           # Pass variable
terraform plan -var-file=prod.tfvars     # Use variable file
terraform plan -target=module.vpc        # Target specific resource
terraform plan -destroy                  # Plan destruction
terraform plan -refresh-only             # Detect drift only
terraform plan -detailed-exitcode        # Exit 0=no changes, 1=error, 2=changes
terraform plan -parallelism=10           # Control concurrency
terraform plan -compact-warnings         # Reduce warning verbosity
```

### Apply

```bash
terraform apply                          # Interactive apply
terraform apply plan.tfplan              # Apply saved plan (recommended)
terraform apply -auto-approve            # Skip confirmation (CI only)
terraform apply -parallelism=10          # Control parallelism
terraform apply -replace=aws_instance.x  # Force resource replacement
terraform apply -refresh=false           # Skip refresh (faster, riskier)
terraform apply -target=module.vpc       # Apply specific resource only
```

### Destroy

```bash
terraform destroy                        # Destroy all resources
terraform destroy -target=aws_instance.x # Destroy specific resource
terraform destroy -auto-approve          # Skip confirmation (CI only)
terraform plan -destroy -out=destroy.tfplan  # Preview destruction
terraform apply destroy.tfplan           # Apply destruction plan
```

### Validate and Format

```bash
terraform validate                       # Validate configuration syntax
terraform fmt                            # Format HCL files
terraform fmt -check                     # Check formatting (CI)
terraform fmt -diff                      # Show formatting changes
terraform fmt -recursive                 # Format subdirectories
terraform fmt -write=false               # Preview without writing
```

### Output and Show

```bash
terraform output                         # Show all outputs
terraform output -json                   # JSON format
terraform output vpc_id                  # Specific output
terraform output -raw vpc_id             # Raw value (for scripts)
terraform show                           # Show current state
terraform show -json                     # JSON format
terraform show plan.tfplan               # Show saved plan
```

## State Operations

### Inspecting State

```bash
terraform state list                     # List all resources
terraform state list module.vpc          # List resources in module
terraform state show aws_instance.web    # Show resource details
terraform state pull                     # Download remote state to stdout
terraform state pull > backup.tfstate    # Backup state
```

### Modifying State

```bash
# Rename resource (refactoring)
terraform state mv aws_instance.old aws_instance.new

# Move to module
terraform state mv aws_instance.web module.compute.aws_instance.web

# Remove from state (keeps real resource)
terraform state rm aws_instance.orphan

# Push state (dangerous - use with caution)
terraform state push backup.tfstate
```

### Import Existing Resources

```bash
# Import single resource
terraform import aws_instance.web i-1234567890abcdef0

# Import with index
terraform import 'aws_instance.web[0]' i-1234567890

# Import into module
terraform import module.vpc.aws_vpc.main vpc-12345

# Generate import blocks (Terraform 1.5+)
terraform plan -generate-config-out=generated.tf
```

### State Locking

```bash
# Force unlock (use only when lock is stale)
terraform force-unlock LOCK_ID

# Disable locking (not recommended)
terraform plan -lock=false
```

## Workspace Management

Workspaces provide isolated state for the same configuration.

```bash
terraform workspace list                 # List workspaces
terraform workspace new staging          # Create workspace
terraform workspace select production    # Switch workspace
terraform workspace delete staging       # Delete workspace
terraform workspace show                 # Current workspace
```

### Workspace in Configuration

```hcl
# Use workspace name in resources
resource "aws_instance" "web" {
  tags = {
    Environment = terraform.workspace
  }
}

# Environment-specific configuration
locals {
  env_config = {
    default    = { instance_type = "t3.micro", count = 1 }
    staging    = { instance_type = "t3.small", count = 2 }
    production = { instance_type = "t3.large", count = 3 }
  }
  config = local.env_config[terraform.workspace]
}

resource "aws_instance" "web" {
  count         = local.config.count
  instance_type = local.config.instance_type
}
```

## Module Development

### Module Structure

```
modules/vpc/
├── main.tf           # Resources
├── variables.tf      # Input variables
├── outputs.tf        # Output values
├── versions.tf       # Required providers
├── locals.tf         # Local values (optional)
└── README.md         # Documentation
```

### Module Usage

```hcl
# Local module
module "vpc" {
  source = "./modules/vpc"

  cidr_block  = "10.0.0.0/16"
  environment = var.environment
}

# Git module with version
module "vpc" {
  source = "git::https://github.com/org/modules.git//vpc?ref=v1.0.0"
}

# Registry module
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}

# Output from module
output "vpc_id" {
  value = module.vpc.vpc_id
}
```

### Module Versioning

```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"      # Exact version
  # version = "~> 5.0"   # Any 5.x
  # version = ">= 5.0"   # 5.0 or higher
}
```

## Terraform Cloud/Enterprise

### Login and Setup

```bash
# Login to Terraform Cloud
terraform login

# Login to Enterprise
terraform login app.terraform.example.com
```

### Cloud Backend Configuration

```hcl
terraform {
  cloud {
    organization = "my-org"

    workspaces {
      name = "my-workspace"
    }
  }
}

# Or with tags for multiple workspaces
terraform {
  cloud {
    organization = "my-org"

    workspaces {
      tags = ["app:web", "env:production"]
    }
  }
}
```

### Remote Execution

```bash
# Runs execute in Terraform Cloud
terraform plan   # Plan runs remotely
terraform apply  # Apply runs remotely

# Local planning with remote state
terraform plan -target=aws_instance.web
```

### Sentinel Policy (Enterprise)

```hcl
# Sentinel policy example - enforce tagging
import "tfplan/v2" as tfplan

required_tags = ["Environment", "Owner", "Project"]

main = rule {
  all tfplan.resources as _, r {
    all r.changes as _, c {
      all required_tags as tag {
        c.after.tags contains tag
      }
    }
  }
}
```

## Multi-Environment Patterns

### Directory-Based (Recommended for Different Infrastructure)

```
environments/
├── dev/
│   ├── main.tf
│   ├── backend.tf
│   └── terraform.tfvars
├── staging/
│   └── ...
└── production/
    └── ...
```

### Workspace-Based (Same Infrastructure, Different Scale)

```bash
# Create environments
terraform workspace new dev
terraform workspace new staging
terraform workspace new production

# Deploy to specific environment
terraform workspace select staging
terraform apply -var-file=staging.tfvars
```

### Variable Files Pattern

```bash
# Per-environment variable files
terraform plan -var-file=environments/production.tfvars

# Common + environment-specific
terraform plan -var-file=common.tfvars -var-file=production.tfvars
```

### Backend Configuration Per Environment

```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket         = "company-terraform-state"
    key            = "project/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}
```

```bash
# Initialize with environment-specific backend
terraform init -backend-config=backends/production.hcl
```

## GitOps/PR Workflow

### PR-Based Infrastructure Changes

```bash
# On PR branch - generate plan
terraform init
terraform plan -out=plan.tfplan -no-color 2>&1 | tee plan.txt

# Post plan as PR comment
gh pr comment $PR_NUMBER --body "## Terraform Plan
\`\`\`
$(cat plan.txt)
\`\`\`"
```

### CI/CD Pipeline Pattern

```yaml
# GitHub Actions example
name: Terraform
on:
  pull_request:
  push:
    branches: [main]

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init
      - run: terraform plan -out=plan.tfplan
      - uses: actions/upload-artifact@v4
        with:
          name: tfplan
          path: plan.tfplan

  apply:
    needs: plan
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: actions/download-artifact@v4
        with:
          name: tfplan
      - run: terraform init
      - run: terraform apply plan.tfplan
```

### Plan Review Checklist

- No unexpected resource deletions
- No sensitive data exposed in outputs
- Resource counts are reasonable
- No unintended permission changes
- Cost estimate is acceptable

## Decision Matrix

### When to Apply vs Plan-Only

| Situation | Action |
|-----------|--------|
| PR review | Plan only, post to PR |
| Main branch merge | Apply with saved plan |
| Emergency fix | Plan, review, apply with approval |
| Drift detection | `plan -refresh-only` |
| Development | Plan frequently, apply when ready |

### Workspace vs Directory Selection

| Scenario | Approach |
|----------|----------|
| Same infrastructure, different scale | Workspaces |
| Different infrastructure per env | Directories |
| Different providers per env | Directories |
| Rapid prototyping | Workspaces |
| Compliance/audit requirements | Directories |

### State Operation Safety

| Operation | Risk | Precaution |
|-----------|------|------------|
| state mv | Medium | Plan before and after |
| state rm | High | Backup state first |
| state push | Critical | Never without backup |
| import | Low | Verify resource ID first |

### Terraform Cloud vs Self-Managed

| Factor | Terraform Cloud | Self-Managed |
|--------|-----------------|--------------|
| State management | Automatic | Configure backend |
| Remote execution | Built-in | CI/CD pipeline |
| Policy enforcement | Sentinel | External tools |
| Cost estimation | Built-in | Manual |
| Team collaboration | Built-in | Git + reviews |

## Safety Rules

1. **Never auto-approve in production** - Always review plans
2. **Use saved plans** - `plan -out=` then `apply plan.tfplan`
3. **Backup state before modifications** - `state pull > backup.tfstate`
4. **Lock state** - Use DynamoDB or equivalent for remote state
5. **Review destroy plans carefully** - Check resource counts
6. **Use -target sparingly** - Can create inconsistent state
7. **Never edit state files manually** - Use state commands
8. **Test with plan -destroy** - Before actual destruction

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| State lock | Concurrent operations | Wait or `force-unlock` |
| Provider not found | Missing init | Run `terraform init` |
| Resource already exists | Import needed | `terraform import` |
| Cycle detected | Circular dependency | Review `depends_on` |
| Count/for_each conflict | Both used | Use one or the other |

### Recovery Procedures

```bash
# State corruption - restore from backup
terraform state pull > current.tfstate.backup
terraform state push backup.tfstate

# Drift detected - reconcile
terraform plan -refresh-only
terraform apply -refresh-only  # Accept current state

# Resource stuck - taint for recreation
terraform taint aws_instance.web
terraform apply
```

## Resources

See `references/quick-reference.md` for command cheatsheet.
See `references/examples.md` for real-world workflows.
See `references/decision-tree.md` for complex decision scenarios.
