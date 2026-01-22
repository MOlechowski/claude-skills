---
name: tofu
description: "OpenTofu infrastructure as code. Use for: (1) provisioning cloud infrastructure (AWS, GCP, Azure), (2) managing infrastructure state, (3) multi-environment deployments, (4) module development. Triggers: tofu plan, tofu apply, provision infrastructure, IaC, infrastructure as code, OpenTofu."
---

# OpenTofu Expertise Skill

OpenTofu is an open-source fork of Terraform (MPL 2.0 license). Commands are identical to Terraform with the `tofu` binary.

## Core Workflow

```bash
tofu init      # Initialize providers and modules
tofu plan      # Preview changes
tofu apply     # Apply changes
tofu destroy   # Tear down infrastructure
```

## Basic Usage

```bash
tofu init                           # Initialize working directory
tofu plan -out=plan.tfplan          # Save plan to file
tofu apply plan.tfplan              # Apply saved plan
tofu plan -target=aws_instance.web  # Plan specific resource
tofu apply -auto-approve            # Skip confirmation (CI only)
```

## Command Reference

### Init

```bash
tofu init                           # Standard init
tofu init -upgrade                  # Upgrade providers
tofu init -reconfigure              # Reconfigure backend
tofu init -backend-config=prod.hcl  # Dynamic backend config
tofu init -migrate-state            # Migrate state between backends
tofu init -get=false                # Skip module download
```

### Plan

```bash
tofu plan                           # Standard plan
tofu plan -out=plan.tfplan          # Save plan (recommended)
tofu plan -var="env=prod"           # Pass variable
tofu plan -var-file=prod.tfvars     # Use variable file
tofu plan -target=module.vpc        # Target specific resource
tofu plan -destroy                  # Plan destruction
tofu plan -refresh-only             # Detect drift only
tofu plan -detailed-exitcode        # Exit 0=no changes, 1=error, 2=changes
tofu plan -parallelism=10           # Control concurrency
tofu plan -compact-warnings         # Reduce warning verbosity
```

### Apply

```bash
tofu apply                          # Interactive apply
tofu apply plan.tfplan              # Apply saved plan (recommended)
tofu apply -auto-approve            # Skip confirmation (CI only)
tofu apply -parallelism=10          # Control parallelism
tofu apply -replace=aws_instance.x  # Force resource replacement
tofu apply -refresh=false           # Skip refresh (faster, riskier)
tofu apply -target=module.vpc       # Apply specific resource only
```

### Destroy

```bash
tofu destroy                        # Destroy all resources
tofu destroy -target=aws_instance.x # Destroy specific resource
tofu destroy -auto-approve          # Skip confirmation (CI only)
tofu plan -destroy -out=destroy.tfplan  # Preview destruction
tofu apply destroy.tfplan           # Apply destruction plan
```

### Validate and Format

```bash
tofu validate                       # Validate configuration syntax
tofu fmt                            # Format HCL files
tofu fmt -check                     # Check formatting (CI)
tofu fmt -diff                      # Show formatting changes
tofu fmt -recursive                 # Format subdirectories
tofu fmt -write=false               # Preview without writing
```

### Output and Show

```bash
tofu output                         # Show all outputs
tofu output -json                   # JSON format
tofu output vpc_id                  # Specific output
tofu output -raw vpc_id             # Raw value (for scripts)
tofu show                           # Show current state
tofu show -json                     # JSON format
tofu show plan.tfplan               # Show saved plan
```

## State Operations

### Inspecting State

```bash
tofu state list                     # List all resources
tofu state list module.vpc          # List resources in module
tofu state show aws_instance.web    # Show resource details
tofu state pull                     # Download remote state to stdout
tofu state pull > backup.tfstate    # Backup state
```

### Modifying State

```bash
# Rename resource (refactoring)
tofu state mv aws_instance.old aws_instance.new

# Move to module
tofu state mv aws_instance.web module.compute.aws_instance.web

# Remove from state (keeps real resource)
tofu state rm aws_instance.orphan

# Push state (dangerous - use with caution)
tofu state push backup.tfstate
```

### Import Existing Resources

```bash
# Import single resource
tofu import aws_instance.web i-1234567890abcdef0

# Import with index
tofu import 'aws_instance.web[0]' i-1234567890

# Import into module
tofu import module.vpc.aws_vpc.main vpc-12345

# Generate import blocks (OpenTofu 1.5+)
tofu plan -generate-config-out=generated.tf
```

### State Locking

```bash
# Force unlock (use only when lock is stale)
tofu force-unlock LOCK_ID

# Disable locking (not recommended)
tofu plan -lock=false
```

## Workspace Management

Workspaces provide isolated state for the same configuration.

```bash
tofu workspace list                 # List workspaces
tofu workspace new staging          # Create workspace
tofu workspace select production    # Switch workspace
tofu workspace delete staging       # Delete workspace
tofu workspace show                 # Current workspace
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
tofu workspace new dev
tofu workspace new staging
tofu workspace new production

# Deploy to specific environment
tofu workspace select staging
tofu apply -var-file=staging.tfvars
```

### Variable Files Pattern

```bash
# Per-environment variable files
tofu plan -var-file=environments/production.tfvars

# Common + environment-specific
tofu plan -var-file=common.tfvars -var-file=production.tfvars
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
tofu init -backend-config=backends/production.hcl
```

## GitOps/PR Workflow

### PR-Based Infrastructure Changes

```bash
# On PR branch - generate plan
tofu init
tofu plan -out=plan.tfplan -no-color 2>&1 | tee plan.txt

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
      - uses: opentofu/setup-opentofu@v1
      - run: tofu init
      - run: tofu plan -out=plan.tfplan
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
      - uses: opentofu/setup-opentofu@v1
      - uses: actions/download-artifact@v4
        with:
          name: tfplan
      - run: tofu init
      - run: tofu apply plan.tfplan
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
| Provider not found | Missing init | Run `tofu init` |
| Resource already exists | Import needed | `tofu import` |
| Cycle detected | Circular dependency | Review `depends_on` |
| Count/for_each conflict | Both used | Use one or the other |

### Recovery Procedures

```bash
# State corruption - restore from backup
tofu state pull > current.tfstate.backup
tofu state push backup.tfstate

# Drift detected - reconcile
tofu plan -refresh-only
tofu apply -refresh-only  # Accept current state

# Resource stuck - taint for recreation
tofu taint aws_instance.web
tofu apply
```

## Resources

See `references/quick-reference.md` for command cheatsheet.
See `references/examples.md` for real-world workflows.
See `references/decision-tree.md` for complex decision scenarios.
