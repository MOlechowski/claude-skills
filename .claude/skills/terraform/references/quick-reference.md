# Terraform Quick Reference

## Command Syntax

```bash
terraform [global options] <command> [args]
```

## Essential Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize working directory |
| `plan` | Preview changes |
| `apply` | Apply changes |
| `destroy` | Destroy infrastructure |
| `validate` | Validate configuration |
| `fmt` | Format HCL files |
| `output` | Show output values |
| `show` | Show state or plan |
| `login` | Login to Terraform Cloud |

## Init Flags

| Flag | Description |
|------|-------------|
| `-upgrade` | Upgrade providers to latest |
| `-reconfigure` | Reconfigure backend |
| `-backend-config=FILE` | Backend config file |
| `-migrate-state` | Migrate state to new backend |
| `-get=false` | Skip module download |

## Plan Flags

| Flag | Description |
|------|-------------|
| `-out=FILE` | Save plan to file |
| `-var="key=value"` | Set variable |
| `-var-file=FILE` | Variable file |
| `-target=RESOURCE` | Target specific resource |
| `-destroy` | Plan destruction |
| `-refresh-only` | Detect drift only |
| `-detailed-exitcode` | 0=no changes, 2=changes |
| `-parallelism=N` | Concurrent operations |

## Apply Flags

| Flag | Description |
|------|-------------|
| `plan.tfplan` | Apply saved plan |
| `-auto-approve` | Skip confirmation |
| `-parallelism=N` | Concurrent operations |
| `-replace=RESOURCE` | Force replacement |
| `-target=RESOURCE` | Target specific resource |
| `-refresh=false` | Skip refresh |

## State Commands

| Command | Description |
|---------|-------------|
| `state list` | List resources |
| `state show RESOURCE` | Show resource details |
| `state mv SRC DEST` | Rename/move resource |
| `state rm RESOURCE` | Remove from state |
| `state pull` | Download state |
| `state push FILE` | Upload state |
| `import RESOURCE ID` | Import existing resource |
| `force-unlock ID` | Release stuck lock |

## Workspace Commands

| Command | Description |
|---------|-------------|
| `workspace list` | List workspaces |
| `workspace new NAME` | Create workspace |
| `workspace select NAME` | Switch workspace |
| `workspace delete NAME` | Delete workspace |
| `workspace show` | Current workspace |

## Terraform Cloud Commands

| Command | Description |
|---------|-------------|
| `login` | Login to Terraform Cloud |
| `login HOST` | Login to Enterprise |
| `logout` | Logout |

## Output Commands

| Command | Description |
|---------|-------------|
| `output` | Show all outputs |
| `output -json` | JSON format |
| `output NAME` | Specific output |
| `output -raw NAME` | Raw value |

## Format Commands

| Command | Description |
|---------|-------------|
| `fmt` | Format current dir |
| `fmt -check` | Check only (CI) |
| `fmt -diff` | Show changes |
| `fmt -recursive` | Include subdirs |

## Common Patterns

### Safe Apply Workflow

```bash
terraform plan -out=plan.tfplan
terraform apply plan.tfplan
```

### Multi-Environment

```bash
terraform workspace select staging
terraform plan -var-file=staging.tfvars -out=plan.tfplan
terraform apply plan.tfplan
```

### State Backup Before Changes

```bash
terraform state pull > backup-$(date +%Y%m%d).tfstate
terraform state mv old_name new_name
```

### Drift Detection

```bash
terraform plan -refresh-only -detailed-exitcode
# Exit code 2 = drift detected
```

### Import Resource

```bash
# Add resource block to .tf file first
terraform import aws_instance.web i-1234567890abcdef0
terraform plan  # Verify no changes
```

### Destroy Single Resource

```bash
terraform plan -destroy -target=aws_instance.temp -out=destroy.tfplan
terraform apply destroy.tfplan
```

### Terraform Cloud Setup

```bash
terraform login
terraform init  # With cloud block in config
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (no changes with -detailed-exitcode) |
| 1 | Error |
| 2 | Changes present (with -detailed-exitcode) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TF_VAR_name` | Set variable |
| `TF_LOG` | Log level (TRACE, DEBUG, INFO, WARN, ERROR) |
| `TF_LOG_PATH` | Log file path |
| `TF_INPUT` | Disable prompts (0 or false) |
| `TF_CLI_ARGS` | Default CLI arguments |
| `TF_CLI_ARGS_plan` | Default arguments for plan |
| `TF_DATA_DIR` | Data directory (default: .terraform) |
| `TF_TOKEN_hostname` | API token for hostname |
| `TF_CLOUD_ORGANIZATION` | Default TFC organization |

## HCL Quick Syntax

### Variables

```hcl
variable "name" {
  type        = string
  default     = "value"
  description = "Description"
}
```

### Locals

```hcl
locals {
  common_tags = {
    Project = var.project
    Env     = terraform.workspace
  }
}
```

### Outputs

```hcl
output "id" {
  value       = aws_instance.web.id
  description = "Instance ID"
  sensitive   = false
}
```

### Resource with Count

```hcl
resource "aws_instance" "web" {
  count         = var.instance_count
  instance_type = var.instance_type
  tags = {
    Name = "web-${count.index}"
  }
}
```

### Resource with for_each

```hcl
resource "aws_instance" "web" {
  for_each      = var.instances
  instance_type = each.value.type
  tags = {
    Name = each.key
  }
}
```

### Dynamic Blocks

```hcl
resource "aws_security_group" "web" {
  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs
    }
  }
}
```

## Provider Configuration

### AWS

```hcl
provider "aws" {
  region  = "us-east-1"
  profile = "myprofile"
}
```

### GCP

```hcl
provider "google" {
  project = "my-project"
  region  = "us-central1"
}
```

### Azure

```hcl
provider "azurerm" {
  features {}
  subscription_id = "xxx"
}
```

## Backend Configuration

### S3

```hcl
terraform {
  backend "s3" {
    bucket         = "my-tf-state"
    key            = "path/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tf-locks"
    encrypt        = true
  }
}
```

### GCS

```hcl
terraform {
  backend "gcs" {
    bucket = "my-tf-state"
    prefix = "path"
  }
}
```

### Azure Blob

```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "rg-tfstate"
    storage_account_name = "tfstate"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
  }
}
```

### Terraform Cloud

```hcl
terraform {
  cloud {
    organization = "my-org"
    workspaces {
      name = "my-workspace"
    }
  }
}
```

## Terraform Cloud Quick Reference

### Workspace Configuration

```hcl
# Single workspace
terraform {
  cloud {
    organization = "my-org"
    workspaces {
      name = "production"
    }
  }
}

# Multiple workspaces with tags
terraform {
  cloud {
    organization = "my-org"
    workspaces {
      tags = ["app:web"]
    }
  }
}
```

### CLI-Driven vs VCS-Driven

| Mode | Trigger | Use Case |
|------|---------|----------|
| CLI | `terraform apply` | Local development |
| VCS | Git push/merge | GitOps workflow |
| API | API calls | Custom automation |
