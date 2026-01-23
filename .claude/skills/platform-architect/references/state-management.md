# State Management

## Contents
- [Remote Backends](#remote-backends) - S3, GCS, Azure, Terraform Cloud
- [State Isolation Strategies](#state-isolation-strategies) - Directory, workspace, account
- [State Locking](#state-locking) - Lock override, timeout
- [State Inspection](#state-inspection) - List, show, pull
- [State Surgery](#state-surgery) - Move, remove, import, replace
- [State Recovery](#state-recovery) - From backup, from infrastructure
- [Cross-State References](#cross-state-references) - Remote state, SSM
- [State Security](#state-security) - Encryption, access control
- [Anti-patterns](#anti-patterns) - Common mistakes

## Remote Backends

### S3 + DynamoDB (AWS)

```hcl
terraform {
  backend "s3" {
    bucket         = "myorg-terraform-state"
    key            = "prod/networking/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}
```

DynamoDB table for locking:
```hcl
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}
```

### GCS (GCP)

```hcl
terraform {
  backend "gcs" {
    bucket = "myorg-terraform-state"
    prefix = "prod/networking"
  }
}
```

### Azure Blob

```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "terraform-state-rg"
    storage_account_name = "tfstate12345"
    container_name       = "tfstate"
    key                  = "prod/networking.tfstate"
  }
}
```

### Terraform Cloud

```hcl
terraform {
  cloud {
    organization = "myorg"
    workspaces {
      name = "prod-networking"
    }
  }
}
```

## State Isolation Strategies

### Directory-Based

```
infrastructure/
├── networking/
│   ├── backend.tf    # s3://state/networking/terraform.tfstate
│   └── main.tf
├── compute/
│   ├── backend.tf    # s3://state/compute/terraform.tfstate
│   └── main.tf
└── database/
    ├── backend.tf    # s3://state/database/terraform.tfstate
    └── main.tf
```

**Pros:** Complete isolation, independent lifecycles
**Cons:** Cross-stack references need data sources or outputs

### Workspace-Based

```hcl
terraform {
  backend "s3" {
    bucket = "myorg-terraform-state"
    key    = "app/terraform.tfstate"
    region = "us-east-1"
  }
}

# Access workspace name
locals {
  environment = terraform.workspace
}
```

Usage:
```bash
terraform workspace new dev
terraform workspace new prod
terraform workspace select prod
terraform apply
```

**Pros:** Single codebase, DRY
**Cons:** Shared backend, can't have different configs per workspace

### Account-Based

```
aws-account-dev/
├── networking/
└── compute/

aws-account-prod/
├── networking/
└── compute/
```

**Pros:** Maximum isolation, security boundaries
**Cons:** Duplication, harder cross-account references

## State Locking

### Manual Lock Override

```bash
# Force unlock (dangerous - use only if lock is stale)
terraform force-unlock LOCK_ID
```

### Lock Timeout

```bash
terraform apply -lock-timeout=10m
```

## State Inspection

### List Resources

```bash
terraform state list
terraform state list module.vpc
```

### Show Resource

```bash
terraform state show aws_instance.web
terraform state show 'module.vpc.aws_subnet.private[0]'
```

### Pull State

```bash
terraform state pull > state.json
```

## State Surgery

### Move Resource

```bash
# Rename resource
terraform state mv aws_instance.web aws_instance.app

# Move into module
terraform state mv aws_instance.web module.compute.aws_instance.web

# Move between state files
terraform state mv -state-out=other.tfstate aws_instance.web aws_instance.web
```

### Remove Resource (Stop Managing)

```bash
# Remove from state without destroying
terraform state rm aws_instance.web
```

### Import Existing Resource

```bash
terraform import aws_instance.web i-1234567890abcdef0
terraform import 'module.vpc.aws_subnet.private[0]' subnet-abc123
```

### Replace Resource

```bash
# Mark for replacement on next apply
terraform apply -replace=aws_instance.web
```

## State Recovery

### From Backup

S3 versioning allows recovery:
```bash
aws s3api list-object-versions --bucket myorg-terraform-state --prefix prod/networking
aws s3api get-object --bucket myorg-terraform-state --key prod/networking/terraform.tfstate --version-id VERSION_ID recovered.tfstate
```

### From Running Infrastructure

```bash
# Generate import blocks
terraform plan -generate-config-out=generated.tf

# Or manually import each resource
terraform import aws_vpc.main vpc-abc123
terraform import aws_subnet.private subnet-def456
```

### State Refresh

```bash
# Sync state with actual infrastructure
terraform refresh

# Or via plan (safer)
terraform plan -refresh-only
terraform apply -refresh-only
```

## Cross-State References

### Remote State Data Source

```hcl
data "terraform_remote_state" "networking" {
  backend = "s3"
  config = {
    bucket = "myorg-terraform-state"
    key    = "prod/networking/terraform.tfstate"
    region = "us-east-1"
  }
}

resource "aws_instance" "web" {
  subnet_id = data.terraform_remote_state.networking.outputs.private_subnet_ids[0]
}
```

### SSM Parameter Store (Alternative)

```hcl
# In networking stack
resource "aws_ssm_parameter" "vpc_id" {
  name  = "/infrastructure/prod/vpc_id"
  type  = "String"
  value = aws_vpc.main.id
}

# In compute stack
data "aws_ssm_parameter" "vpc_id" {
  name = "/infrastructure/prod/vpc_id"
}
```

## State Security

### Encryption

- S3: Enable SSE-S3 or SSE-KMS
- GCS: Enabled by default
- Azure: Enable encryption at rest

### Access Control

```hcl
# S3 bucket policy - restrict to specific roles
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/TerraformRole"
      },
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::myorg-terraform-state/*"
    }
  ]
}
```

### Sensitive Data

State contains sensitive values. Mitigations:
- Encrypt at rest and transit
- Restrict access
- Use `sensitive = true` on outputs
- Consider Vault for secrets instead of state

## Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| Local state in team | Conflicts, lost state | Use remote backend |
| No locking | Concurrent corruption | Enable DynamoDB/native locking |
| State in git | Secrets exposed | Use remote backend |
| Single state for everything | Blast radius, slow | Split by domain |
| No versioning | Can't recover | Enable S3 versioning |
