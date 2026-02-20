# Module Patterns

## Contents
- [Module Types](#module-types) - Resource, pattern, root modules
- [Versioning](#versioning) - Semantic versioning, git tags
- [Registry Patterns](#registry-patterns) - Private registry, GitHub, S3
- [Dependency Injection](#dependency-injection) - Provider passthrough, data injection
- [Module Interface Design](#module-interface-design) - Validation, output contracts
- [Module Testing](#module-testing) - Terratest example
- [Anti-patterns](#anti-patterns) - Common mistakes

## Module Types

### Resource Modules

Wrap a single cloud resource with sensible defaults.

```hcl
# modules/s3-bucket/main.tf
resource "aws_s3_bucket" "this" {
  bucket = var.name
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = var.versioning ? "Enabled" : "Disabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

### Pattern Modules

Combine resources for common use cases.

```hcl
# modules/vpc/main.tf
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"

  name = var.name
  cidr = var.cidr

  azs             = var.availability_zones
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets

  enable_nat_gateway = true
  single_nat_gateway = var.environment != "prod"

  tags = var.tags
}
```

### Root Modules

Instantiate patterns for environments.

```hcl
# environments/prod/main.tf
module "networking" {
  source = "../../modules/vpc"

  name               = "prod-vpc"
  cidr               = "10.0.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  private_subnets    = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  environment        = "prod"
  tags               = local.common_tags
}
```

## Versioning

### Semantic Versioning

```
MAJOR.MINOR.PATCH
  │     │     └── Bug fixes, no interface changes
  │     └── New features, backward compatible
  └── Breaking changes
```

### Git Tags

```bash
git tag -a v1.0.0 -m "Initial release"
git push origin v1.0.0
```

### Module Source References

```hcl
# Pin to exact version
module "vpc" {
  source  = "git::https://github.com/org/modules.git//vpc?ref=v1.2.3"
}

# Pin to major version (via branch)
module "vpc" {
  source  = "git::https://github.com/org/modules.git//vpc?ref=v1"
}

# Registry with version constraint
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}
```

## Registry Patterns

### Private Registry (Terraform Cloud)

```hcl
module "vpc" {
  source  = "app.terraform.io/myorg/vpc/aws"
  version = "1.2.3"
}
```

### GitHub Releases

```hcl
module "vpc" {
  source = "github.com/org/terraform-aws-vpc?ref=v1.2.3"
}
```

### S3 Backend for Modules

```hcl
module "vpc" {
  source = "s3::https://s3-us-east-1.amazonaws.com/modules/vpc.zip"
}
```

## Dependency Injection

### Provider Passthrough

```hcl
# Root module passes provider
provider "aws" {
  alias  = "us_east"
  region = "us-east-1"
}

module "vpc_east" {
  source = "./modules/vpc"
  providers = {
    aws = aws.us_east
  }
}
```

### Data Source Injection

```hcl
# Pass data as variables instead of looking up in module
data "aws_caller_identity" "current" {}

module "s3" {
  source     = "./modules/s3"
  account_id = data.aws_caller_identity.current.account_id
}
```

## Module Interface Design

### Input Validation

```hcl
variable "environment" {
  type        = string
  description = "Environment name"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "instance_count" {
  type        = number
  description = "Number of instances"
  validation {
    condition     = var.instance_count > 0 && var.instance_count <= 10
    error_message = "Instance count must be between 1 and 10."
  }
}
```

### Output Contracts

```hcl
output "vpc_id" {
  description = "VPC identifier"
  value       = aws_vpc.this.id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "connection_info" {
  description = "Database connection information"
  value = {
    host     = aws_db_instance.this.endpoint
    port     = aws_db_instance.this.port
    database = aws_db_instance.this.db_name
  }
  sensitive = true
}
```

## Module Testing

### Terratest Example

```go
package test

import (
    "testing"
    "github.com/gruntwork-io/terratest/modules/iac-terraform"
    "github.com/stretchr/testify/assert"
)

func TestVpcModule(t *testing.T) {
    terraformOptions := &terraform.Options{
        TerraformDir: "../modules/vpc",
        Vars: map[string]interface{}{
            "name": "test-vpc",
            "cidr": "10.0.0.0/16",
        },
    }

    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)

    vpcId := terraform.Output(t, terraformOptions, "vpc_id")
    assert.NotEmpty(t, vpcId)
}
```

## Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| Nested modules > 2 levels | Hard to debug | Flatten hierarchy |
| Module with 50+ resources | Slow, risky | Split by lifecycle |
| Hardcoded provider in module | Not reusable | Accept provider config |
| Data lookups in module | Hidden dependencies | Inject via variables |
| Unpinned versions | Breaking changes | Always pin versions |
