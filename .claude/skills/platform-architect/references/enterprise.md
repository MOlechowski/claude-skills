# Enterprise Patterns

## Contents
- [Platform Engineering](#platform-engineering) - Internal developer platform, self-service
- [Governance](#governance) - Naming conventions, tag policies, SCPs
- [Team Boundaries](#team-boundaries) - Module ownership, CODEOWNERS, access control
- [Blast Radius Reduction](#blast-radius-reduction) - State isolation, dependencies, change windows
- [Multi-Account Strategy](#multi-account-strategy) - Organization structure, cross-account access
- [Enterprise Anti-patterns](#enterprise-anti-patterns) - Common mistakes

## Platform Engineering

### Internal Developer Platform

```
┌─────────────────────────────────────────────────────────────┐
│                    Developer Portal                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ Service     │  │ Environment │  │ Monitoring  │          │
│  │ Catalog     │  │ Requests    │  │ Dashboard   │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Platform Abstractions                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ Compute     │  │ Database    │  │ Networking  │          │
│  │ Module      │  │ Module      │  │ Module      │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Cloud Infrastructure                      │
│        AWS / GCP / Azure / Kubernetes                        │
└─────────────────────────────────────────────────────────────┘
```

### Self-Service Infrastructure

```hcl
# modules/platform/service/main.tf
# High-level abstraction for developers

variable "service_name" {
  type        = string
  description = "Name of the service"
}

variable "service_type" {
  type        = string
  description = "Type of service: api, worker, scheduled"
  validation {
    condition     = contains(["api", "worker", "scheduled"], var.service_type)
    error_message = "Service type must be api, worker, or scheduled."
  }
}

variable "size" {
  type        = string
  description = "Service size: small, medium, large"
  default     = "small"
}

locals {
  size_config = {
    small  = { cpu = 256,  memory = 512,  replicas = 1 }
    medium = { cpu = 512,  memory = 1024, replicas = 2 }
    large  = { cpu = 1024, memory = 2048, replicas = 3 }
  }
}

module "ecs_service" {
  source = "../internal/ecs-service"

  name     = var.service_name
  cpu      = local.size_config[var.size].cpu
  memory   = local.size_config[var.size].memory
  replicas = local.size_config[var.size].replicas

  load_balancer = var.service_type == "api"
  # ... internal implementation details hidden
}
```

### Developer Usage

```hcl
# teams/payments/services/api/main.tf
module "payments_api" {
  source = "git::https://github.com/org/platform-modules.git//service?ref=v2.0.0"

  service_name = "payments-api"
  service_type = "api"
  size         = "medium"

  environment_variables = {
    DATABASE_URL = data.aws_ssm_parameter.db_url.value
  }
}
```

## Governance

### Naming Conventions

```hcl
# modules/naming/main.tf
variable "project" {
  type = string
}

variable "environment" {
  type = string
}

variable "region" {
  type    = string
  default = "use1"
}

variable "resource_type" {
  type = string
}

variable "name" {
  type = string
}

locals {
  # Format: {project}-{env}-{region}-{type}-{name}
  # Example: acme-prod-use1-vpc-main
  resource_name = join("-", [
    var.project,
    var.environment,
    var.region,
    var.resource_type,
    var.name
  ])
}

output "name" {
  value = local.resource_name
}
```

### Tag Policies

```hcl
# Organization-level tag policy
resource "aws_organizations_policy" "tag_policy" {
  name    = "required-tags"
  type    = "TAG_POLICY"
  content = jsonencode({
    tags = {
      Environment = {
        tag_key = {
          "@@assign" = "Environment"
        }
        tag_value = {
          "@@assign" = ["dev", "staging", "prod"]
        }
        enforced_for = {
          "@@assign" = [
            "ec2:instance",
            "rds:db",
            "s3:bucket"
          ]
        }
      }
      Owner = {
        tag_key = {
          "@@assign" = "Owner"
        }
      }
      CostCenter = {
        tag_key = {
          "@@assign" = "CostCenter"
        }
        tag_value = {
          "@@assign" = ["engineering", "marketing", "operations"]
        }
      }
    }
  })
}
```

### Service Control Policies

```hcl
# Prevent disabling CloudTrail
resource "aws_organizations_policy" "prevent_cloudtrail_disable" {
  name    = "prevent-cloudtrail-disable"
  type    = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyCloudTrailDisable"
        Effect   = "Deny"
        Action   = [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging"
        ]
        Resource = "*"
      }
    ]
  })
}

# Require encryption
resource "aws_organizations_policy" "require_encryption" {
  name    = "require-encryption"
  type    = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyUnencryptedS3"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "*"
        Condition = {
          Null = {
            "s3:x-amz-server-side-encryption" = "true"
          }
        }
      }
    ]
  })
}
```

## Team Boundaries

### Module Ownership

```
organization/
├── platform-team/           # Owns: core modules, shared infra
│   ├── modules/
│   │   ├── networking/
│   │   ├── security/
│   │   └── observability/
│   └── shared-infrastructure/
│       ├── dns/
│       └── logging/
│
├── team-payments/           # Owns: payments domain
│   ├── services/
│   │   ├── payments-api/
│   │   └── payments-worker/
│   └── infrastructure/
│       └── payments-specific/
│
└── team-users/              # Owns: user domain
    ├── services/
    └── infrastructure/
```

### CODEOWNERS

```
# .github/CODEOWNERS

# Platform team owns core modules
/modules/networking/    @org/platform-team
/modules/security/      @org/platform-team
/modules/observability/ @org/platform-team

# Team-specific ownership
/teams/payments/        @org/payments-team
/teams/users/           @org/users-team

# Require platform review for shared infra
/shared-infrastructure/ @org/platform-team
```

### Access Control

```hcl
# Per-team IAM role
resource "aws_iam_role" "team_role" {
  for_each = toset(["payments", "users", "platform"])

  name = "team-${each.key}-terraform"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/Team" = each.key
          }
        }
      }
    ]
  })
}

# Team-scoped permissions
resource "aws_iam_role_policy" "team_policy" {
  for_each = toset(["payments", "users"])

  name = "team-${each.key}-policy"
  role = aws_iam_role.team_role[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["*"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Team" = each.key
          }
        }
      }
    ]
  })
}
```

## Blast Radius Reduction

### State Isolation by Domain

```
infrastructure/
├── networking/          # Separate state
│   └── backend.tf       # s3://state/networking/
├── security/            # Separate state
│   └── backend.tf       # s3://state/security/
├── platform/            # Separate state
│   └── backend.tf       # s3://state/platform/
└── teams/
    ├── payments/        # Separate state per team
    │   └── backend.tf   # s3://state/teams/payments/
    └── users/
        └── backend.tf   # s3://state/teams/users/
```

### Dependency Order

```hcl
# Define explicit dependencies
locals {
  layer_order = {
    1 = ["networking"]           # First: VPCs, subnets
    2 = ["security"]             # Second: IAM, security groups
    3 = ["platform"]             # Third: shared services
    4 = ["teams/*"]              # Last: team workloads
  }
}
```

### Change Windows

```hcl
# Restrict prod changes to maintenance windows
variable "allow_changes" {
  type    = bool
  default = false
}

resource "aws_instance" "critical" {
  count = var.allow_changes || var.environment != "prod" ? 1 : 0

  # ...

  lifecycle {
    prevent_destroy = var.environment == "prod"
  }
}
```

## Multi-Account Strategy

### Organization Structure

```
Organization Root
├── Core OU
│   ├── Management Account (billing, org management)
│   ├── Audit Account (CloudTrail, Config)
│   └── Log Archive Account (centralized logs)
│
├── Infrastructure OU
│   ├── Network Account (Transit Gateway, DNS)
│   └── Shared Services Account (CI/CD, artifacts)
│
├── Workloads OU
│   ├── Dev OU
│   │   ├── Team-Payments-Dev
│   │   └── Team-Users-Dev
│   ├── Staging OU
│   │   ├── Team-Payments-Staging
│   │   └── Team-Users-Staging
│   └── Prod OU
│       ├── Team-Payments-Prod
│       └── Team-Users-Prod
│
└── Sandbox OU
    └── Developer Sandboxes
```

### Cross-Account Access

```hcl
# In workload account
provider "aws" {
  alias  = "network"
  region = "us-east-1"

  assume_role {
    role_arn = "arn:aws:iam::NETWORK_ACCOUNT:role/TerraformCrossAccount"
  }
}

# Read VPC from network account
data "aws_vpc" "shared" {
  provider = aws.network

  tags = {
    Name = "shared-vpc"
  }
}
```

## Enterprise Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| Single account | No isolation | Multi-account strategy |
| No CODEOWNERS | Unclear ownership | Define ownership |
| Shared state all teams | Blast radius | Isolate by domain |
| Manual provisioning | Inconsistent | Self-service platform |
| No tag enforcement | Cost chaos | Tag policies + SCPs |
| Team silos | Duplication | Platform modules |
| No guardrails | Security risks | SCPs + Sentinel |
