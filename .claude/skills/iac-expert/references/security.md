# Security Patterns

## Contents
- [Policy as Code](#policy-as-code) - OPA, Sentinel, Checkov, tfsec
- [Secrets Management](#secrets-management) - Vault, AWS Secrets Manager, SOPS
- [Compliance Frameworks](#compliance-frameworks) - SOC 2, HIPAA, PCI-DSS patterns
- [IAM Best Practices](#iam-best-practices) - Least privilege, conditions
- [Network Security](#network-security) - VPC, flow logs, NACLs
- [Security Anti-patterns](#security-anti-patterns) - Common mistakes

## Policy as Code

### OPA (Open Policy Agent)

```rego
# policy/iac-terraform.rego
package terraform

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group_rule"
  resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
  resource.change.after.type == "ingress"
  msg := sprintf("Security group %s allows ingress from 0.0.0.0/0", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  not resource.change.after.server_side_encryption_configuration
  msg := sprintf("S3 bucket %s missing encryption", [resource.address])
}
```

Usage:
```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
opa eval --data policy/ --input plan.json "data.terraform.deny"
```

### Sentinel (Terraform Cloud/Enterprise)

```sentinel
# require-tags.sentinel
import "tfplan/v2" as tfplan

required_tags = ["Environment", "Owner", "CostCenter"]

main = rule {
  all tfplan.resource_changes as _, rc {
    rc.type == "aws_instance" implies
      all required_tags as tag {
        rc.change.after.tags contains tag
      }
  }
}
```

### Checkov

```bash
# Scan directory
checkov -d terraform/

# Scan plan file
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
checkov -f plan.json

# Skip specific checks
checkov -d terraform/ --skip-check CKV_AWS_18,CKV_AWS_21
```

Common checks:
| Check ID | Description |
|----------|-------------|
| CKV_AWS_18 | S3 bucket logging |
| CKV_AWS_19 | S3 bucket encryption |
| CKV_AWS_21 | S3 bucket versioning |
| CKV_AWS_23 | Security group description |
| CKV_AWS_24 | Security group open to 0.0.0.0/0 |

### tfsec

```bash
# Scan directory
tfsec terraform/

# Output as SARIF for GitHub
tfsec terraform/ --format sarif > results.sarif

# Custom severity threshold
tfsec terraform/ --minimum-severity HIGH
```

## Secrets Management

### HashiCorp Vault

```hcl
# Provider configuration
provider "vault" {
  address = "https://vault.example.com"
}

# Read secret
data "vault_generic_secret" "db" {
  path = "secret/data/prod/database"
}

resource "aws_db_instance" "main" {
  username = data.vault_generic_secret.db.data["username"]
  password = data.vault_generic_secret.db.data["password"]
}
```

### AWS Secrets Manager

```hcl
data "aws_secretsmanager_secret_version" "db" {
  secret_id = "prod/database/credentials"
}

locals {
  db_creds = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)
}

resource "aws_db_instance" "main" {
  username = local.db_creds["username"]
  password = local.db_creds["password"]
}
```

### SOPS with Terraform

```yaml
# secrets.yaml (encrypted)
db_password: ENC[AES256_GCM,data:...,type:str]
api_key: ENC[AES256_GCM,data:...,type:str]
sops:
  kms:
    - arn: arn:aws:kms:us-east-1:123456789:key/abc123
```

```hcl
data "sops_file" "secrets" {
  source_file = "secrets.yaml"
}

resource "aws_db_instance" "main" {
  password = data.sops_file.secrets.data["db_password"]
}
```

### Environment Variables

```bash
# Export before running terraform
export TF_VAR_db_password="secret123"

# In variables.tf
variable "db_password" {
  type      = string
  sensitive = true
}
```

## Compliance Frameworks

### SOC 2 Patterns

```hcl
# Encryption at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.this.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# Access logging
resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.this.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/"
}

# Versioning for audit trail
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

### HIPAA Patterns

```hcl
# KMS with key rotation
resource "aws_kms_key" "hipaa" {
  description             = "HIPAA-compliant encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

# CloudTrail for audit logging
resource "aws_cloudtrail" "hipaa" {
  name                          = "hipaa-audit-trail"
  s3_bucket_name                = aws_s3_bucket.audit.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.hipaa.arn
}
```

### PCI-DSS Patterns

```hcl
# Network segmentation
resource "aws_subnet" "cardholder" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.100.0/24"

  tags = {
    Name       = "cardholder-data-subnet"
    Compliance = "PCI-DSS"
    Zone       = "CDE"
  }
}

# Security group - restrict access
resource "aws_security_group" "cardholder" {
  name        = "cardholder-data-sg"
  description = "PCI-DSS compliant security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow from bastion only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    description = "Deny all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = []
  }
}
```

## IAM Best Practices

### Least Privilege

```hcl
# Specific actions, not wildcard
resource "aws_iam_policy" "s3_read" {
  name = "s3-read-specific"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
      }
    ]
  })
}
```

### Conditions

```hcl
resource "aws_iam_policy" "mfa_required" {
  name = "require-mfa"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
}
```

## Network Security

### VPC Security

```hcl
# Flow logs
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

# NACL for subnet-level filtering
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 443
    to_port    = 443
  }

  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }
}
```

## Security Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| `*` in IAM actions | Over-permissive | Specific actions |
| Secrets in .tf files | Exposed in git | Use secrets manager |
| 0.0.0.0/0 ingress | Open to internet | Restrict CIDR |
| Unencrypted storage | Data exposure | Enable encryption |
| No MFA enforcement | Weak auth | Require MFA |
| Public S3 buckets | Data leak | Block public access |
| Hardcoded credentials | Security breach | Use IAM roles |
| No audit logging | No visibility | Enable CloudTrail |
