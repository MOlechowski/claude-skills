# Migration Patterns

## Contents
- [Manual to IAC](#manual-to-iac) - Discovery, import workflow, bulk import
- [Tool-to-Tool Migration](#tool-to-tool-migration) - CFN to TF, TF to OpenTofu, TF to Pulumi
- [Modernization Patterns](#modernization-patterns) - Monolith to modular, single to split state
- [Version Upgrades](#version-upgrades) - Terraform version, provider upgrades
- [Migration Anti-patterns](#migration-anti-patterns) - Common mistakes

## Manual to IAC

### Discovery Phase

```bash
# AWS: List all resources
aws resourcegroupstaggingapi get-resources --region us-east-1

# List specific resource types
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,Tags]'
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,DBInstanceClass]'
aws s3 ls
```

### Import Workflow

```bash
# 1. Write resource configuration (empty or minimal)
cat > main.tf << 'EOF'
resource "aws_instance" "web" {
  # Will be populated after import
}
EOF

# 2. Import the resource
terraform import aws_instance.web i-1234567890abcdef0

# 3. Generate configuration from state
terraform show -no-color > imported.tf

# 4. Clean up generated config, add variables

# 5. Plan to verify no changes
terraform plan  # Should show "No changes"
```

### Terraform 1.5+ Import Blocks

```hcl
# import.tf
import {
  to = aws_instance.web
  id = "i-1234567890abcdef0"
}

import {
  to = aws_vpc.main
  id = "vpc-abc123"
}

import {
  to = aws_subnet.private[0]
  id = "subnet-def456"
}
```

```bash
# Generate configuration
terraform plan -generate-config-out=generated.tf

# Review and clean up generated.tf
# Then apply
terraform apply
```

### Bulk Import Script

```bash
#!/bin/bash
# import_ec2.sh

# Get all instance IDs
instances=$(aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].InstanceId' \
  --output text)

index=0
for id in $instances; do
  echo "Importing $id as aws_instance.imported[$index]"
  terraform import "aws_instance.imported[$index]" "$id"
  ((index++))
done
```

### Import Checklist

- [ ] Inventory all resources to import
- [ ] Check for dependencies (VPC before subnets)
- [ ] Plan import order (networking → compute → database)
- [ ] Write minimal config stubs
- [ ] Import each resource
- [ ] Generate/update configuration
- [ ] Remove hardcoded values
- [ ] Add variables and outputs
- [ ] Verify with `terraform plan`

## Tool-to-Tool Migration

### CloudFormation to Terraform

```bash
# 1. Export CloudFormation resources
aws cloudformation describe-stack-resources \
  --stack-name my-stack \
  --query 'StackResources[*].[ResourceType,PhysicalResourceId]'

# 2. Map CFN types to Terraform types
# AWS::EC2::Instance → aws_instance
# AWS::S3::Bucket → aws_s3_bucket

# 3. Import each resource
terraform import aws_instance.web i-1234567890abcdef0
terraform import aws_s3_bucket.data my-bucket-name
```

### CloudFormation to CDK

```bash
# Use cdk migrate (CDK 2.50+)
cdk migrate --stack-name my-stack --from-stack

# Or from template file
cdk migrate --stack-name my-stack --from-path template.yaml
```

### Terraform to OpenTofu

```bash
# 1. Replace terraform binary with tofu
# OpenTofu is drop-in compatible

# 2. Reinitialize
tofu init -upgrade

# 3. Verify state compatibility
tofu plan

# 4. Update CI/CD pipelines
# hashicorp/setup-terraform → opentofu/setup-opentofu
```

### Terraform to Pulumi

```bash
# 1. Install Pulumi
curl -fsSL https://get.pulumi.com | sh

# 2. Convert HCL to Pulumi (TypeScript)
pulumi convert --from terraform --language typescript

# 3. Or import from state
pulumi import --from terraform ./terraform.tfstate

# 4. Review and adjust generated code
```

### Migration Matrix

| From | To | Approach | Difficulty |
|------|-----|----------|------------|
| CFN | Terraform | Import by resource | Medium |
| CFN | CDK | `cdk migrate` | Low |
| Terraform | OpenTofu | Drop-in replace | Very Low |
| Terraform | Pulumi | `pulumi convert` | Medium |
| Pulumi | Terraform | Manual rewrite | High |
| Manual | Any | Import resources | High |

## Modernization Patterns

### Monolith to Modular

**Before:**
```
infrastructure/
└── main.tf  # 2000 lines, all resources
```

**After:**
```
infrastructure/
├── modules/
│   ├── networking/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── compute/
│   └── database/
├── environments/
│   ├── dev/
│   ├── staging/
│   └── prod/
└── main.tf  # Calls modules
```

**Migration Steps:**

1. Identify logical groupings
2. Create module structure
3. Move resources to modules
4. Update state with `terraform state mv`
5. Create module interfaces (variables/outputs)
6. Wire modules together

```bash
# Move resources to module
terraform state mv aws_vpc.main module.networking.aws_vpc.main
terraform state mv aws_subnet.private module.networking.aws_subnet.private
```

### Single State to Split

**Before:**
```
terraform.tfstate  # Contains everything
```

**After:**
```
networking/terraform.tfstate
compute/terraform.tfstate
database/terraform.tfstate
```

**Migration Steps:**

```bash
# 1. Pull current state
terraform state pull > full-state.json

# 2. Create new state files for each component
cd networking
terraform init
terraform state push ../full-state.json

# 3. Remove unrelated resources from each state
terraform state rm module.compute
terraform state rm module.database

# 4. Repeat for compute and database directories
```

### Legacy Patterns to Modern

| Legacy Pattern | Modern Pattern | Migration |
|---------------|----------------|-----------|
| Hardcoded values | Variables + tfvars | Extract to variables |
| Copy-paste modules | Versioned registry | Publish to registry |
| Local state | Remote state | `terraform state push` |
| No workspaces | Workspace/directory | Restructure |
| count | for_each | Careful state moves |

### Count to For Each

```hcl
# Before
resource "aws_subnet" "private" {
  count = 3
  cidr_block = "10.0.${count.index}.0/24"
}

# After
resource "aws_subnet" "private" {
  for_each = toset(["a", "b", "c"])
  cidr_block = "10.0.${index(["a", "b", "c"], each.key)}.0/24"
}
```

State migration:
```bash
terraform state mv 'aws_subnet.private[0]' 'aws_subnet.private["a"]'
terraform state mv 'aws_subnet.private[1]' 'aws_subnet.private["b"]'
terraform state mv 'aws_subnet.private[2]' 'aws_subnet.private["c"]'
```

## Version Upgrades

### Terraform Version Upgrade

```bash
# 1. Check current version constraints
grep -r "required_version" .

# 2. Update version constraints
terraform {
  required_version = ">= 1.6.0"
}

# 3. Upgrade state format
terraform init -upgrade

# 4. Plan and review
terraform plan
```

### Provider Version Upgrade

```hcl
# 1. Check current version
terraform providers

# 2. Update version constraint
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"  # Upgrade from 4.x
    }
  }
}

# 3. Upgrade and apply
terraform init -upgrade
terraform plan  # Review for breaking changes
```

### Breaking Changes Checklist

- [ ] Read provider changelog
- [ ] Check deprecated resources/arguments
- [ ] Test in non-prod environment first
- [ ] Update resource configurations
- [ ] Run plan to verify

## Migration Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| Big bang migration | High risk | Incremental approach |
| No state backup | Can't recover | Backup before changes |
| Skipping plan | Unexpected changes | Always plan first |
| Manual state edits | Corruption | Use state commands |
| Ignoring dependencies | Import failures | Map dependencies first |
| No testing | Broken infrastructure | Test in lower env |
