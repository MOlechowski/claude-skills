# Troubleshooting

## Contents
- [Common Errors](#common-errors) - Provider, state, resource, plan/apply errors
- [Drift Detection](#drift-detection) - Manual, automated, resolving drift
- [Performance Issues](#performance-issues) - Slow plans, large state, rate limits
- [Debugging](#debugging) - Logging, state inspection, graph visualization
- [Recovery Procedures](#recovery-procedures) - Corrupt state, accidental destroy, provider issues
- [Troubleshooting Checklist](#troubleshooting-checklist) - Before asking for help
- [Anti-patterns](#anti-patterns) - Common mistakes

## Common Errors

### Provider Errors

**Error: No valid credential sources found**
```
Error: No valid credential sources found for AWS Provider.
```

Fix:
```bash
# Check credentials
aws sts get-caller-identity

# Set environment variables
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."

# Or use profile
export AWS_PROFILE=myprofile
```

**Error: Unauthorized operation**
```
Error: error creating EC2 Instance: UnauthorizedOperation
```

Fix:
```bash
# Check IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:role/TerraformRole \
  --action-names ec2:RunInstances

# Add missing permissions to IAM policy
```

### State Errors

**Error: State lock**
```
Error: Error acquiring the state lock
Lock Info:
  ID:        abc123
  Path:      terraform.tfstate
  Operation: OperationTypeApply
```

Fix:
```bash
# Check if another operation is running
# If stale, force unlock
terraform force-unlock abc123
```

**Error: State version mismatch**
```
Error: state snapshot was created by Terraform v1.6.0,
which is newer than current v1.5.0
```

Fix:
```bash
# Upgrade Terraform
brew upgrade terraform

# Or use tfenv
tfenv use 1.6.0
```

**Error: Resource not in state**
```
Error: Resource "aws_instance.web" not found in state
```

Fix:
```bash
# Import the resource
terraform import aws_instance.web i-1234567890abcdef0

# Or remove from config if it shouldn't exist
```

### Resource Errors

**Error: Resource already exists**
```
Error: error creating S3 Bucket: BucketAlreadyExists
```

Fix:
```bash
# Import existing resource
terraform import aws_s3_bucket.data existing-bucket-name

# Or use unique naming
resource "aws_s3_bucket" "data" {
  bucket = "${var.project}-${var.environment}-data-${random_id.suffix.hex}"
}
```

**Error: Dependency violation**
```
Error: error deleting Security Group: DependencyViolation
```

Fix:
```hcl
# Use depends_on to control order
resource "aws_security_group" "main" {
  # ...
}

resource "aws_instance" "web" {
  vpc_security_group_ids = [aws_security_group.main.id]
  # ...
}

# Delete instance before security group
# Or add lifecycle rule
lifecycle {
  create_before_destroy = true
}
```

### Plan/Apply Errors

**Error: Cycle detected**
```
Error: Cycle: module.a.output.id, module.b.var.a_id
```

Fix:
```hcl
# Break the cycle by using data sources or restructuring
# Option 1: Use data source instead of direct reference
data "aws_instance" "a" {
  instance_id = var.known_instance_id
}

# Option 2: Pass through root module
module "a" {
  source = "./a"
}

module "b" {
  source = "./b"
  a_id   = module.a.id  # Explicit dependency
}
```

**Error: Invalid count/for_each**
```
Error: Invalid count argument
  count = length(data.aws_availability_zones.available.names)
The "count" value depends on resource attributes that cannot be determined until apply
```

Fix:
```hcl
# Use static values or pre-known data
variable "availability_zones" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

resource "aws_subnet" "private" {
  count = length(var.availability_zones)
  # ...
}
```

## Drift Detection

### Manual Detection

```bash
# Detect drift
terraform plan -detailed-exitcode
# Exit 0: No changes
# Exit 1: Error
# Exit 2: Changes detected

# Refresh state from infrastructure
terraform refresh

# Or safer approach
terraform plan -refresh-only
terraform apply -refresh-only
```

### Automated Detection

```yaml
# GitHub Actions
name: Drift Detection
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  detect-drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3

      - name: Check for drift
        id: drift
        run: |
          terraform init
          terraform plan -detailed-exitcode
        continue-on-error: true

      - name: Alert on drift
        if: steps.drift.outcome == 'failure' && steps.drift.outputs.exitcode == '2'
        run: |
          # Send Slack/email notification
          echo "Drift detected!"
```

### Resolving Drift

```bash
# Option 1: Update infrastructure to match code
terraform apply

# Option 2: Update code to match infrastructure
terraform show > current-state.txt
# Edit .tf files to match current state
terraform plan  # Should show no changes

# Option 3: Import changed resources
terraform import aws_instance.web i-new-instance-id
```

## Performance Issues

### Slow Plans

**Causes:**
- Large state file
- Too many resources in one state
- Provider rate limiting
- Network latency

**Solutions:**

```bash
# Parallelize operations
terraform apply -parallelism=20

# Target specific resources
terraform plan -target=module.networking
terraform apply -target=aws_instance.web

# Split state
# Move resources to separate state files
terraform state mv module.database separate-database.tfstate
```

### Large State Files

```bash
# Check state size
ls -lh terraform.tfstate

# Remove old resources
terraform state rm aws_instance.deleted

# Compact state
terraform state pull > state.json
# Edit state.json to remove lineage history
terraform state push state.json
```

### Provider Rate Limits

```hcl
# Add retry configuration
provider "aws" {
  retry_mode  = "standard"
  max_retries = 5
}

# Reduce parallelism
# terraform apply -parallelism=5
```

## Debugging

### Enable Logging

```bash
# Trace-level logging
export TF_LOG=TRACE
terraform plan

# Log to file
export TF_LOG=DEBUG
export TF_LOG_PATH=terraform.log
terraform apply

# Provider-specific logging
export TF_LOG_PROVIDER=DEBUG
```

### Log Levels

| Level | Use Case |
|-------|----------|
| TRACE | Full protocol dumps |
| DEBUG | Detailed operations |
| INFO | General operations |
| WARN | Potential issues |
| ERROR | Failures only |

### State Inspection

```bash
# List all resources
terraform state list

# Show specific resource
terraform state show aws_instance.web

# Pull full state for inspection
terraform state pull > state.json
cat state.json | jq '.resources[] | select(.type == "aws_instance")'
```

### Graph Visualization

```bash
# Generate dependency graph
terraform graph | dot -Tpng > graph.png

# Filter to specific types
terraform graph -type=plan > plan-graph.dot
```

## Recovery Procedures

### Corrupt State Recovery

```bash
# 1. Stop all terraform operations

# 2. Restore from backup
aws s3api list-object-versions \
  --bucket terraform-state \
  --prefix prod/iac-terraform.tfstate

aws s3api get-object \
  --bucket terraform-state \
  --key prod/iac-terraform.tfstate \
  --version-id "VERSION_ID" \
  recovered.tfstate

# 3. Push recovered state
terraform state push recovered.tfstate

# 4. Verify
terraform plan
```

### Accidental Destroy Recovery

```bash
# 1. Check if resources still exist
aws ec2 describe-instances --instance-ids i-destroyed

# 2. If yes, import back
terraform import aws_instance.web i-destroyed

# 3. If no, recreate
terraform apply
```

### Provider Upgrade Issues

```bash
# Downgrade provider
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 4.67.0"  # Pin to working version
    }
  }
}

terraform init -upgrade

# Check for breaking changes
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/version-5-upgrade
```

## Troubleshooting Checklist

### Before Asking for Help

- [ ] Read the full error message
- [ ] Check terraform version: `terraform version`
- [ ] Check provider versions: `terraform providers`
- [ ] Try with debug logging: `TF_LOG=DEBUG terraform plan`
- [ ] Search provider issues on GitHub
- [ ] Check if it's a known issue in changelog

### Information to Gather

```bash
# Version info
terraform version

# Provider versions
terraform providers

# Configuration summary
tree -L 2

# Sanitized error log
TF_LOG=DEBUG terraform plan 2>&1 | grep -v "secret\|password\|key"
```

## Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| Ignoring warnings | Future errors | Address warnings |
| No logging | Hard to debug | Enable TF_LOG |
| No drift detection | Silent changes | Schedule checks |
| Force unlock without checking | State corruption | Verify lock first |
| Skip plan | Unexpected changes | Always plan |
| No state backups | Can't recover | Enable versioning |
