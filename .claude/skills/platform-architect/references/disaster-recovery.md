# Disaster Recovery

## Contents
- [State Recovery](#state-recovery) - Corruption, lost state, lock stuck, surgery
- [Infrastructure Recovery](#infrastructure-recovery) - Multi-region, failover, RTO/RPO
- [Backup Strategies](#backup-strategies) - State backup, database, EBS snapshots
- [Blast Radius Reduction](#blast-radius-reduction) - Protection, change windows, staged rollouts
- [Runbook Template](#runbook-template) - DR runbook example
- [DR Anti-patterns](#dr-anti-patterns) - Common mistakes

## State Recovery

### State Corruption

**Symptoms:**
- `terraform plan` shows unexpected destroys/creates
- State file is empty or malformed
- "Error loading state" messages

**Recovery from S3 Versioning:**

```bash
# List versions
aws s3api list-object-versions \
  --bucket terraform-state \
  --prefix prod/terraform.tfstate \
  --max-items 10

# Download previous version
aws s3api get-object \
  --bucket terraform-state \
  --key prod/terraform.tfstate \
  --version-id "VERSION_ID" \
  recovered-state.tfstate

# Verify recovered state
terraform show -state=recovered-state.tfstate

# Replace current state
terraform state push recovered-state.tfstate
```

### State File Lost

```bash
# Option 1: Restore from backup (if available)
terraform state push backup.tfstate

# Option 2: Rebuild from infrastructure
# Generate import blocks for all resources
terraform plan -generate-config-out=generated.tf

# Or manually import each resource
terraform import aws_vpc.main vpc-abc123
terraform import aws_subnet.private[0] subnet-def456
```

### State Lock Stuck

```bash
# Force unlock (use carefully)
terraform force-unlock LOCK_ID

# For DynamoDB locks, manually delete
aws dynamodb delete-item \
  --table-name terraform-locks \
  --key '{"LockID":{"S":"terraform-state/prod/terraform.tfstate"}}'
```

### State Surgery

```bash
# Remove resource from state (keep in cloud)
terraform state rm aws_instance.problematic

# Move resource between states
terraform state mv -state-out=other.tfstate \
  aws_instance.web aws_instance.web

# Rename resource
terraform state mv aws_instance.old aws_instance.new

# Pull state for manual inspection
terraform state pull > state.json
```

## Infrastructure Recovery

### Multi-Region Setup

```hcl
# Primary region
provider "aws" {
  alias  = "primary"
  region = "us-east-1"
}

# DR region
provider "aws" {
  alias  = "dr"
  region = "us-west-2"
}

# Cross-region RDS replica
resource "aws_db_instance" "primary" {
  provider             = aws.primary
  identifier           = "prod-db-primary"
  engine               = "postgres"
  instance_class       = "db.r5.large"
  backup_retention_period = 7
}

resource "aws_db_instance" "replica" {
  provider             = aws.dr
  identifier           = "prod-db-replica"
  replicate_source_db  = aws_db_instance.primary.arn
  instance_class       = "db.r5.large"
}

# S3 cross-region replication
resource "aws_s3_bucket_replication_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  role   = aws_iam_role.replication.arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.data_dr.arn
      storage_class = "STANDARD"
    }
  }
}
```

### Failover Patterns

```hcl
# Route 53 failover
resource "aws_route53_health_check" "primary" {
  fqdn              = aws_lb.primary.dns_name
  port              = 443
  type              = "HTTPS"
  resource_path     = "/health"
  failure_threshold = 3
  request_interval  = 30
}

resource "aws_route53_record" "app" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "app.example.com"
  type    = "A"

  failover_routing_policy {
    type = "PRIMARY"
  }

  set_identifier  = "primary"
  health_check_id = aws_route53_health_check.primary.id

  alias {
    name                   = aws_lb.primary.dns_name
    zone_id                = aws_lb.primary.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "app_dr" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "app.example.com"
  type    = "A"

  failover_routing_policy {
    type = "SECONDARY"
  }

  set_identifier = "secondary"

  alias {
    name                   = aws_lb.dr.dns_name
    zone_id                = aws_lb.dr.zone_id
    evaluate_target_health = true
  }
}
```

### RTO/RPO Strategies

| Strategy | RTO | RPO | Cost | Use Case |
|----------|-----|-----|------|----------|
| Backup & Restore | Hours | Hours | Low | Dev, non-critical |
| Pilot Light | Minutes-Hours | Minutes | Medium | Staging, cost-sensitive |
| Warm Standby | Minutes | Seconds | High | Production |
| Multi-Site Active | Seconds | Near-zero | Very High | Mission critical |

### Pilot Light Pattern

```hcl
# DR region: minimal footprint
module "dr_core" {
  source = "./modules/core-infrastructure"
  providers = {
    aws = aws.dr
  }

  environment = "dr"

  # Minimal sizing
  db_instance_class = "db.t3.medium"  # Can be scaled up
  asg_min_size      = 0               # No running instances
  asg_max_size      = 10              # Can scale when activated
}

# Scaling script for DR activation
# dr_activate.sh
# aws autoscaling update-auto-scaling-group \
#   --auto-scaling-group-name dr-asg \
#   --min-size 2 --desired-capacity 4
```

## Backup Strategies

### Automated State Backup

```hcl
# S3 versioning for state bucket
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle rule for version retention
resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "state-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}
```

### Database Backups

```hcl
resource "aws_db_instance" "main" {
  identifier = "prod-db"

  # Automated backups
  backup_retention_period = 30
  backup_window           = "03:00-04:00"

  # Enable deletion protection
  deletion_protection = true

  # Point-in-time recovery
  copy_tags_to_snapshot = true
}

# Manual snapshot before major changes
resource "aws_db_snapshot" "before_migration" {
  db_instance_identifier = aws_db_instance.main.identifier
  db_snapshot_identifier = "before-migration-${formatdate("YYYY-MM-DD", timestamp())}"
}
```

### EBS Snapshots

```hcl
# DLM lifecycle policy
resource "aws_dlm_lifecycle_policy" "ebs_backup" {
  description        = "EBS backup policy"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]

    schedule {
      name = "Daily snapshots"

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["03:00"]
      }

      retain_rule {
        count = 14
      }

      tags_to_add = {
        SnapshotType = "DLM"
      }
    }

    target_tags = {
      Backup = "true"
    }
  }
}
```

## Blast Radius Reduction

### Resource Protection

```hcl
resource "aws_instance" "critical" {
  # ...

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_db_instance" "production" {
  deletion_protection = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "data" {
  # ...
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}
```

### Change Windows

```hcl
variable "maintenance_mode" {
  type        = bool
  default     = false
  description = "Set to true during maintenance windows"
}

resource "aws_instance" "critical" {
  # Only allow changes during maintenance
  lifecycle {
    ignore_changes = var.maintenance_mode ? [] : all
  }
}
```

### Staged Rollouts

```hcl
# Canary deployment
resource "aws_autoscaling_group" "canary" {
  name                = "app-canary"
  desired_capacity    = 1
  max_size            = 1
  min_size            = 1
  launch_template {
    id      = aws_launch_template.new_version.id
    version = "$Latest"
  }
}

resource "aws_autoscaling_group" "main" {
  name                = "app-main"
  desired_capacity    = 10
  max_size            = 20
  min_size            = 5
  launch_template {
    id      = aws_launch_template.current_version.id
    version = "$Latest"
  }
}
```

## Runbook Template

```markdown
# DR Runbook: Database Failover

## Trigger Conditions
- Primary database unreachable for > 5 minutes
- Primary region experiencing outage
- Manual failover requested

## Steps

### 1. Assess Situation (5 min)
- [ ] Confirm primary database is unreachable
- [ ] Check AWS Health Dashboard
- [ ] Notify on-call team

### 2. Promote DR Replica (10 min)
- [ ] Run: `aws rds promote-read-replica --db-instance-identifier prod-db-replica`
- [ ] Wait for instance to become available
- [ ] Verify: `aws rds describe-db-instances --db-instance-identifier prod-db-replica`

### 3. Update DNS (5 min)
- [ ] Update Route 53 to point to DR database
- [ ] Or: Failover happens automatically if health checks configured

### 4. Update Application Config (5 min)
- [ ] Update SSM Parameter: `/prod/database/endpoint`
- [ ] Restart application services or wait for config refresh

### 5. Verify (10 min)
- [ ] Test application connectivity
- [ ] Check error rates in monitoring
- [ ] Verify data integrity

### 6. Communication
- [ ] Update status page
- [ ] Notify stakeholders

## Rollback
To return to primary after recovery:
1. Resync data to primary
2. Update DNS back to primary
3. Demote DR instance back to replica
```

## DR Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| No state backups | Can't recover state | Enable S3 versioning |
| Single region | No failover option | Multi-region setup |
| Untested DR | Won't work when needed | Regular DR drills |
| No runbooks | Panic during outage | Document procedures |
| No deletion protection | Accidental deletes | Enable protection |
| No monitoring | Miss failures | Set up health checks |
