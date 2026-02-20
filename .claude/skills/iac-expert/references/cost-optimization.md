# Cost Optimization

## Contents
- [Infracost Integration](#infracost-integration) - Installation, usage, CI/CD
- [Tagging Strategy](#tagging-strategy) - Required tags, enforcement, cost allocation
- [Right-Sizing](#right-sizing) - Instance selection, auto scaling
- [Reserved/Savings Plans](#reservedsavings-plans) - Recommendations, coverage tracking
- [Budget Alerts](#budget-alerts) - Monthly budget, service-specific
- [Spot Instances](#spot-instances) - Mixed instances, spot fleet
- [Storage Optimization](#storage-optimization) - S3 lifecycle, EBS optimization
- [Cost Anti-patterns](#cost-anti-patterns) - Common mistakes

## Infracost Integration

### Installation

```bash
# macOS
brew install infracost

# Linux
curl -fsSL https://raw.githubusercontent.com/infracost/infracost/master/scripts/install.sh | sh

# Register for free API key
infracost auth login
```

### Basic Usage

```bash
# Breakdown by resource
infracost breakdown --path .

# Diff between branches
git checkout main
infracost breakdown --path . --format json --out-file main.json

git checkout feature-branch
infracost diff --path . --compare-to main.json
```

### CI/CD Integration

```yaml
name: Infracost
on: [pull_request]

jobs:
  infracost:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Infracost
        uses: infracost/actions/setup@v2
        with:
          api-key: ${{ secrets.INFRACOST_API_KEY }}

      - name: Checkout base branch
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.ref }}
          path: base

      - name: Generate Infracost cost estimate baseline
        run: |
          infracost breakdown --path base \
            --format json \
            --out-file /tmp/infracost-base.json

      - name: Checkout PR branch
        uses: actions/checkout@v4
        with:
          path: pr

      - name: Generate Infracost diff
        run: |
          infracost diff --path pr \
            --format json \
            --compare-to /tmp/infracost-base.json \
            --out-file /tmp/infracost.json

      - name: Post Infracost comment
        uses: infracost/actions/comment@v1
        with:
          path: /tmp/infracost.json
          behavior: update
```

## Tagging Strategy

### Required Tags

```hcl
variable "required_tags" {
  type = object({
    Environment = string
    Owner       = string
    CostCenter  = string
    Project     = string
    ManagedBy   = string
  })
}

locals {
  common_tags = merge(var.required_tags, {
    ManagedBy = "terraform"
  })
}

resource "aws_instance" "web" {
  # ...
  tags = merge(local.common_tags, {
    Name = "web-server"
  })
}
```

### Tag Enforcement with Policy

```hcl
# AWS Config rule
resource "aws_config_config_rule" "required_tags" {
  name = "required-tags"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "Environment"
    tag2Key   = "Owner"
    tag3Key   = "CostCenter"
  })
}

# SCP for tag enforcement
data "aws_iam_policy_document" "require_tags" {
  statement {
    sid       = "DenyUntaggedResources"
    effect    = "Deny"
    actions   = ["ec2:RunInstances"]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/CostCenter"
      values   = ["true"]
    }
  }
}
```

### Tag-Based Cost Allocation

```hcl
# Enable cost allocation tags
resource "aws_ce_cost_allocation_tag" "environment" {
  tag_key = "Environment"
  status  = "Active"
}

resource "aws_ce_cost_allocation_tag" "cost_center" {
  tag_key = "CostCenter"
  status  = "Active"
}
```

## Right-Sizing

### Instance Selection

```hcl
variable "workload_type" {
  type = string
  validation {
    condition     = contains(["compute", "memory", "general"], var.workload_type)
    error_message = "Workload type must be compute, memory, or general."
  }
}

locals {
  instance_families = {
    compute = "c6i"
    memory  = "r6i"
    general = "m6i"
  }

  instance_sizes = {
    dev     = "medium"
    staging = "large"
    prod    = "xlarge"
  }

  instance_type = "${local.instance_families[var.workload_type]}.${local.instance_sizes[var.environment]}"
}
```

### Auto Scaling

```hcl
resource "aws_autoscaling_policy" "scale_down" {
  name                   = "scale-down"
  autoscaling_group_name = aws_autoscaling_group.main.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = -1
  cooldown               = 300
}

resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "low-cpu-utilization"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 20
  alarm_actions       = [aws_autoscaling_policy.scale_down.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.main.name
  }
}
```

## Reserved/Savings Plans

### Recommendations Module

```hcl
# Get RI recommendations
data "aws_ce_savings_plans_purchase_recommendation" "compute" {
  savings_plans_type = "COMPUTE_SP"
  term_in_years      = "ONE_YEAR"
  payment_option     = "NO_UPFRONT"
  lookback_period    = "SIXTY_DAYS"
}

output "savings_plan_recommendations" {
  value = data.aws_ce_savings_plans_purchase_recommendation.compute.savings_plans_purchase_recommendation_details
}
```

### Coverage Tracking

```hcl
resource "aws_budgets_budget" "ri_coverage" {
  name         = "ri-coverage"
  budget_type  = "RI_COVERAGE"
  limit_amount = "80"
  limit_unit   = "PERCENTAGE"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "LESS_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["finops@example.com"]
  }
}
```

## Budget Alerts

### Monthly Budget

```hcl
resource "aws_budgets_budget" "monthly" {
  name              = "monthly-budget"
  budget_type       = "COST"
  limit_amount      = "1000"
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2024-01-01_00:00"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Environment$prod"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = ["alerts@example.com"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["alerts@example.com"]
    subscriber_sns_topic_arns  = [aws_sns_topic.budget_alerts.arn]
  }
}
```

### Service-Specific Budget

```hcl
resource "aws_budgets_budget" "ec2" {
  name         = "ec2-budget"
  budget_type  = "COST"
  limit_amount = "500"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = ["Amazon Elastic Compute Cloud - Compute"]
  }
}
```

## Spot Instances

### Mixed Instances Policy

```hcl
resource "aws_autoscaling_group" "main" {
  name             = "main-asg"
  desired_capacity = 3
  max_size         = 10
  min_size         = 2

  mixed_instances_policy {
    instances_distribution {
      on_demand_base_capacity                  = 1
      on_demand_percentage_above_base_capacity = 25
      spot_allocation_strategy                 = "capacity-optimized"
    }

    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.main.id
        version            = "$Latest"
      }

      override {
        instance_type = "m6i.large"
      }
      override {
        instance_type = "m5.large"
      }
      override {
        instance_type = "m5a.large"
      }
    }
  }
}
```

### Spot Fleet

```hcl
resource "aws_spot_fleet_request" "workers" {
  iam_fleet_role                      = aws_iam_role.spot_fleet.arn
  spot_price                          = "0.03"
  target_capacity                     = 5
  terminate_instances_with_expiration = true

  launch_specification {
    instance_type = "m5.large"
    ami           = data.aws_ami.amazon_linux.id
    spot_price    = "0.03"
  }

  launch_specification {
    instance_type = "m5a.large"
    ami           = data.aws_ami.amazon_linux.id
    spot_price    = "0.028"
  }
}
```

## Storage Optimization

### S3 Lifecycle Rules

```hcl
resource "aws_s3_bucket_lifecycle_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}
```

### EBS Optimization

```hcl
# Use gp3 instead of gp2
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  type              = "gp3"
  iops              = 3000
  throughput        = 125

  tags = {
    Name = "data-volume"
  }
}
```

## Cost Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| No tagging | Can't allocate costs | Enforce tags |
| Over-provisioned | Paying for unused | Right-size, auto-scale |
| No lifecycle rules | Storage grows forever | Add S3 lifecycle |
| gp2 volumes | More expensive | Migrate to gp3 |
| On-demand only | Missing discounts | Use Savings Plans |
| No budget alerts | Surprise bills | Set up alerts |
| Unused EIPs | $3.65/month each | Release or attach |
| Idle resources | Paying for nothing | Scheduled shutdown |
