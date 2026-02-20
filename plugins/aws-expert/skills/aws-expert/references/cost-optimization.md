# AWS Cost Optimization

Strategies for reducing AWS costs while maintaining performance and reliability.

## Pricing Models

### Comparison Matrix

| Model | Commitment | Discount | Best For |
|-------|------------|----------|----------|
| On-Demand | None | 0% | Variable, unpredictable workloads |
| Savings Plans (Compute) | 1 or 3 years | Up to 66% | Diverse compute usage |
| Savings Plans (EC2 Instance) | 1 or 3 years | Up to 72% | Specific instance family |
| Reserved Instances | 1 or 3 years | Up to 72% | Steady-state, predictable |
| Spot Instances | None | Up to 90% | Fault-tolerant, flexible |

### Savings Plans vs Reserved Instances

| Aspect | Savings Plans | Reserved Instances |
|--------|---------------|-------------------|
| Flexibility | Region, instance type, OS | Fixed attributes |
| Coverage | EC2, Fargate, Lambda | EC2 only (Standard) |
| Payment | All upfront, partial, no upfront | All upfront, partial, no upfront |
| Term | 1 or 3 years | 1 or 3 years |
| Modification | Automatic across eligible usage | Manual exchange/modification |
| Best For | Diverse workloads, growth | Stable, known requirements |

### When to Use Each

```
┌─────────────────────────────────────────────────┐
│      Is the workload predictable?               │
└─────────────────────┬───────────────────────────┘
                      │
         ┌────────────┴────────────┐
         │ Yes                     │ No
         ▼                         ▼
┌─────────────────┐       ┌─────────────────┐
│ Will it run     │       │ Fault-tolerant? │
│ continuously?   │       └────────┬────────┘
└────────┬────────┘                │
         │                    ┌────┴────┐
    ┌────┴────┐               │ Yes     │ No
    │ Yes     │ No            ▼         ▼
    ▼         ▼         ┌─────────┐ ┌─────────┐
┌────────┐ ┌────────┐   │  Spot   │ │On-Demand│
│Savings │ │On-Demand│   └─────────┘ └─────────┘
│Plans/RI│ │         │
└────────┘ └─────────┘
```

---

## Compute Optimization

### Right-Sizing

**Use AWS Compute Optimizer:**
```bash
# Get recommendations
aws compute-optimizer get-ec2-instance-recommendations \
  --query 'instanceRecommendations[].{Instance:instanceArn,Current:currentInstanceType,Recommended:recommendationOptions[0].instanceType,Savings:recommendationOptions[0].projectedUtilizationMetrics}'
```

**Right-sizing checklist:**
- CPU utilization consistently < 40%: Downsize
- Memory utilization < 40%: Consider memory-optimized alternatives
- Network throughput unused: Use smaller instance type

### Spot Instance Strategies

**Use Cases:**
- Batch processing
- CI/CD workers
- Dev/test environments
- Stateless web servers behind ALB
- Containers on ECS/EKS

**Spot Best Practices:**
```
1. Diversify instance types (3+ types)
2. Diversify Availability Zones
3. Use Spot Fleet or ASG mixed instances
4. Set maximum price at On-Demand (avoid bidding wars)
5. Use interruption handlers
```

**EKS with Spot:**
```yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: my-cluster
  region: us-west-2

managedNodeGroups:
  - name: spot-workers
    instanceTypes: ["m5.large", "m5a.large", "m4.large"]
    spot: true
    minSize: 2
    desiredCapacity: 4
    maxSize: 10
```

**Spot interruption handling:**
```bash
# Check for interruption notice (2-minute warning)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/spot/termination-time
```

### Graviton (ARM) Migration

**Savings: 20-40% compared to equivalent Intel/AMD**

| Service | Graviton Instance |
|---------|-------------------|
| EC2 | m7g, c7g, r7g, t4g |
| RDS | db.m7g, db.r7g |
| ElastiCache | cache.m7g, cache.r7g |
| Lambda | arm64 architecture |

**Migration checklist:**
1. Verify software compatibility (most Linux workloads compatible)
2. Rebuild container images for arm64
3. Test performance
4. Gradual rollout

### Auto Scaling Optimization

**Target tracking for cost efficiency:**
```json
{
  "TargetTrackingScalingPolicyConfiguration": {
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ASGAverageCPUUtilization"
    },
    "ScaleInCooldown": 300,
    "ScaleOutCooldown": 60
  }
}
```

**Scheduled scaling for predictable patterns:**
```bash
aws autoscaling put-scheduled-update-group-action \
  --auto-scaling-group-name my-asg \
  --scheduled-action-name scale-down-night \
  --recurrence "0 20 * * *" \
  --desired-capacity 2

aws autoscaling put-scheduled-update-group-action \
  --auto-scaling-group-name my-asg \
  --scheduled-action-name scale-up-morning \
  --recurrence "0 8 * * 1-5" \
  --desired-capacity 10
```

---

## Storage Optimization

### S3 Cost Reduction

**Storage Class Optimization:**

| Monthly Access | Recommended Class |
|----------------|-------------------|
| > 1x per month | Standard |
| 1x per 1-3 months | Standard-IA |
| < 1x per 3 months | Glacier Instant Retrieval |
| Rarely, can wait | Glacier Flexible Retrieval |
| Compliance archive | Glacier Deep Archive |

**Lifecycle Policy:**
```json
{
  "Rules": [
    {
      "ID": "Move to IA then Glacier",
      "Status": "Enabled",
      "Filter": {},
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 90,
          "StorageClass": "GLACIER"
        }
      ],
      "Expiration": {
        "Days": 365
      }
    }
  ]
}
```

**Intelligent-Tiering:**
- Automatic movement between tiers
- No retrieval fees
- Small monitoring fee per object
- Best for unknown access patterns

### EBS Optimization

**Volume Type Selection:**
| Volume | $/GB/month | Use Case |
|--------|------------|----------|
| gp3 | $0.08 | General purpose (default) |
| gp2 | $0.10 | Legacy (migrate to gp3) |
| io2 | $0.125+ | High IOPS |
| st1 | $0.045 | Throughput (sequential) |
| sc1 | $0.015 | Cold storage |

**Cost reduction strategies:**
```bash
# Find unattached volumes
aws ec2 describe-volumes \
  --filters "Name=status,Values=available" \
  --query 'Volumes[].[VolumeId,Size,CreateTime]'

# Find old snapshots
aws ec2 describe-snapshots \
  --owner-ids self \
  --query 'Snapshots[?StartTime<`2023-01-01`].[SnapshotId,VolumeSize,StartTime]'
```

### Data Transfer Costs

**Cost Hierarchy:**
```
Free:  Same AZ, CloudFront to origin, S3 to CloudFront
Cheap: Cross-AZ within region ($0.01/GB)
Moderate: Cross-region ($0.02/GB)
Expensive: Internet egress ($0.09/GB first 10TB)
```

**Reduction Strategies:**
1. Use VPC endpoints (avoid NAT Gateway charges)
2. Use CloudFront for frequently accessed content
3. Compress data before transfer
4. Use S3 Transfer Acceleration for uploads
5. Consider Direct Connect for high-volume transfers

---

## Database Optimization

### RDS Cost Reduction

**Right-size instances:**
```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/RDS \
  --metric-name CPUUtilization \
  --dimensions Name=DBInstanceIdentifier,Value=my-db \
  --start-time $(date -d '7 days ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Average Maximum
```

**Reserved Instances for databases:**
- 1-year: ~30% savings
- 3-year: ~50% savings
- Consider multi-AZ requirements

**Aurora Serverless v2:**
- Pay for actual usage
- Scale to zero (0.5 ACU minimum)
- Good for variable workloads

### DynamoDB Optimization

**Capacity Modes:**

| Mode | Best For | Billing |
|------|----------|---------|
| On-Demand | Variable, unpredictable | Per-request |
| Provisioned | Consistent, predictable | Per-hour |
| Provisioned + Auto Scaling | Predictable with spikes | Per-hour |

**Cost reduction strategies:**
1. Use auto-scaling with provisioned capacity
2. Right-size partition keys (avoid hot partitions)
3. Use TTL for automatic expiration
4. Consider reserved capacity for steady usage

```bash
# Reserved capacity (1 year)
aws dynamodb purchase-reserved-capacity-offering \
  --reserved-capacity-offering-id xxx \
  --reserved-capacity-id my-reservation
```

### Caching Strategy

**ElastiCache ROI:**
```
Database read: $0.10 per 1M requests (RDS)
Cache read: $0.01 per 1M requests (ElastiCache)

If cache hit rate = 90%:
Cost with cache = (0.1 * $0.10) + (1.0 * $0.01) = $0.02
Cost without cache = 1.0 * $0.10 = $0.10
Savings = 80%
```

---

## Serverless Optimization

### Lambda Cost Reduction

**Memory optimization:**
```
Lower memory = Lower cost per ms
Higher memory = Faster execution = Lower duration cost

Find the sweet spot using AWS Lambda Power Tuning
```

**Best practices:**
1. Minimize cold starts (smaller packages, provisioned concurrency)
2. Use ARM architecture (20% cheaper)
3. Optimize function duration
4. Use reserved concurrency to limit costs

**Cost calculation:**
```
Cost = Requests × $0.20/1M + Duration × $0.0000166667/GB-second

1M requests, 1GB, 200ms average:
= (1M × $0.20/1M) + (1M × 0.2s × 1GB × $0.0000166667)
= $0.20 + $3.33 = $3.53
```

### API Gateway Optimization

**HTTP API vs REST API:**
| Feature | HTTP API | REST API |
|---------|----------|----------|
| Price | $1.00/million | $3.50/million |
| Features | Basic | Full (caching, WAF, etc.) |
| Performance | Faster | More features |

**Use HTTP API when:**
- Simple proxy to Lambda/HTTP
- Don't need API keys, caching, request/response transformation

### Fargate Optimization

**Spot Fargate:**
- Up to 70% savings
- Good for batch, non-critical workloads
- Requires interruption handling

```json
{
  "capacityProviderStrategy": [
    {
      "capacityProvider": "FARGATE_SPOT",
      "weight": 2,
      "base": 0
    },
    {
      "capacityProvider": "FARGATE",
      "weight": 1,
      "base": 1
    }
  ]
}
```

---

## Cost Monitoring & Governance

### Cost Allocation Tags

**Required tags:**
```json
{
  "TagPolicy": {
    "tags": {
      "Environment": {
        "tag_key": {
          "@@assign": "Environment"
        },
        "tag_value": {
          "@@assign": ["prod", "staging", "dev"]
        },
        "enforced_for": {
          "@@assign": ["ec2:instance", "rds:db"]
        }
      },
      "CostCenter": {
        "tag_key": {
          "@@assign": "CostCenter"
        }
      }
    }
  }
}
```

**Enable cost allocation tags:**
```bash
aws ce update-cost-allocation-tags-status \
  --cost-allocation-tags-status TagKey=Environment,Status=Active
```

### Budgets & Alerts

**Create budget with alert:**
```bash
aws budgets create-budget \
  --account-id 123456789012 \
  --budget '{
    "BudgetName": "monthly-total",
    "BudgetLimit": {"Amount": "1000", "Unit": "USD"},
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST"
  }' \
  --notifications-with-subscribers '[{
    "Notification": {
      "NotificationType": "ACTUAL",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 80,
      "ThresholdType": "PERCENTAGE"
    },
    "Subscribers": [{
      "SubscriptionType": "EMAIL",
      "Address": "team@example.com"
    }]
  }]'
```

### Cost Anomaly Detection

```bash
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "ServiceMonitor",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "SERVICE"
  }'

aws ce create-anomaly-subscription \
  --anomaly-subscription '{
    "SubscriptionName": "DailyAlerts",
    "Threshold": 100,
    "Frequency": "DAILY",
    "MonitorArnList": ["arn:aws:ce::123456789012:anomalymonitor/xxx"],
    "Subscribers": [{
      "Type": "EMAIL",
      "Address": "team@example.com"
    }]
  }'
```

---

## Quick Wins Checklist

### Immediate Actions (< 1 hour)

- [ ] Delete unattached EBS volumes
- [ ] Delete old snapshots
- [ ] Release unused Elastic IPs
- [ ] Stop idle development instances
- [ ] Review and right-size RDS instances
- [ ] Enable S3 Intelligent-Tiering for large buckets

### Short-term Actions (< 1 week)

- [ ] Migrate gp2 volumes to gp3
- [ ] Implement S3 lifecycle policies
- [ ] Purchase Savings Plans for steady workloads
- [ ] Enable Spot for dev/test environments
- [ ] Set up cost allocation tags
- [ ] Create budget alerts

### Medium-term Actions (< 1 month)

- [ ] Migrate to Graviton instances
- [ ] Implement auto-scaling for all workloads
- [ ] Review and optimize Lambda memory settings
- [ ] Implement caching (ElastiCache, CloudFront)
- [ ] Review data transfer patterns
- [ ] Set up Cost Anomaly Detection

---

## Service-Specific Tips

### EC2
- Use instance scheduler for dev/test
- Migrate to latest generation instances
- Use Spot for stateless workloads
- Right-size based on actual utilization

### S3
- Use lifecycle policies aggressively
- Enable Intelligent-Tiering
- Use S3 Select for partial object retrieval
- Compress objects before storing

### RDS
- Stop dev/test instances when not in use
- Use Aurora Serverless for variable workloads
- Right-size based on CloudWatch metrics
- Consider Reserved Instances for production

### Lambda
- Optimize memory settings
- Use ARM architecture
- Minimize package size
- Use Provisioned Concurrency only when needed

### CloudWatch
- Set appropriate log retention periods
- Use log class for infrequent access logs
- Optimize custom metric resolution
- Review and clean up unused dashboards

---

## Tools & Resources

| Tool | Purpose |
|------|---------|
| Cost Explorer | Visualize and analyze costs |
| Budgets | Set spending limits and alerts |
| Compute Optimizer | Right-sizing recommendations |
| Trusted Advisor | Cost optimization checks |
| Cost Anomaly Detection | Unusual spending alerts |
| Savings Plans | Purchase commitments |
| Reserved Instance Reporting | RI utilization tracking |
