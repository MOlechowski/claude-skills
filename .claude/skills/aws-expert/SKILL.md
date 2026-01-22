---
name: aws-expert
description: "AWS architecture expertise: Well-Architected Framework (6 pillars), service selection, security (IAM, encryption, VPC), cost optimization (Reserved/Savings Plans/Spot), DR/HA patterns, observability. Use for: architecture decisions, choosing AWS services, security best practices, cost optimization, multi-region design. Triggers: aws architecture, well-architected, which aws service, aws security, aws cost, multi-region, disaster recovery."
---

# AWS Expert

Domain expertise for AWS architecture decisions, service selection, and best practices.

For CLI implementation, see: `aws-cli` skill.
For IaC implementation, see: `terraform` or `tofu` skills.

## Well-Architected Framework Overview

AWS Well-Architected Framework provides architectural best practices across six pillars:

| Pillar | Focus | Key Questions |
|--------|-------|---------------|
| Operational Excellence | Run and monitor systems | How do you respond to events? |
| Security | Protect data and systems | How do you manage identities? |
| Reliability | Recover from failures | How do you handle change? |
| Performance Efficiency | Use resources efficiently | How do you select resources? |
| Cost Optimization | Avoid unnecessary costs | How do you manage demand? |
| Sustainability | Minimize environmental impact | How do you reduce impact? |

For deep dive on each pillar, see: [references/well-architected.md](references/well-architected.md)

## Service Selection Matrices

### Compute

| Use Case | Service | Why |
|----------|---------|-----|
| Short tasks (<15min), event-driven | **Lambda** | No infrastructure, pay-per-invocation |
| Containers, microservices | **ECS Fargate** | Serverless containers, no cluster management |
| Kubernetes workloads | **EKS** | Managed K8s, existing K8s expertise |
| Long-running, stateful | **EC2** | Full control, persistent state |
| Simple web apps | **App Runner** | Container-to-URL in minutes |
| Batch processing | **AWS Batch** | Managed batch computing |

**Decision Flow:**
```
Need full OS control? → EC2
Need Kubernetes? → EKS
Stateless, <15 min execution? → Lambda
Containers, no K8s needed? → Fargate
Simple web service? → App Runner
```

### Database

| Use Case | Service | Why |
|----------|---------|-----|
| Relational, complex queries | **Aurora** | MySQL/PostgreSQL compatible, auto-scaling |
| Simple relational | **RDS** | Managed, less overhead than Aurora |
| Key-value, <10ms latency | **DynamoDB** | Serverless, unlimited scale |
| In-memory cache | **ElastiCache** | Redis/Memcached, microsecond latency |
| Data warehouse | **Redshift** | Columnar storage, petabyte scale |
| Graph data | **Neptune** | Relationships-first queries |
| Document/JSON | **DocumentDB** | MongoDB compatible |
| Time series | **Timestream** | IoT, metrics, analytics |

**Decision Flow:**
```
Need SQL joins? → Aurora/RDS
Need microsecond latency? → ElastiCache
Key-value access patterns? → DynamoDB
Analytics on petabytes? → Redshift
Relationship traversals? → Neptune
```

### Storage

| Use Case | Service | Why |
|----------|---------|-----|
| Object storage, any size | **S3** | Unlimited, 99.999999999% durability |
| Block storage for EC2 | **EBS** | Persistent volumes, snapshots |
| Shared file system (Linux) | **EFS** | NFS, auto-scaling, serverless |
| Shared file system (Windows) | **FSx for Windows** | SMB, Active Directory |
| High-performance computing | **FSx for Lustre** | Sub-millisecond latencies |
| Archive, rarely accessed | **S3 Glacier** | Lowest cost, retrieval in minutes-hours |

**S3 Storage Classes:**
| Class | Use Case | Retrieval |
|-------|----------|-----------|
| Standard | Frequently accessed | Immediate |
| Intelligent-Tiering | Unknown access patterns | Automatic |
| Standard-IA | Infrequent, rapid access | Immediate |
| One Zone-IA | Infrequent, single AZ OK | Immediate |
| Glacier Instant | Archive, immediate access | Milliseconds |
| Glacier Flexible | Archive, flexible retrieval | 1-5 min to 12 hours |
| Glacier Deep Archive | Long-term archive | 12-48 hours |

### Messaging & Events

| Use Case | Service | Why |
|----------|---------|-----|
| Decoupled microservices | **SQS** | Managed queue, at-least-once delivery |
| Fan-out to multiple consumers | **SNS** | Pub/sub, push to many endpoints |
| Event routing, filtering | **EventBridge** | Event bus, 90+ AWS service sources |
| Real-time streaming | **Kinesis Data Streams** | Sub-second latency, replay |
| Managed Kafka | **MSK** | Kafka compatibility, managed |
| Workflow orchestration | **Step Functions** | Visual workflows, error handling |

**Decision Flow:**
```
One producer, one consumer? → SQS
One producer, many consumers? → SNS
Complex event routing? → EventBridge
Real-time analytics stream? → Kinesis
Need Kafka APIs? → MSK
Multi-step workflow? → Step Functions
```

For comprehensive decision matrices, see: [references/service-selection.md](references/service-selection.md)

## Architecture Patterns

### Serverless Web Application

```
CloudFront → API Gateway → Lambda → DynamoDB
     ↓
     S3 (static assets)
```

**Components:**
- CloudFront: CDN, caching, HTTPS
- S3: Static frontend (React, Vue, etc.)
- API Gateway: REST/HTTP APIs, auth
- Lambda: Business logic
- DynamoDB: Data persistence

**Benefits:** No servers, auto-scaling, pay-per-use

### Container Microservices

```
ALB → ECS Fargate → RDS Aurora
         ↓
      Service Mesh (App Mesh)
         ↓
      Service Discovery (Cloud Map)
```

**Components:**
- ALB: Load balancing, path-based routing
- ECS Fargate: Container orchestration
- ECR: Container registry
- Cloud Map: Service discovery
- App Mesh: Observability, traffic control

### Event-Driven Architecture

```
EventBridge
    ↓
┌───────┬───────┬───────┐
Lambda  SQS   SNS   Step Functions
    ↓     ↓     ↓         ↓
DynamoDB  Lambda  Email  Workflow
```

**Benefits:** Loose coupling, scalability, resilience

### Data Lake

```
Data Sources → Kinesis/S3 → Glue ETL → S3 (data lake)
                                           ↓
                              ┌────────────┼────────────┐
                           Athena      Redshift     SageMaker
                           (ad-hoc)   (warehouse)   (ML)
```

**Components:**
- S3: Central data storage
- Glue: ETL, data catalog
- Athena: Serverless SQL queries
- Redshift: Data warehouse
- Lake Formation: Governance, security

### Multi-Region Active-Active

```
Region A                    Region B
┌──────────────────┐       ┌──────────────────┐
│ Route 53 (latency routing)                  │
│       ↓                          ↓          │
│   CloudFront              CloudFront        │
│       ↓                          ↓          │
│     ALB                        ALB          │
│       ↓                          ↓          │
│   ECS/Lambda              ECS/Lambda        │
│       ↓                          ↓          │
│   Aurora Global Database (writer/reader)    │
└──────────────────┘       └──────────────────┘
```

**Key Services:**
- Route 53: DNS failover, latency-based routing
- Aurora Global Database: Cross-region replication
- DynamoDB Global Tables: Multi-region active-active
- S3 Cross-Region Replication: Object replication

## Security Overview

### IAM Principles

| Principle | Implementation |
|-----------|----------------|
| Least Privilege | Grant only required permissions |
| Defense in Depth | Multiple security layers |
| Separation of Duties | Different roles for different tasks |
| MFA Everywhere | Require MFA for humans |
| No Long-Lived Credentials | Use roles, not access keys |

**IAM Policy Evaluation:**
```
Explicit Deny → Organizations SCP → Resource Policy → Identity Policy → Permission Boundary
```

### Encryption Strategy

| Data State | Service | Key Management |
|------------|---------|----------------|
| At Rest | S3, EBS, RDS, DynamoDB | KMS (CMK or AWS-managed) |
| In Transit | ALB, CloudFront, API Gateway | TLS 1.2+ (ACM certificates) |
| In Use | Nitro Enclaves | Isolated compute |

**KMS Key Types:**
- AWS Managed: Automatic rotation, no management
- Customer Managed: Full control, audit trail
- Customer Owned: On-premises HSM (CloudHSM)

### Network Security

| Layer | Service | Purpose |
|-------|---------|---------|
| Edge | WAF, Shield | DDoS, application attacks |
| Perimeter | VPC, Security Groups | Network isolation |
| Internal | PrivateLink, VPC Endpoints | Private connectivity |
| Monitoring | VPC Flow Logs, GuardDuty | Threat detection |

For detailed security patterns, see: [references/security-patterns.md](references/security-patterns.md)

## Cost Optimization Overview

### Pricing Models

| Model | Best For | Savings |
|-------|----------|---------|
| On-Demand | Variable, unpredictable | Baseline |
| Reserved Instances | Steady-state workloads | Up to 72% |
| Savings Plans | Consistent compute usage | Up to 72% |
| Spot Instances | Fault-tolerant, flexible | Up to 90% |

### Savings Plans vs Reserved Instances

| Aspect | Savings Plans | Reserved Instances |
|--------|---------------|-------------------|
| Flexibility | Any instance type/region | Specific instance type |
| Compute Options | EC2, Fargate, Lambda | EC2 only (standard) |
| Commitment | $/hour | Instance type |
| Best For | Diverse workloads | Predictable workloads |

### Quick Wins

| Action | Typical Savings |
|--------|-----------------|
| Right-size instances | 20-40% |
| Use Spot for dev/test | Up to 90% |
| Delete unused resources | Variable |
| S3 Intelligent-Tiering | 30-40% |
| Reserved capacity | 30-72% |

For detailed cost strategies, see: [references/cost-optimization.md](references/cost-optimization.md)

## Pricing & Costs

### AWS CLI Pricing Commands

Query real-time pricing data:

```bash
# List all AWS services
aws pricing describe-services --region us-east-1

# Get EC2 instance pricing
aws pricing get-products --service-code AmazonEC2 \
  --filters Type=TERM_MATCH,Field=instanceType,Value=m5.large \
            Type=TERM_MATCH,Field=location,Value="US East (N. Virginia)" \
  --region us-east-1

# Get RDS pricing
aws pricing get-products --service-code AmazonRDS \
  --filters Type=TERM_MATCH,Field=databaseEngine,Value=MySQL \
  --region us-east-1

# Get available attributes for a service
aws pricing describe-services --service-code AmazonEC2 --region us-east-1
```

**Note:** Pricing API only available in `us-east-1` and `ap-south-1`.

### AWS MCP Servers

AWS provides 64+ official MCP servers via [awslabs/mcp](https://github.com/awslabs/mcp) for AI-assisted infrastructure work.

**Quick Install:** `uvx awslabs.<server-name>@latest`

**Top servers by category:**

| Category | Servers |
|----------|---------|
| Architecture | `aws-pricing-mcp-server`, `aws-well-architected-mcp-server`, `aws-documentation-mcp-server` |
| IaC | `aws-cdk-mcp-server`, `aws-terraform-mcp-server`, `aws-cloudformation-mcp-server` |
| Data | `amazon-dynamodb-mcp-server`, `amazon-aurora-postgresql-mcp-server`, `amazon-redshift-mcp-server` |
| ML/AI | `amazon-bedrock-kb-retrieval-mcp-server`, `amazon-sagemaker-mcp-server`, `amazon-kendra-index-mcp-server` |
| Operations | `amazon-cloudwatch-mcp-server`, `aws-cloudtrail-mcp-server`, `aws-cost-explorer-mcp-server` |

**Example config:**
```json
{
  "mcpServers": {
    "aws-pricing": {
      "command": "uvx",
      "args": ["awslabs.aws-pricing-mcp-server@latest"],
      "env": { "AWS_PROFILE": "your-profile" }
    }
  }
}
```

For full catalog (64+ servers), configuration examples, and IAM permissions, see: [references/mcp-servers.md](references/mcp-servers.md)

### Web Tools

Use `/web-research AWS pricing [service]` or:
- [AWS Pricing Calculator](https://calculator.aws/) - Interactive estimates
- [AWS Cost Explorer](https://aws.amazon.com/aws-cost-management/aws-cost-explorer/) - Historical analysis

## DR/HA Patterns

### Recovery Objectives

| Metric | Definition | Example |
|--------|------------|---------|
| RTO | Recovery Time Objective | "Back online in 4 hours" |
| RPO | Recovery Point Objective | "Lose at most 1 hour of data" |

### DR Strategies (by cost/complexity)

| Strategy | RTO | RPO | Cost |
|----------|-----|-----|------|
| Backup & Restore | Hours | Hours | $ |
| Pilot Light | 10-30 min | Minutes | $$ |
| Warm Standby | Minutes | Seconds | $$$ |
| Active-Active | ~0 | ~0 | $$$$ |

### High Availability Patterns

**Single Region HA:**
```
┌─────────────────────────────────────┐
│              Region                  │
│  ┌─────────┐   ┌─────────┐          │
│  │  AZ-a   │   │  AZ-b   │          │
│  │ ┌─────┐ │   │ ┌─────┐ │          │
│  │ │ EC2 │←┼───┼→│ EC2 │ │  ← ALB   │
│  │ └──┬──┘ │   │ └──┬──┘ │          │
│  └────┼────┘   └────┼────┘          │
│       └──────┬──────┘               │
│              ↓                      │
│         RDS Multi-AZ                │
└─────────────────────────────────────┘
```

**Multi-Region:**
```
Route 53 (health checks, failover)
         ↓
┌────────────────┐  ┌────────────────┐
│   Region A     │  │   Region B     │
│   (Primary)    │  │   (Secondary)  │
│                │  │                │
│  ALB + ECS     │  │  ALB + ECS     │
│       ↓        │  │       ↓        │
│  Aurora Writer │→→│ Aurora Reader  │
└────────────────┘  └────────────────┘
```

## Observability Overview

### Three Pillars

| Pillar | Service | Use Case |
|--------|---------|----------|
| Metrics | CloudWatch Metrics | Performance monitoring |
| Logs | CloudWatch Logs | Debugging, audit |
| Traces | X-Ray | Distributed tracing |

### CloudWatch Strategy

**Key Metrics to Monitor:**
- EC2: CPU, Network, Disk I/O
- RDS: CPU, Connections, Replica Lag
- Lambda: Duration, Errors, Throttles
- ALB: Request count, Latency, 5XX errors

**Alarm Best Practices:**
- Use anomaly detection for dynamic thresholds
- Create composite alarms for complex conditions
- Set up SNS topics for different severity levels

### Logging Strategy

| Service | Log Destination | Retention |
|---------|-----------------|-----------|
| Lambda | CloudWatch Logs | Set per function |
| ECS | CloudWatch Logs | Container stdout/stderr |
| ALB | S3 | Access logs |
| VPC | CloudWatch/S3 | Flow logs |
| API Gateway | CloudWatch Logs | Access + execution |

### X-Ray Tracing

```
Client → API Gateway → Lambda → DynamoDB
           ↓              ↓          ↓
        X-Ray trace spans across all services
```

**Benefits:**
- End-to-end request visualization
- Latency analysis
- Error root cause identification
- Service map generation

## IaC Recommendations

### Tool Comparison

| Tool | Best For | Pros | Cons |
|------|----------|------|------|
| CloudFormation | AWS-only, native | Deep AWS integration, no state management | AWS-only, verbose |
| CDK | Developers, complex infra | Real programming languages | Learning curve, abstraction layers |
| Terraform/OpenTofu | Multi-cloud, mature | Provider ecosystem, state management | External state, HCL syntax |
| Pulumi | Developers preferring code | Real languages, strong typing | Smaller community |

### Recommendations

**Use CloudFormation when:**
- AWS-only infrastructure
- Need native AWS features (drift detection, StackSets)
- Team prefers declarative YAML/JSON

**Use CDK when:**
- Complex infrastructure with reusable patterns
- Team prefers TypeScript/Python over YAML
- Need constructs and higher-level abstractions

**Use Terraform/OpenTofu when:**
- Multi-cloud or hybrid infrastructure
- Existing Terraform expertise
- Need provider ecosystem (non-AWS resources)

For Terraform patterns, see: `terraform` or `tofu` skills.

## Common Anti-Patterns

| Anti-Pattern | Problem | Solution |
|--------------|---------|----------|
| Single AZ deployment | Single point of failure | Multi-AZ with auto-scaling |
| Hardcoded secrets | Security risk | Secrets Manager, Parameter Store |
| No resource tagging | Cost attribution impossible | Enforce tags via SCPs |
| Over-provisioned instances | Wasted spend | Right-sizing, auto-scaling |
| No backup strategy | Data loss risk | Automated backups, cross-region |
| Public S3 buckets | Data exposure | Block public access by default |
| Long-lived credentials | Security risk | IAM roles, temporary credentials |
| Monolithic Lambda | Cold start issues | Smaller functions, provisioned concurrency |
| No monitoring | Blind to issues | CloudWatch, X-Ray, alarms |
| Manual deployments | Inconsistency, errors | CI/CD pipelines, IaC |

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Lambda cold starts | Function initialization | Provisioned concurrency, smaller packages |
| RDS connection limits | Too many connections | Connection pooling (RDS Proxy) |
| S3 performance | Request rate limits | Prefix randomization, CloudFront |
| ECS task failures | Resource constraints | Check task definition limits, logs |
| Cross-account access denied | Missing trust policy | Update IAM role trust relationship |
| VPC connectivity issues | Missing routes/endpoints | Check route tables, VPC endpoints |
| High DynamoDB latency | Hot partitions | Better partition key design |
| CloudFormation stuck | Resource dependencies | Check events, manual cleanup |

## What's New (2024-2025)

### Major Updates

- **Aurora Limitless Database:** Horizontal scaling for PostgreSQL
- **S3 Express One Zone:** Single-digit ms latency for frequently accessed data
- **Bedrock expansion:** Claude, Llama, Mistral models + Agents
- **Lambda SnapStart for Python/Java:** Near-instant cold starts
- **Step Functions Distributed Map:** 10K parallel executions
- **ECS Service Connect:** Built-in service mesh
- **VPC Lattice:** Application networking across VPCs/accounts

### Coming Soon

- Check AWS re:Invent announcements for latest

### Deprecations

- EC2-Classic fully retired
- Python 3.8/Node.js 16 Lambda runtimes deprecated

## References

### Local Reference Files
- [references/well-architected.md](references/well-architected.md) - Six pillars deep dive
- [references/service-selection.md](references/service-selection.md) - Comprehensive decision matrices
- [references/security-patterns.md](references/security-patterns.md) - IAM, encryption, network security
- [references/cost-optimization.md](references/cost-optimization.md) - Savings strategies
- [references/mcp-servers.md](references/mcp-servers.md) - Complete AWS MCP servers catalog (64+ servers)

### MCP Servers
- [AWS MCP Servers (awslabs/mcp)](https://github.com/awslabs/mcp) - Official AWS MCP servers
- [AWS MCP Documentation](https://awslabs.github.io/mcp/) - Setup guides and capabilities

### Pricing
- [AWS Pricing Calculator](https://calculator.aws/)
- [AWS Price List API](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/price-changes.html)
- [EC2 Pricing](https://aws.amazon.com/ec2/pricing/)
- [Lambda Pricing](https://aws.amazon.com/lambda/pricing/)

### Official Documentation
- [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/framework/)
- [AWS Architecture Center](https://aws.amazon.com/architecture/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [AWS Disaster Recovery](https://aws.amazon.com/disaster-recovery/)
