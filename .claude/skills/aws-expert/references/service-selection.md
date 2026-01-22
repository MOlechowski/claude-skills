# AWS Service Selection Guide

Comprehensive decision matrices for choosing the right AWS services.

## Compute Services

### Overview Matrix

| Service | Use Case | Scaling | Pricing Model | Cold Start |
|---------|----------|---------|---------------|------------|
| Lambda | Event-driven, short tasks | Automatic | Per-invocation | Yes |
| Fargate | Containers, no cluster mgmt | Automatic | Per vCPU/memory | No |
| ECS on EC2 | Containers, full control | Manual/ASG | Per EC2 instance | No |
| EKS | Kubernetes workloads | Manual/Karpenter | Per cluster + EC2 | No |
| EC2 | Full control, stateful | Manual/ASG | Per instance | No |
| App Runner | Simple web apps | Automatic | Per vCPU/memory | Minimal |
| Batch | Batch processing | Automatic | Per EC2/Fargate | No |
| Lightsail | Simple VPS | Manual | Fixed monthly | No |

### Lambda vs Containers Decision

```
┌─────────────────────────────────────────────────┐
│              Is execution < 15 minutes?          │
└────────────────────┬────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │ Yes                   │ No
         ▼                       ▼
┌────────────────┐      ┌────────────────┐
│ Is it event-   │      │ Use Containers │
│ driven?        │      │ (Fargate/ECS)  │
└───────┬────────┘      └────────────────┘
        │
   ┌────┴────┐
   │ Yes     │ No
   ▼         ▼
┌────────┐ ┌────────────────┐
│ Lambda │ │ Consider both  │
│        │ │ based on cost  │
└────────┘ └────────────────┘
```

### Lambda Considerations

**Good For:**
- API endpoints with variable traffic
- Event processing (S3, SQS, SNS, EventBridge)
- Scheduled tasks (cron jobs)
- Real-time file processing
- Webhooks

**Avoid When:**
- Execution > 15 minutes
- Need persistent connections (WebSockets at scale)
- High-frequency, consistent traffic (cost inefficient)
- Large deployment packages (>250MB)
- Need GPU

**Cold Start Mitigation:**
- Provisioned Concurrency (eliminates cold starts)
- Keep functions warm with scheduled pings
- Smaller deployment packages
- Use ARM (Graviton) for faster init

### ECS vs EKS Decision

| Factor | Choose ECS | Choose EKS |
|--------|-----------|------------|
| Team expertise | No Kubernetes experience | Kubernetes expertise |
| Portability | AWS-only acceptable | Multi-cloud or hybrid |
| Complexity | Simpler setup preferred | OK with complexity |
| Ecosystem | Basic container needs | Need K8s ecosystem |
| Cost | Lower operational overhead | Worth the overhead |

### EC2 Instance Selection

**Family Selection:**
| Family | Use Case | Examples |
|--------|----------|----------|
| M (General) | Balanced workloads | Web servers, small DBs |
| C (Compute) | CPU-intensive | Batch processing, gaming |
| R (Memory) | Memory-intensive | In-memory DBs, caching |
| T (Burstable) | Variable CPU | Dev/test, small workloads |
| I (Storage) | Storage-optimized | Data warehouses, Kafka |
| G/P (GPU) | ML, graphics | Training, inference |

**Generation:** Always use latest generation (e.g., m7i over m5)

**Processor:**
| Suffix | Processor | Best For |
|--------|-----------|----------|
| (none) | Intel | Broad compatibility |
| a | AMD | Cost savings (10-15%) |
| g | Graviton (ARM) | Best price-performance |

---

## Database Services

### Overview Matrix

| Service | Type | Scaling | Max Size | Latency |
|---------|------|---------|----------|---------|
| RDS | Relational | Vertical + Read Replicas | 64 TB | ms |
| Aurora | Relational | Auto + Read Replicas | 128 TB | ms |
| DynamoDB | Key-Value/Document | Automatic | Unlimited | < 10ms |
| ElastiCache | In-Memory | Cluster | 500 nodes | < 1ms |
| Redshift | Data Warehouse | Manual | Petabytes | seconds |
| Neptune | Graph | Manual | 64 TB | ms |
| DocumentDB | Document | Cluster | 64 TB | ms |
| Timestream | Time Series | Automatic | Unlimited | ms |
| Keyspaces | Wide Column | Automatic | Unlimited | < 10ms |
| MemoryDB | Durable In-Memory | Cluster | 500 nodes | < 1ms |

### SQL vs NoSQL Decision

```
┌────────────────────────────────────────────────┐
│        Do you need complex SQL queries?         │
│        (JOINs, aggregations, transactions)      │
└─────────────────────┬──────────────────────────┘
                      │
          ┌───────────┴───────────┐
          │ Yes                   │ No
          ▼                       ▼
┌─────────────────┐     ┌─────────────────────────┐
│ Aurora or RDS   │     │ What's your access      │
│                 │     │ pattern?                │
└─────────────────┘     └───────────┬─────────────┘
                                    │
          ┌─────────────┬───────────┼───────────┬────────────┐
          │             │           │           │            │
          ▼             ▼           ▼           ▼            ▼
     Key-Value     Document    Graph      Time Series   Wide Column
          │             │           │           │            │
          ▼             ▼           ▼           ▼            ▼
      DynamoDB    DocumentDB   Neptune    Timestream    Keyspaces
```

### RDS vs Aurora

| Factor | RDS | Aurora |
|--------|-----|--------|
| Cost | Lower baseline | Higher, but scales better |
| Scaling | Vertical only | Auto-scaling storage |
| Replicas | Up to 5 | Up to 15 |
| Failover | 60-120 seconds | < 30 seconds |
| Storage | Up to 64 TB | Up to 128 TB |
| Global | Cross-region replicas | Global Database |
| Serverless | No | Aurora Serverless v2 |

**Choose Aurora when:**
- Need auto-scaling storage
- Need more read replicas
- Need faster failover
- Running at scale (cost-effective at higher tiers)

**Choose RDS when:**
- Simpler, predictable workloads
- Cost-sensitive smaller workloads
- Using unsupported engines (Oracle, SQL Server)

### DynamoDB Access Patterns

**Design for DynamoDB when:**
- Known access patterns
- Key-value or simple queries
- Need consistent single-digit millisecond latency
- Need unlimited scale
- Can denormalize data

**Avoid DynamoDB when:**
- Unknown query patterns
- Need ad-hoc SQL queries
- Strong consistency across items required
- Complex transactions

**Key Design:**
| Pattern | Partition Key | Sort Key |
|---------|---------------|----------|
| User profiles | user_id | - |
| Orders by user | user_id | order_date |
| Products by category | category | product_id |
| IoT data | device_id | timestamp |

### Caching Tier Selection

| Need | Service | When to Use |
|------|---------|-------------|
| Session storage | ElastiCache Redis | Web apps, user sessions |
| Query caching | ElastiCache | Reduce database load |
| DynamoDB acceleration | DAX | DynamoDB-specific caching |
| Full-text search | OpenSearch | Logs, search functionality |

---

## Storage Services

### Overview Matrix

| Service | Type | Durability | Access | Cost |
|---------|------|------------|--------|------|
| S3 | Object | 99.999999999% | API | $ |
| EBS | Block | 99.999% | EC2 attached | $$ |
| EFS | File (NFS) | Multi-AZ | EC2/Lambda/Fargate | $$$ |
| FSx Lustre | File (HPC) | Multi-AZ | EC2 | $$$$ |
| FSx Windows | File (SMB) | Multi-AZ | Windows EC2 | $$$ |
| Storage Gateway | Hybrid | Depends | On-premises | $$ |

### S3 Storage Class Selection

| Class | Use Case | Retrieval | Min Duration |
|-------|----------|-----------|--------------|
| Standard | Frequently accessed | Immediate | None |
| Intelligent-Tiering | Unknown patterns | Immediate | None |
| Standard-IA | Infrequent, rapid | Immediate | 30 days |
| One Zone-IA | Infrequent, single AZ | Immediate | 30 days |
| Glacier Instant | Archive, immediate | Milliseconds | 90 days |
| Glacier Flexible | Archive, flexible | 1-5 min to 12 hr | 90 days |
| Glacier Deep Archive | Long-term archive | 12-48 hours | 180 days |

**Selection Flow:**
```
┌─────────────────────────────────────────────┐
│     How often is the data accessed?         │
└────────────────────┬────────────────────────┘
                     │
    ┌────────────────┼────────────────┐
    ▼                ▼                ▼
 Frequently      Infrequent       Rarely/Archive
    │                │                │
    ▼                ▼                ▼
 Standard       Standard-IA     Glacier (choose tier)
    │                │
    └────────────────┴─────────────────────┐
                                           │
              Unknown pattern? → Intelligent-Tiering
```

### EBS Volume Types

| Type | Use Case | IOPS | Throughput |
|------|----------|------|------------|
| gp3 | General purpose | 16,000 | 1,000 MB/s |
| gp2 | General (legacy) | 16,000 | 250 MB/s |
| io2 | High IOPS | 256,000 | 4,000 MB/s |
| st1 | Throughput (HDD) | 500 | 500 MB/s |
| sc1 | Cold (HDD) | 250 | 250 MB/s |

**Default choice:** gp3 (decouple IOPS from size)

### EFS vs FSx

| Factor | EFS | FSx for Lustre | FSx for Windows |
|--------|-----|----------------|-----------------|
| Protocol | NFS | Lustre | SMB |
| Best for | Linux, containers | HPC, ML | Windows workloads |
| Latency | Sub-millisecond | Sub-millisecond | Sub-millisecond |
| S3 integration | No | Yes | No |
| AD integration | No | No | Yes |

---

## Networking Services

### Load Balancer Selection

| Type | Layer | Use Case | Protocols |
|------|-------|----------|-----------|
| ALB | 7 | HTTP/HTTPS routing | HTTP, HTTPS, gRPC |
| NLB | 4 | TCP/UDP, high performance | TCP, UDP, TLS |
| GLB | 3 | Third-party appliances | IP packets |
| CLB | 4/7 | Legacy (avoid) | TCP, HTTP |

**Selection:**
- **ALB**: Web applications, microservices, path-based routing
- **NLB**: Gaming, IoT, extreme performance, static IP needed
- **GLB**: Firewall, IDS/IPS appliances

### API Gateway vs ALB

| Factor | API Gateway | ALB |
|--------|-------------|-----|
| Protocol | REST, HTTP, WebSocket | HTTP, HTTPS, gRPC |
| Auth | Built-in (Cognito, Lambda) | Via target |
| Rate limiting | Built-in | Via WAF |
| Caching | Built-in | Via CloudFront |
| Cost | Per request | Per hour + LCU |
| Best for | Serverless APIs | Container/EC2 apps |

### VPC Connectivity Options

| Need | Service | Use Case |
|------|---------|----------|
| VPC to VPC (same region) | VPC Peering | Simple, low cost |
| VPC to VPC (cross-region) | Transit Gateway | Hub-and-spoke |
| VPC to on-premises | Site-to-Site VPN | Encrypted, quick setup |
| VPC to on-premises (dedicated) | Direct Connect | High bandwidth, consistent |
| Private AWS service access | VPC Endpoints | No internet gateway needed |
| Expose private service | PrivateLink | Share services privately |

### DNS & CDN

| Service | Use Case |
|---------|----------|
| Route 53 | DNS, domain registration, health checks |
| CloudFront | CDN, caching, edge compute |
| Global Accelerator | Static IP, TCP/UDP acceleration |

**CloudFront vs Global Accelerator:**
- CloudFront: HTTP/HTTPS content caching
- Global Accelerator: Any TCP/UDP, gaming, VoIP

---

## Messaging & Events

### Queue Selection

| Service | Pattern | Ordering | Deduplication |
|---------|---------|----------|---------------|
| SQS Standard | At-least-once | Best effort | No |
| SQS FIFO | Exactly-once | Guaranteed | Yes |
| Kinesis | Streaming | Per-shard | No |
| MSK | Kafka | Per-partition | Configurable |

### Event Routing

```
┌─────────────────────────────────────────────────┐
│         What's your event pattern?              │
└─────────────────────┬───────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    ▼                 ▼                 ▼
 One-to-one      One-to-many     Complex routing
    │                 │                 │
    ▼                 ▼                 ▼
   SQS              SNS           EventBridge
```

### Step Functions vs SQS + Lambda

| Factor | Step Functions | SQS + Lambda |
|--------|---------------|--------------|
| Orchestration | Visual workflow | Manual coordination |
| Error handling | Built-in retries, catch | Manual implementation |
| State management | Automatic | Manual |
| Cost | Per state transition | Per message + invocation |
| Best for | Complex workflows | Simple queuing |

---

## Analytics & Big Data

### Data Lake Architecture

| Layer | Service | Purpose |
|-------|---------|---------|
| Ingestion | Kinesis, MSK, DMS | Real-time and batch |
| Storage | S3 | Central data lake |
| Catalog | Glue Data Catalog | Metadata management |
| Processing | Glue ETL, EMR | Transformation |
| Query | Athena | Ad-hoc SQL |
| Warehouse | Redshift | BI, complex analytics |
| Visualization | QuickSight | Dashboards |

### Analytics Service Selection

| Need | Service | When to Use |
|------|---------|-------------|
| Ad-hoc SQL | Athena | Occasional queries on S3 |
| Data warehouse | Redshift | BI, regular reporting |
| Real-time | Kinesis Analytics | Streaming analytics |
| Big data | EMR | Spark, Hadoop workloads |
| Serverless ETL | Glue | Schema discovery, transforms |
| Search | OpenSearch | Log analytics, full-text search |

---

## Machine Learning

### ML Service Tiers

| Tier | Service | Use Case |
|------|---------|----------|
| Pre-built | Rekognition, Comprehend, Translate | No ML expertise needed |
| Low-code | SageMaker Canvas | Business analysts |
| Full ML | SageMaker | Data scientists, custom models |
| Infrastructure | EC2 P/G instances, Inferentia | Maximum control |

### Pre-built AI Services

| Service | Purpose |
|---------|---------|
| Rekognition | Image and video analysis |
| Comprehend | NLP, sentiment, entities |
| Transcribe | Speech-to-text |
| Polly | Text-to-speech |
| Translate | Language translation |
| Textract | Document processing |
| Lex | Chatbots |
| Personalize | Recommendations |
| Forecast | Time series forecasting |
| Kendra | Intelligent search |
| Bedrock | Foundation models (LLMs) |

---

## Security Services

### Identity & Access

| Service | Use Case |
|---------|----------|
| IAM | AWS resource access |
| IAM Identity Center | Workforce SSO |
| Cognito User Pools | Application user management |
| Cognito Identity Pools | Federated access to AWS |
| Directory Service | Active Directory |
| RAM | Cross-account resource sharing |

### Detection & Response

| Service | Purpose |
|---------|---------|
| GuardDuty | Threat detection |
| Security Hub | Security posture |
| Inspector | Vulnerability scanning |
| Detective | Investigation |
| Macie | Data security (S3) |
| Config | Configuration compliance |

### Protection

| Service | Purpose |
|---------|---------|
| WAF | Web application firewall |
| Shield | DDoS protection |
| Firewall Manager | Central firewall management |
| Network Firewall | VPC-level firewall |
| KMS | Encryption key management |
| Secrets Manager | Secrets rotation |
| Certificate Manager | TLS certificates |
