# AWS Well-Architected Framework

Deep dive on the six pillars of well-architected systems.

## 1. Operational Excellence

**Focus:** Run and monitor systems to deliver business value and continually improve.

### Design Principles

- Perform operations as code (IaC)
- Make frequent, small, reversible changes
- Refine operations procedures frequently
- Anticipate failure
- Learn from all operational failures

### Key Practices

**Organization:**
- Evaluate external customer needs
- Evaluate internal customer needs
- Evaluate governance requirements
- Evaluate compliance requirements
- Evaluate threat landscape

**Prepare:**
- Design telemetry
- Design for operations
- Mitigate deployment risks
- Understand operational readiness

**Operate:**
- Understand workload health
- Understand operations health
- Respond to events

**Evolve:**
- Learn, share, and improve

### Implementation Checklist

| Area | Question | AWS Service |
|------|----------|-------------|
| Telemetry | How do you collect metrics? | CloudWatch, X-Ray |
| Deployment | How do you deploy safely? | CodePipeline, CodeDeploy |
| Response | How do you respond to events? | EventBridge, Lambda, SNS |
| Runbooks | Are procedures documented? | Systems Manager Documents |
| Game days | Do you test failure scenarios? | Fault Injection Simulator |

### Key Metrics

- Deployment frequency
- Lead time for changes
- Mean time to recovery (MTTR)
- Change failure rate

---

## 2. Security

**Focus:** Protect data, systems, and assets through risk assessments and mitigation.

### Design Principles

- Implement a strong identity foundation
- Enable traceability
- Apply security at all layers
- Automate security best practices
- Protect data in transit and at rest
- Keep people away from data
- Prepare for security events

### Key Practices

**Identity and Access Management:**
- Use centralized identity provider
- Use temporary credentials
- Require MFA
- Apply least privilege

**Detection:**
- Configure service and application logging
- Analyze logs and metrics centrally
- Automate alerting and response

**Infrastructure Protection:**
- Create network layers
- Control traffic at all layers
- Automate compute protection

**Data Protection:**
- Define data classification
- Implement encryption
- Protect data at rest and in transit
- Automate data protection

**Incident Response:**
- Identify key personnel
- Pre-provision access
- Pre-deploy tools
- Run game days

### Implementation Checklist

| Area | Practice | AWS Service |
|------|----------|-------------|
| Identity | Centralized IdP | IAM Identity Center (SSO) |
| Identity | Temporary credentials | IAM Roles, STS |
| Identity | MFA enforcement | IAM, Identity Center |
| Detection | Log aggregation | CloudWatch Logs, CloudTrail |
| Detection | Threat detection | GuardDuty |
| Detection | Security posture | Security Hub |
| Network | Firewall | Security Groups, NACLs, WAF |
| Network | Private connectivity | PrivateLink, VPC Endpoints |
| Data | Encryption at rest | KMS, S3 encryption |
| Data | Encryption in transit | ACM, TLS |
| Response | Automated remediation | Lambda, Config Rules |

### Key Metrics

- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- Percentage of resources compliant
- Number of security findings

---

## 3. Reliability

**Focus:** Ability to recover from failures and meet demand.

### Design Principles

- Automatically recover from failure
- Test recovery procedures
- Scale horizontally
- Stop guessing capacity
- Manage change in automation

### Key Practices

**Foundations:**
- Manage service quotas
- Plan network topology
- Meet resiliency targets

**Workload Architecture:**
- Design for service availability
- Design distributed systems to prevent failures
- Design distributed systems to mitigate failures

**Change Management:**
- Monitor workload resources
- Design to adapt to changes in demand
- Implement change

**Failure Management:**
- Back up data
- Use fault isolation
- Design to withstand component failures
- Test reliability
- Plan for disaster recovery

### Implementation Checklist

| Area | Practice | AWS Service |
|------|----------|-------------|
| Foundations | Service quotas | Service Quotas, Trusted Advisor |
| Architecture | Multi-AZ deployment | ALB, RDS Multi-AZ |
| Architecture | Auto-scaling | Auto Scaling Groups, Fargate |
| Monitoring | Health checks | Route 53, ALB health checks |
| Monitoring | Alarms | CloudWatch Alarms |
| Backup | Automated backups | AWS Backup, RDS snapshots |
| DR | Cross-region replication | S3 CRR, Aurora Global |
| Testing | Chaos engineering | Fault Injection Simulator |

### Recovery Objectives

| Tier | RTO | RPO | Strategy |
|------|-----|-----|----------|
| Mission Critical | < 1 min | 0 | Active-Active |
| Business Critical | < 10 min | < 1 min | Warm Standby |
| Business Operational | < 1 hour | < 15 min | Pilot Light |
| Business Functional | < 24 hours | < 1 hour | Backup & Restore |

### Key Metrics

- Availability (uptime percentage)
- Mean time between failures (MTBF)
- Mean time to recovery (MTTR)
- Recovery point actual (RPA)
- Recovery time actual (RTA)

---

## 4. Performance Efficiency

**Focus:** Use computing resources efficiently to meet requirements.

### Design Principles

- Democratize advanced technologies
- Go global in minutes
- Use serverless architectures
- Experiment more often
- Consider mechanical sympathy

### Key Practices

**Selection:**
- Evaluate available options
- Consider location (regions, edge)
- Use purpose-built databases
- Consider serverless

**Review:**
- Evolve workload to use new services
- Use performance architecture review
- Benchmark performance
- Load test

**Monitoring:**
- Monitor resources to identify degradation
- Create alarms for thresholds

**Tradeoffs:**
- Understand performance tradeoffs
- Use patterns like caching
- Consider read replicas

### Selection Guidelines

| Workload Type | Recommended Approach |
|---------------|---------------------|
| Unpredictable traffic | Serverless (Lambda, Fargate) |
| Steady traffic | Containers or EC2 with right-sizing |
| High-performance compute | EC2 with enhanced networking |
| Low-latency global | Edge computing (CloudFront, Lambda@Edge) |

### Caching Strategy

| Layer | Service | Use Case |
|-------|---------|----------|
| CDN | CloudFront | Static assets, API responses |
| Application | ElastiCache | Session data, computed results |
| Database | DAX | DynamoDB acceleration |
| API | API Gateway | Response caching |

### Key Metrics

- Latency (P50, P95, P99)
- Throughput (requests/second)
- Error rate
- Resource utilization
- Cache hit ratio

---

## 5. Cost Optimization

**Focus:** Run systems to deliver business value at the lowest price point.

### Design Principles

- Implement cloud financial management
- Adopt a consumption model
- Measure overall efficiency
- Stop spending on undifferentiated heavy lifting
- Analyze and attribute expenditure

### Key Practices

**Practice Cloud Financial Management:**
- Establish cloud financial management
- Quantify business value
- Define organization cost awareness

**Expenditure and Usage Awareness:**
- Governance
- Monitor cost and usage
- Decommission resources

**Cost-Effective Resources:**
- Evaluate cost when selecting services
- Select correct resource type and size
- Select best pricing model
- Plan for data transfer

**Manage Demand and Supply:**
- Analyze workload over time
- Implement buffer or throttle
- Match supply to demand

**Optimize Over Time:**
- Review and analyze regularly
- Define and enforce cost optimization

### Pricing Model Selection

| Workload Pattern | Recommended Model |
|------------------|-------------------|
| Steady, predictable | Reserved Instances / Savings Plans |
| Varying but consistent | Savings Plans (Compute) |
| Fault-tolerant, flexible | Spot Instances |
| Short-term, variable | On-Demand |
| Development/Test | Spot + On-Demand mix |

### Cost Allocation Strategy

| Tag | Purpose | Example Values |
|-----|---------|----------------|
| Environment | Separate prod/dev | prod, staging, dev |
| CostCenter | Business unit billing | engineering, marketing |
| Project | Project tracking | project-alpha |
| Owner | Accountability | team-platform |

### Key Metrics

- Total cost of ownership (TCO)
- Cost per transaction
- Cost per customer
- Savings rate (RI/SP utilization)
- Waste percentage

---

## 6. Sustainability

**Focus:** Minimize environmental impact of running cloud workloads.

### Design Principles

- Understand your impact
- Establish sustainability goals
- Maximize utilization
- Anticipate and adopt new, more efficient offerings
- Use managed services
- Reduce downstream impact

### Key Practices

**Region Selection:**
- Choose regions with lower carbon intensity
- Consider data residency requirements

**Alignment to Demand:**
- Scale resources with demand
- Use auto-scaling
- Implement buffer/throttle patterns

**Software and Architecture:**
- Optimize code for efficiency
- Remove unused code and features
- Use efficient data formats

**Data:**
- Implement data lifecycle policies
- Use appropriate storage classes
- Compress data

**Hardware:**
- Use instance types with better energy efficiency
- Consider Graviton (ARM) processors

**Development and Deployment:**
- Use efficient development practices
- Implement CI/CD to minimize builds

### Implementation

| Area | Action | Benefit |
|------|--------|---------|
| Compute | Use Graviton instances | Up to 60% better energy efficiency |
| Compute | Right-size resources | Reduce waste |
| Storage | S3 Intelligent-Tiering | Automatic optimization |
| Storage | Data lifecycle policies | Delete unused data |
| Architecture | Serverless | Scale to zero |
| Region | Renewable energy regions | Lower carbon footprint |

### AWS Sustainability Resources

- **Customer Carbon Footprint Tool**: Track emissions
- **AWS Clean Energy Commitment**: 100% renewable by 2025
- **Sustainability Pillar Whitepaper**: Detailed guidance

---

## Well-Architected Review Process

### When to Review

- New workload design
- Major architecture changes
- Periodic review (quarterly/annually)
- After incidents

### Review Steps

1. **Prepare**: Gather architecture diagrams, team members
2. **Review**: Answer questions for each pillar
3. **Identify**: High and medium risk issues (HRIs, MRIs)
4. **Prioritize**: Based on business impact
5. **Remediate**: Create improvement plan
6. **Measure**: Track improvement over time

### AWS Tools

| Tool | Use Case |
|------|----------|
| Well-Architected Tool | Self-service reviews |
| Trusted Advisor | Automated checks |
| AWS Config | Compliance monitoring |
| Compute Optimizer | Right-sizing recommendations |

### Well-Architected Lenses

Specialized guidance for specific workloads:
- Serverless
- SaaS
- Machine Learning
- Data Analytics
- IoT
- Containers
- SAP
- Games
- Financial Services
- Healthcare
