# AWS Security Patterns

Detailed security best practices for IAM, encryption, network security, and compliance.

## IAM Best Practices

### Identity Foundation

**Principle:** Use centralized identity management with temporary credentials.

```
┌─────────────────────────────────────────────────┐
│              IAM Identity Center                │
│         (Centralized User Management)           │
└──────────────────────┬──────────────────────────┘
                       │
         ┌─────────────┼─────────────────┐
         ▼             ▼                 ▼
   ┌──────────┐  ┌──────────┐     ┌──────────┐
   │ Account A │  │ Account B │     │ Account C │
   │           │  │           │     │           │
   │ IAM Roles │  │ IAM Roles │     │ IAM Roles │
   └──────────┘  └──────────┘     └──────────┘
```

### Least Privilege

**Start Restrictive:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/my-prefix/*"
    }
  ]
}
```

**Avoid Wildcards:**
```json
// BAD - Too permissive
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}

// GOOD - Specific actions and resources
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::my-bucket",
    "arn:aws:s3:::my-bucket/*"
  ]
}
```

### Permission Boundaries

Limit maximum permissions for delegated administration:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "s3:*",
        "lambda:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "organizations:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Service Control Policies (SCPs)

**Organization-level guardrails:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeaveOrg",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    },
    {
      "Sid": "RequireIMDSv2",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:MetadataHttpTokens": "required"
        }
      }
    },
    {
      "Sid": "DenyRootUser",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```

### IAM Roles for Service Accounts

**EKS IRSA (IAM Roles for Service Accounts):**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/MyRole
```

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.region.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.region.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub": "system:serviceaccount:namespace:my-service-account"
        }
      }
    }
  ]
}
```

### Cross-Account Access

**Role Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SOURCE_ACCOUNT:role/SourceRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id"
        }
      }
    }
  ]
}
```

---

## Encryption Patterns

### Encryption at Rest

**Service-level encryption:**

| Service | Default | Managed Key | Customer Key |
|---------|---------|-------------|--------------|
| S3 | SSE-S3 | SSE-KMS | SSE-KMS (CMK) |
| EBS | AES-256 | AWS managed | CMK |
| RDS | AES-256 | AWS managed | CMK |
| DynamoDB | AES-256 | AWS owned | CMK |

**S3 Bucket Policy for Encryption:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    }
  ]
}
```

### KMS Key Policies

**Cross-account key sharing:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCrossAccountUse",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::OTHER_ACCOUNT:root"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
```

### Encryption in Transit

**ALB/NLB TLS:**
- Use ACM certificates (automatic renewal)
- Enforce TLS 1.2+ security policy
- Use HTTPS listeners

**API Gateway:**
```yaml
# Enforce HTTPS
x-amazon-apigateway-endpoint-configuration:
  disableExecuteApiEndpoint: true  # Force CloudFront/custom domain
```

**RDS SSL:**
```bash
# Force SSL connections
aws rds modify-db-parameter-group \
  --db-parameter-group-name my-pg \
  --parameters "ParameterName=rds.force_ssl,ParameterValue=1,ApplyMethod=pending-reboot"
```

### Secrets Management

**Secrets Manager with Rotation:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:prod/*"
    }
  ]
}
```

**Parameter Store (for configuration):**
```bash
# Secure string with KMS
aws ssm put-parameter \
  --name /app/prod/db-password \
  --value "secret" \
  --type SecureString \
  --key-id alias/my-key
```

---

## Network Security

### VPC Design

**Recommended Subnet Layout:**

```
VPC: 10.0.0.0/16
│
├── Public Subnets (Internet-facing)
│   ├── 10.0.1.0/24 (AZ-a)  # ALB, NAT Gateway
│   └── 10.0.2.0/24 (AZ-b)
│
├── Private Subnets (Application)
│   ├── 10.0.11.0/24 (AZ-a) # ECS, Lambda
│   └── 10.0.12.0/24 (AZ-b)
│
└── Data Subnets (Database)
    ├── 10.0.21.0/24 (AZ-a) # RDS, ElastiCache
    └── 10.0.22.0/24 (AZ-b)
```

### Security Groups

**Layered Security Groups:**

```
┌─────────────────────────────────────────────────┐
│                    ALB SG                       │
│         Ingress: 443 from 0.0.0.0/0             │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│                  App SG                         │
│         Ingress: 8080 from ALB SG               │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│                   DB SG                         │
│         Ingress: 5432 from App SG               │
└─────────────────────────────────────────────────┘
```

**Reference other security groups:**
```hcl
resource "aws_security_group_rule" "app_from_alb" {
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  security_group_id        = aws_security_group.app.id
}
```

### VPC Endpoints

**Gateway Endpoints (S3, DynamoDB):**
```hcl
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.us-east-1.s3"

  route_table_ids = [aws_route_table.private.id]
}
```

**Interface Endpoints (other services):**
```hcl
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.us-east-1.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}
```

### WAF Rules

**Common WAF Rule Groups:**

| Rule Group | Purpose |
|------------|---------|
| AWSManagedRulesCommonRuleSet | OWASP Top 10 |
| AWSManagedRulesKnownBadInputsRuleSet | Known malicious patterns |
| AWSManagedRulesSQLiRuleSet | SQL injection |
| AWSManagedRulesLinuxRuleSet | Linux-specific attacks |
| AWSManagedRulesAmazonIpReputationList | Known bad IPs |

**Rate Limiting:**
```json
{
  "Name": "RateLimitRule",
  "Priority": 1,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 2000,
      "AggregateKeyType": "IP"
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "RateLimitRule"
  }
}
```

---

## Detection & Response

### GuardDuty

**Enable across organization:**
```bash
# Enable in management account
aws guardduty create-detector --enable

# Enable for all member accounts
aws guardduty create-members --detector-id xxx --account-details ...
```

**Key Finding Types:**
| Type | Description |
|------|-------------|
| UnauthorizedAccess | Suspicious API calls |
| Recon | Port scanning, discovery |
| Trojan | Malware indicators |
| Cryptocurrency | Mining activity |
| Backdoor | Command and control |

### Security Hub

**Enable with standards:**
```bash
aws securityhub enable-security-hub \
  --enable-default-standards

# Enable specific standard
aws securityhub batch-enable-standards \
  --standards-subscription-requests StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0
```

**Available Standards:**
- CIS AWS Foundations Benchmark
- AWS Foundational Security Best Practices
- PCI DSS
- NIST SP 800-53

### CloudTrail

**Organization Trail:**
```hcl
resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_organization_trail         = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}
```

### Config Rules

**Compliance Monitoring:**

| Rule | Purpose |
|------|---------|
| s3-bucket-public-read-prohibited | Block public S3 |
| encrypted-volumes | Require EBS encryption |
| iam-user-mfa-enabled | Enforce MFA |
| rds-instance-public-access-check | Block public RDS |
| vpc-sg-open-only-to-authorized-ports | Limit open ports |

**Auto-Remediation:**
```yaml
ConfigRule:
  Type: AWS::Config::ConfigRule
  Properties:
    ConfigRuleName: s3-bucket-public-read-prohibited
    Source:
      Owner: AWS
      SourceIdentifier: S3_BUCKET_PUBLIC_READ_PROHIBITED

RemediationConfiguration:
  Type: AWS::Config::RemediationConfiguration
  Properties:
    ConfigRuleName: !Ref ConfigRule
    TargetId: AWS-DisableS3BucketPublicReadWrite
    TargetType: SSM_DOCUMENT
    Automatic: true
```

---

## Compliance Patterns

### Data Residency

**Restrict to specific regions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "eu-west-1",
            "eu-central-1"
          ]
        }
      }
    }
  ]
}
```

### Audit Logging

**Centralized logging architecture:**

```
┌─────────────────────────────────────────────────┐
│                Member Accounts                  │
│  CloudTrail → S3 (local) → Replication         │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│               Log Archive Account               │
│  S3 (centralized) → Glacier (long-term)         │
│            ↓                                    │
│     CloudWatch Logs → OpenSearch                │
└─────────────────────────────────────────────────┘
```

### PCI DSS Considerations

| Requirement | AWS Implementation |
|-------------|-------------------|
| Network segmentation | VPC, Security Groups |
| Encryption at rest | KMS, S3 SSE, EBS encryption |
| Encryption in transit | TLS, ACM certificates |
| Access control | IAM, least privilege |
| Logging | CloudTrail, VPC Flow Logs |
| Vulnerability scanning | Inspector |

### HIPAA Considerations

| Requirement | AWS Implementation |
|-------------|-------------------|
| PHI encryption | KMS with CMK |
| Access controls | IAM, resource policies |
| Audit controls | CloudTrail, Config |
| Integrity | S3 Object Lock, Versioning |
| Transmission security | TLS 1.2+, VPN |
| BAA | AWS Business Associate Addendum |

---

## Incident Response

### Preparation

**Pre-provision access:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BreakGlassAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/IncidentResponseRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

### Containment

**Isolate compromised instance:**
```bash
# Create isolation security group (no rules)
aws ec2 create-security-group \
  --group-name isolation-sg \
  --description "Isolation for incident response"

# Apply to compromised instance
aws ec2 modify-instance-attribute \
  --instance-id i-xxx \
  --groups sg-isolation
```

### Investigation

**Capture evidence:**
```bash
# Create EBS snapshot
aws ec2 create-snapshot \
  --volume-id vol-xxx \
  --description "Incident response - $(date +%Y%m%d)"

# Enable VPC Flow Logs if not enabled
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-xxx \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::forensics-bucket
```

### Automation

**EventBridge rule for automated response:**
```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{"numeric": [">=", 7]}]
  }
}
```

**Lambda remediation:**
```python
def handler(event, context):
    finding = event['detail']

    if finding['type'].startswith('UnauthorizedAccess:IAMUser'):
        # Disable access key
        iam.update_access_key(
            UserName=finding['resource']['accessKeyDetails']['userName'],
            AccessKeyId=finding['resource']['accessKeyDetails']['accessKeyId'],
            Status='Inactive'
        )
```
