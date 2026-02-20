# LocalStack Service Parity

Service coverage and limitations compared to real AWS.

## Coverage Tiers

### Tier 1: High Parity (Community)

Core services with comprehensive coverage. Safe to rely on for most use cases.

| Service | Coverage | Notes |
|---------|----------|-------|
| S3 | High | Buckets, objects, versioning, lifecycle, presigned URLs |
| DynamoDB | High | Tables, indexes, streams, TTL, transactions |
| SQS | High | Queues, messages, FIFO, dead-letter |
| SNS | High | Topics, subscriptions, filters |
| Lambda | High | Functions, layers, event sources |
| Kinesis | High | Streams, shards, consumers |
| Secrets Manager | High | Secrets, rotation |
| SSM Parameter Store | High | Parameters, hierarchies |
| CloudWatch Logs | High | Log groups, streams, filters |
| Step Functions | High | State machines, executions |
| EventBridge | High | Rules, targets, buses |
| API Gateway | Medium-High | REST, HTTP APIs, stages |

### Tier 2: Good Parity (Pro Recommended)

Services that work well but may have gaps in advanced features.

| Service | Coverage | Notes |
|---------|----------|-------|
| CloudFormation | Medium-High | Most resources; some intrinsic functions limited |
| IAM | Medium-High (Pro) | Policies, roles; enforcement requires Pro |
| Cognito | Medium | User pools, identity pools |
| KMS | Medium-High | Keys, encryption/decryption |
| SES | Medium | Send email; limited analytics |
| EC2 | Medium | Instances, VPCs; limited networking |
| Route 53 | Medium | Hosted zones, records |
| ACM | Medium | Certificates |

### Tier 3: Partial Parity (Pro Required)

Services with significant limitations. Test critical paths on real AWS.

| Service | Coverage | Notes |
|---------|----------|-------|
| RDS | Medium (Pro) | MySQL, PostgreSQL; limited engines |
| ElastiCache | Medium (Pro) | Redis, Memcached |
| ECS | Medium (Pro) | Task definitions, services |
| EKS | Low-Medium (Pro) | Cluster management; limited k8s integration |
| Athena | Medium (Pro) | Queries; limited SQL support |
| Glue | Low-Medium (Pro) | Crawlers, jobs |
| AppSync | Medium (Pro) | GraphQL APIs |

### Tier 4: Basic/Experimental

Limited support. Use for basic testing only.

| Service | Coverage | Notes |
|---------|----------|-------|
| Redshift | Low | Basic operations |
| EMR | Low | Limited |
| Neptune | Low | Basic graph queries |
| DocumentDB | Low | Basic operations |
| MSK | Low | Basic Kafka |

## Known Limitations

### Lambda

| Feature | Status | Workaround |
|---------|--------|------------|
| Container images | Supported | - |
| Layers | Supported | - |
| Provisioned concurrency | Not supported | N/A |
| Reserved concurrency | Limited | - |
| SnapStart | Not supported | N/A |
| Extensions | Limited | - |

**Docker network issues:**
```bash
# If Lambda can't reach other containers
LAMBDA_DOCKER_NETWORK=host localstack start
# Or specify network name
LAMBDA_DOCKER_NETWORK=my-network localstack start
```

### S3

| Feature | Status | Notes |
|---------|--------|-------|
| Standard operations | Full | - |
| Versioning | Full | - |
| Lifecycle rules | Full | - |
| Presigned URLs | Full | Check clock sync |
| Object Lock | Partial | - |
| S3 Select | Partial | - |
| Glacier | Limited | - |
| Transfer Acceleration | Not supported | - |

### DynamoDB

| Feature | Status | Notes |
|---------|--------|-------|
| CRUD operations | Full | - |
| GSI/LSI | Full | - |
| Streams | Full | - |
| Transactions | Full | - |
| TTL | Full | - |
| PartiQL | Partial | - |
| DAX | Not supported | - |

### CloudFormation

| Feature | Status | Notes |
|---------|--------|-------|
| Basic resources | Full | - |
| Nested stacks | Supported | - |
| Custom resources | Supported | - |
| Drift detection | Limited | - |
| Change sets | Limited | - |
| StackSets | Not supported | - |

**Unsupported intrinsic functions:**
- Some `Fn::` functions may behave differently
- Test complex templates on real AWS

### IAM (Pro)

| Feature | Status | Notes |
|---------|--------|-------|
| Policies | Full | - |
| Roles | Full | - |
| Users/Groups | Full | - |
| Policy enforcement | Pro only | Community ignores policies |
| STS assume role | Supported | - |
| OIDC providers | Limited | - |

## Parity Testing Strategy

### Verify Critical Paths

```python
import pytest
import os

@pytest.fixture(params=["localstack", "aws"])
def aws_env(request):
    if request.param == "localstack":
        return {"endpoint_url": "http://localhost:4566"}
    return {}  # Real AWS

def test_s3_upload_download(aws_env, s3_client):
    """Test on both LocalStack and real AWS."""
    s3_client.put_object(Bucket="test", Key="file.txt", Body=b"data")
    response = s3_client.get_object(Bucket="test", Key="file.txt")
    assert response["Body"].read() == b"data"
```

### Document Differences

When you find parity gaps:

1. **Note the specific difference**
2. **Check LocalStack GitHub issues**
3. **Consider workarounds**
4. **Test critical flows on real AWS periodically**

### Recommended Testing Matrix

| Test Type | LocalStack | Real AWS | Frequency |
|-----------|------------|----------|-----------|
| Unit tests | Yes | No | Every commit |
| Integration | Yes | No | Every commit |
| E2E (happy path) | Yes | Yes | Weekly |
| E2E (edge cases) | Yes | Yes | Before release |
| Performance | No | Yes | Before release |

## Service-Specific Tips

### Lambda Best Practices

```bash
# Pre-pull runtime images for faster cold starts
docker pull public.ecr.aws/lambda/python:3.11

# Use hot reloading for development
LAMBDA_REMOTE_DOCKER=0 localstack start
```

### DynamoDB Best Practices

```bash
# Increase heap for large tables
DYNAMODB_HEAP_SIZE=512m localstack start
```

### CloudFormation Best Practices

- Test template syntax with `awslocal cloudformation validate-template`
- Use `SERVICES=cloudformation,s3,dynamodb,...` to include all required services
- Check resource support in LocalStack docs before using

## Getting Help

- **Documentation**: https://docs.localstack.cloud/
- **GitHub Issues**: https://github.com/localstack/localstack/issues
- **Slack Community**: https://aws-localstack.cloud/slack
- **Coverage Docs**: https://docs.localstack.cloud/references/coverage/
