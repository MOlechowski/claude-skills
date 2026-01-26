---
name: localstack-expert
description: "LocalStack architecture expertise: testing strategies, CI/CD integration, service parity, state management, Pro features. Use for: designing local AWS testing, choosing LocalStack vs real AWS, CI pipeline setup, debugging service differences, Cloud Pods strategy. Triggers: localstack architecture, local aws testing, localstack ci, localstack pro, aws emulation strategy, cloud pods."
---

# LocalStack Expert

Architecture guidance for LocalStack-based AWS emulation. Delegates CLI operations to `localstack` and `awslocal` skills.

## Decision Matrix: LocalStack vs Real AWS

| Scenario | Recommendation |
|----------|----------------|
| Unit tests | LocalStack |
| Integration tests | LocalStack |
| E2E tests (critical paths) | Both LocalStack + real AWS |
| Load/performance testing | Real AWS |
| Security testing | Real AWS |
| Cost estimation | Real AWS |
| Local development | LocalStack |
| CI/CD pipelines | LocalStack |

## Decision Matrix: Community vs Pro

| Need | Community | Pro |
|------|-----------|-----|
| Core services (S3, DynamoDB, SQS, SNS, Lambda) | Yes | Yes |
| Advanced services (RDS, ECS, EKS, Athena) | Limited | Full |
| IAM policy enforcement | No | Yes |
| Cloud Pods (state snapshots) | No | Yes |
| Chaos engineering | No | Yes |
| CI analytics | No | Yes |
| Team collaboration | No | Yes |

## Testing Strategy

### Test Pyramid with LocalStack

```
        /\
       /  \     E2E (real AWS for critical paths)
      /----\
     /      \   Integration (LocalStack)
    /--------\
   /          \ Unit (mocks + LocalStack for AWS SDK)
  /------------\
```

### Recommended Approach

1. **Unit tests**: Mock AWS SDK calls or use LocalStack for realistic responses
2. **Integration tests**: LocalStack for all AWS interactions
3. **E2E tests**: Run against LocalStack in CI, periodically validate against real AWS
4. **Pre-production**: Real AWS with minimal resources

### Test Configuration Pattern

```python
# conftest.py
import pytest
import os

@pytest.fixture(scope="session")
def aws_endpoint():
    """Return endpoint URL based on environment."""
    if os.getenv("USE_LOCALSTACK", "true").lower() == "true":
        return "http://localhost:4566"
    return None  # Use real AWS

@pytest.fixture
def s3_client(aws_endpoint):
    import boto3
    return boto3.client(
        "s3",
        endpoint_url=aws_endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1"
    )
```

## State Management

### Options Comparison

| Method | Use Case | Persistence |
|--------|----------|-------------|
| Ephemeral | Fast CI, isolation | None |
| `PERSISTENCE=1` | Container restarts | Local volume |
| Cloud Pods | Team sharing, CI seeding | Remote |
| State export/import | Backup, migration | File-based |

### Cloud Pods Strategy

For detailed Cloud Pods commands, see `references/ci-patterns.md`.

**When to use Cloud Pods:**
- Pre-seed CI with test data
- Share debugging state with team
- Version infrastructure configurations
- Reproduce customer issues

**Merge strategies:**
- `overwrite`: Complete replacement (clean slate)
- `account-region-merge`: Merge by account/region (default)
- `service-merge`: Merge only non-overlapping resources

## CI/CD Integration

See `references/ci-patterns.md` for complete YAML examples.

### Quick Reference

| Platform | Action/Image |
|----------|--------------|
| GitHub Actions | `LocalStack/setup-localstack@v0.2.3` |
| GitLab CI | `localstack/localstack` service |
| CircleCI | `localstack/localstack` Docker image |
| Jenkins | Docker agent with LocalStack |

### CI Best Practices

1. **Use ephemeral instances**: Start fresh each job for isolation
2. **Pre-seed with Cloud Pods**: Load known state for consistent tests
3. **Limit services**: Set `SERVICES=` to reduce startup time
4. **Cache Docker images**: Reduce pull time
5. **Parallel execution**: LocalStack handles concurrent requests

## Anti-Patterns

| Anti-Pattern | Problem | Solution |
|--------------|---------|----------|
| Testing against real AWS in CI | Slow, costly, flaky | Use LocalStack |
| No service limits | Slow startup | Set `SERVICES=s3,dynamodb,...` |
| Hardcoded endpoints | Inflexible | Use env vars for endpoint URL |
| Ignoring parity gaps | False confidence | Know limitations, test critical paths on real AWS |
| Manual state setup | Inconsistent | Use Cloud Pods or init scripts |
| Running as root | Security risk | Use non-root user |

## Service Parity Considerations

See `references/service-parity.md` for detailed coverage.

**High parity (safe to rely on):**
- S3, DynamoDB, SQS, SNS, Lambda, Kinesis
- IAM (Pro), Secrets Manager, SSM Parameter Store
- Step Functions, EventBridge, CloudWatch Logs

**Partial parity (verify behavior):**
- RDS (Pro), ElastiCache (Pro)
- EC2 (basic operations)
- CloudFormation (most resources)

**Check before using:**
- EKS, ECS (Pro, varies by feature)
- Athena, Glue (Pro)
- Complex IAM policies

## Debugging LocalStack Issues

### Service Differences

```bash
# Enable debug logging
DEBUG=1 localstack start

# Check service status
localstack status services

# View detailed logs
localstack logs -f

# Generate diagnostic report
curl localhost:4566/_localstack/diagnose | gzip > diagnose.json.gz
```

### Common Issues

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Different behavior than AWS | Service parity gap | Check docs, test on real AWS |
| Lambda timeout | Network/Docker issues | Check `LAMBDA_DOCKER_NETWORK` |
| Slow Lambda cold start | Image pull | Pre-pull base images |
| S3 presigned URL fails | Clock skew | Sync system time |
| CloudFormation drift | Partial resource support | Check resource coverage |

## Pro Features Overview

| Feature | Use Case |
|---------|----------|
| IAM Enforcement | Test permission policies |
| Cloud Pods | State sharing and CI seeding |
| Chaos Engineering | Fault injection testing |
| Stack Insights | Resource visualization |
| CI Analytics | Test run tracking |
| Extensions | Custom service emulation |

## References

- `references/ci-patterns.md` - CI/CD YAML templates (GitHub Actions, GitLab, etc.)
- `references/service-parity.md` - Service coverage and limitations

## Integration

- For CLI commands: use `localstack` skill
- For AWS CLI commands: use `awslocal` skill
