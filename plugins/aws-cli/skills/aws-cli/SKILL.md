---
name: aws-cli
description: "AWS CLI v2 expertise: authentication (IAM, SSO, roles, profiles), 20+ service commands, output formatting (--query, jq), multi-account patterns, CI/CD integration. Use for: aws commands, credential management, scripting AWS operations, debugging API calls. Triggers: aws cli, aws configure, aws s3, aws ec2, assume-role, aws sso."
---

# AWS CLI

AWS CLI v2 expertise for command-line operations, authentication, scripting, and automation.

For architecture guidance, see: `aws-expert` skill.
For IaC implementation, see: `iac-terraform` or `iac-tofu` skills.

## Authentication Methods

### Credential Priority (highest to lowest)

1. Command line `--profile` option
2. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
3. Web identity token (OIDC)
4. Credentials/config file profiles
5. IAM role (EC2 instance profile, ECS task role, Lambda execution role)

### SSO (IAM Identity Center)

**Recommended for human users:**

```bash
# Configure SSO profile
aws configure sso
# Prompts for: SSO start URL, SSO region, account, role, profile name

# Login
aws sso login --profile my-sso-profile

# Use
aws s3 ls --profile my-sso-profile

# Logout
aws sso logout
```

**Config file (~/.aws/config):**
```ini
[profile my-sso-profile]
sso_start_url = https://my-org.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = AdministratorAccess
region = us-west-2
output = json
```

### IAM User Credentials

**For programmatic access (prefer roles when possible):**

```bash
# Configure default profile
aws configure

# Configure named profile
aws configure --profile production

# Set specific values
aws configure set region us-west-2 --profile production
aws configure set output json
```

**Files:**
- `~/.aws/credentials` - Access keys
- `~/.aws/config` - Region, output, profiles

### Assume Role

**For cross-account and elevated privileges:**

```bash
# Manual assume role
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --role-session-name my-session

# Auto-assume via profile config
[profile cross-account]
role_arn = arn:aws:iam::123456789012:role/MyRole
source_profile = default
region = us-west-2

# With MFA
[profile mfa-protected]
role_arn = arn:aws:iam::123456789012:role/MyRole
source_profile = default
mfa_serial = arn:aws:iam::111111111111:mfa/my-user
```

### Environment Variables

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...          # For temporary credentials
export AWS_DEFAULT_REGION=us-west-2
export AWS_PROFILE=production         # Use specific profile
export AWS_ROLE_ARN=arn:aws:iam::...  # For web identity
```

## Output Formatting

### Output Formats

```bash
aws ec2 describe-instances --output json   # Default, full detail
aws ec2 describe-instances --output table  # Human-readable tables
aws ec2 describe-instances --output text   # Tab-separated, scriptable
aws ec2 describe-instances --output yaml   # YAML format
```

### JMESPath Queries (--query)

**Basic filtering:**
```bash
# Get specific field
aws ec2 describe-instances --query 'Reservations[*].Instances[*].InstanceId'

# Flatten nested arrays
aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text

# Filter by condition
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?State.Name==`running`].InstanceId'

# Multiple fields
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name]' \
  --output table

# Named columns
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{ID:InstanceId,Type:InstanceType,State:State.Name}' \
  --output table
```

**Common patterns:**
```bash
# First item only
--query 'Items[0]'

# Last item
--query 'Items[-1]'

# Sort by field
--query 'sort_by(Items, &Name)'

# Reverse sort
--query 'reverse(sort_by(Items, &Date))'

# Contains filter
--query "Items[?contains(Name, 'prod')]"

# Length
--query 'length(Items)'
```

### jq Integration

```bash
# Complex transformations
aws ec2 describe-instances | jq '.Reservations[].Instances[] | {id: .InstanceId, type: .InstanceType}'

# Filter and count
aws s3api list-objects-v2 --bucket my-bucket | jq '[.Contents[] | select(.Size > 1000000)] | length'

# Extract specific values
aws lambda list-functions | jq -r '.Functions[].FunctionName'
```

### Pagination

```bash
# Auto-pagination (default)
aws s3api list-objects-v2 --bucket my-bucket

# Manual pagination
aws s3api list-objects-v2 --bucket my-bucket --max-items 100
# Returns NextToken in output

aws s3api list-objects-v2 --bucket my-bucket --starting-token <NextToken>

# Disable pagination
aws s3api list-objects-v2 --bucket my-bucket --no-paginate

# Page size (items per API call)
aws s3api list-objects-v2 --bucket my-bucket --page-size 1000
```

## Multi-Account Patterns

### Profile-Based Switching

```ini
# ~/.aws/config
[profile dev]
region = us-west-2

[profile staging]
region = us-west-2

[profile prod]
region = us-east-1
```

```bash
# Switch with --profile
aws s3 ls --profile dev
aws s3 ls --profile prod

# Switch with environment variable
export AWS_PROFILE=prod
aws s3 ls
```

### Cross-Account Role Assumption

```ini
# ~/.aws/config
[profile prod-admin]
role_arn = arn:aws:iam::PROD_ACCOUNT:role/AdminRole
source_profile = dev
region = us-east-1
```

```bash
# Uses dev credentials to assume prod role
aws s3 ls --profile prod-admin
```

### Organization-Wide Commands

```bash
# List all accounts
aws organizations list-accounts

# List organizational units
aws organizations list-roots
aws organizations list-organizational-units-for-parent --parent-id r-xxxx

# Get account info
aws organizations describe-account --account-id 123456789012
```

### Multi-Account Script Pattern

```bash
#!/bin/bash
# Run command across multiple accounts
accounts=("dev" "staging" "prod")

for profile in "${accounts[@]}"; do
  echo "=== $profile ==="
  aws s3 ls --profile "$profile"
done
```

## Debugging

### Debug Mode

```bash
# Full debug output
aws s3 ls --debug

# Debug to file
aws s3 ls --debug 2> debug.log
```

### Dry Run

```bash
# Check permissions without executing
aws ec2 run-instances \
  --image-id ami-12345678 \
  --instance-type t3.micro \
  --dry-run
```

### Credential Debugging

```bash
# Verify identity
aws sts get-caller-identity

# Check credential source
aws configure list

# Test specific permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/my-user \
  --action-names s3:GetObject
```

### Common Error Codes

| Error | Cause | Solution |
|-------|-------|----------|
| `ExpiredToken` | Session token expired | Re-authenticate (`aws sso login` or new session) |
| `InvalidClientTokenId` | Wrong access key | Check credentials configuration |
| `AccessDenied` | Insufficient permissions | Check IAM policies, resource policies |
| `UnauthorizedAccess` | Wrong account/role | Verify `aws sts get-caller-identity` |
| `ThrottlingException` | Rate limit hit | Add retries with backoff |
| `ResourceNotFoundException` | Resource doesn't exist | Verify resource name, region |
| `ValidationError` | Invalid parameters | Check command syntax, parameter values |

## CI/CD Integration

### GitHub Actions (OIDC)

```yaml
# .github/workflows/deploy.yml
name: Deploy
on: push

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-west-2

      - name: Deploy
        run: aws s3 sync ./dist s3://my-bucket/
```

**IAM Role Trust Policy for GitHub OIDC:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:*"
        }
      }
    }
  ]
}
```

### GitLab CI (OIDC)

```yaml
# .gitlab-ci.yml
deploy:
  image: amazon/aws-cli:latest
  id_tokens:
    AWS_TOKEN:
      aud: https://gitlab.com
  script:
    - >
      export $(printf "AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s"
      $(aws sts assume-role-with-web-identity
      --role-arn arn:aws:iam::123456789012:role/GitLabRole
      --role-session-name "GitLabRunner-${CI_PROJECT_ID}-${CI_PIPELINE_ID}"
      --web-identity-token ${AWS_TOKEN}
      --duration-seconds 3600
      --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]'
      --output text))
    - aws s3 sync ./dist s3://my-bucket/
```

For complete CI/CD examples, see: [references/examples.md](references/examples.md)

## Local Development Tools

### LocalStack

```bash
# Start LocalStack
docker run -d -p 4566:4566 localstack/aws-localstack

# Configure endpoint
aws --endpoint-url=http://localhost:4566 s3 ls

# Or use profile
[profile localstack]
endpoint_url = http://localhost:4566
region = us-east-1

aws s3 ls --profile localstack
```

### SAM CLI

```bash
# Initialize new project
sam init

# Local invoke
sam local invoke MyFunction --event event.json

# Local API
sam local start-api

# Build
sam build

# Deploy
sam deploy --guided
```

### CDK CLI

```bash
# Initialize
cdk init app --language typescript

# Synthesize CloudFormation
cdk synth

# Deploy
cdk deploy

# Diff (preview changes)
cdk diff

# Destroy
cdk destroy
```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `Unable to locate credentials` | No credentials configured | Run `aws configure` or check env vars |
| `The security token included in the request is expired` | Session expired | `aws sso login` or refresh credentials |
| `An error occurred (AccessDenied)` | Insufficient permissions | Check IAM policies with `iam simulate-principal-policy` |
| `Could not connect to the endpoint URL` | Wrong region or endpoint | Check `--region` or endpoint URL |
| `Partial credentials found` | Missing secret key | Check both access key and secret are set |
| `Profile not found` | Missing profile config | Add profile to `~/.aws/config` |
| `Token has expired` | SSO session expired | `aws sso login --profile <name>` |
| `Maximum number of retries exceeded` | Network/throttling issues | Check connectivity, add jitter/backoff |

## References

### Local Reference Files
- [references/services.md](references/services.md) - Service commands (S3, EC2, Lambda, ECS, RDS, DynamoDB, IAM, CloudFormation, CloudWatch, Secrets Manager, STS, Cost)
- [references/quick-reference.md](references/quick-reference.md) - Command cheatsheet
- [references/examples.md](references/examples.md) - Scripting and CI/CD examples

### Official Documentation
- [AWS CLI v2 User Guide](https://docs.aws.amazon.com/cli/latest/userguide/)
- [AWS CLI Command Reference](https://awscli.amazonaws.com/v2/documentation/api/latest/index.html)
- [JMESPath Tutorial](https://jmespath.org/tutorial.html)
- [AWS SSO Configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
