# AWS CLI Scripting Examples

Complete patterns for automation, CI/CD, and multi-account operations.

## CI/CD Workflows

### GitHub Actions with OIDC

**IAM Role Trust Policy:**
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

**Workflow file (.github/workflows/deploy.yml):**
```yaml
name: Deploy to AWS
on:
  push:
    branches: [main]

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

      - name: Deploy to S3
        run: aws s3 sync ./dist s3://my-bucket/ --delete

      - name: Invalidate CloudFront
        run: |
          aws cloudfront create-invalidation \
            --distribution-id E123456789 \
            --paths "/*"
```

**Multi-environment deployment:**
```yaml
name: Deploy
on:
  push:
    branches: [main, staging]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Set environment
        run: |
          if [ "${{ github.ref_name }}" == "main" ]; then
            echo "ENV=prod" >> $GITHUB_ENV
            echo "ROLE_ARN=arn:aws:iam::111111111111:role/GitHubProdRole" >> $GITHUB_ENV
            echo "BUCKET=prod-bucket" >> $GITHUB_ENV
          else
            echo "ENV=staging" >> $GITHUB_ENV
            echo "ROLE_ARN=arn:aws:iam::222222222222:role/GitHubStagingRole" >> $GITHUB_ENV
            echo "BUCKET=staging-bucket" >> $GITHUB_ENV
          fi

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ env.ROLE_ARN }}
          aws-region: us-west-2

      - name: Deploy
        run: aws s3 sync ./dist s3://${{ env.BUCKET }}/
```

### GitLab CI with OIDC

**.gitlab-ci.yml:**
```yaml
stages:
  - deploy

variables:
  AWS_REGION: us-west-2

deploy:
  stage: deploy
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
    - aws sts get-caller-identity
    - aws s3 sync ./dist s3://my-bucket/
  only:
    - main
```

### ECR + ECS Deployment

```yaml
name: Deploy to ECS
on:
  push:
    branches: [main]

env:
  AWS_REGION: us-west-2
  ECR_REPOSITORY: my-app
  ECS_CLUSTER: my-cluster
  ECS_SERVICE: my-service

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Build and push image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
          echo "image=$ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG" >> $GITHUB_OUTPUT
        id: build-image

      - name: Update ECS service
        run: |
          aws ecs update-service \
            --cluster $ECS_CLUSTER \
            --service $ECS_SERVICE \
            --force-new-deployment

      - name: Wait for deployment
        run: |
          aws ecs wait services-stable \
            --cluster $ECS_CLUSTER \
            --services $ECS_SERVICE
```

### Lambda Deployment

```yaml
name: Deploy Lambda
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install and build
        run: |
          npm ci
          npm run build
          cd dist && zip -r ../function.zip .

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-west-2

      - name: Deploy Lambda
        run: |
          aws lambda update-function-code \
            --function-name my-function \
            --zip-file fileb://function.zip

          # Wait for update to complete
          aws lambda wait function-updated \
            --function-name my-function

      - name: Publish version
        run: |
          VERSION=$(aws lambda publish-version \
            --function-name my-function \
            --query 'Version' --output text)

          aws lambda update-alias \
            --function-name my-function \
            --name prod \
            --function-version $VERSION
```

## Multi-Account Scripts

### Run Command Across Accounts

```bash
#!/bin/bash
# run-across-accounts.sh - Execute AWS command in multiple accounts

PROFILES=("dev" "staging" "prod")
COMMAND="$*"

if [ -z "$COMMAND" ]; then
  echo "Usage: $0 <aws command>"
  echo "Example: $0 s3 ls"
  exit 1
fi

for profile in "${PROFILES[@]}"; do
  echo "=========================================="
  echo "Account: $profile"
  echo "=========================================="
  aws $COMMAND --profile "$profile"
  echo ""
done
```

### Cross-Account Resource Inventory

```bash
#!/bin/bash
# inventory.sh - Collect resource inventory across accounts

PROFILES=("dev" "staging" "prod")
OUTPUT_DIR="./inventory-$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

for profile in "${PROFILES[@]}"; do
  echo "Processing: $profile"

  # Get account ID
  ACCOUNT_ID=$(aws sts get-caller-identity --profile "$profile" --query 'Account' --output text)

  # EC2 instances
  aws ec2 describe-instances --profile "$profile" \
    --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name,Tags[?Key==`Name`].Value|[0]]' \
    --output json > "$OUTPUT_DIR/${profile}_ec2.json"

  # RDS instances
  aws rds describe-db-instances --profile "$profile" \
    --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceClass,Engine,DBInstanceStatus]' \
    --output json > "$OUTPUT_DIR/${profile}_rds.json"

  # Lambda functions
  aws lambda list-functions --profile "$profile" \
    --query 'Functions[].[FunctionName,Runtime,MemorySize]' \
    --output json > "$OUTPUT_DIR/${profile}_lambda.json"

  # S3 buckets
  aws s3api list-buckets --profile "$profile" \
    --query 'Buckets[].[Name,CreationDate]' \
    --output json > "$OUTPUT_DIR/${profile}_s3.json"

done

echo "Inventory saved to: $OUTPUT_DIR"
```

### Assume Role Helper

```bash
#!/bin/bash
# assume-role.sh - Assume role and export credentials

ROLE_ARN="$1"
SESSION_NAME="${2:-cli-session}"

if [ -z "$ROLE_ARN" ]; then
  echo "Usage: $0 <role-arn> [session-name]"
  exit 1
fi

# Assume role and parse credentials
CREDS=$(aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name "$SESSION_NAME" \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
  --output text)

# Export as environment variables
export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | cut -f1)
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | cut -f2)
export AWS_SESSION_TOKEN=$(echo "$CREDS" | cut -f3)

echo "Assumed role: $ROLE_ARN"
aws sts get-caller-identity
```

**Usage:**
```bash
source ./assume-role.sh arn:aws:iam::123456789012:role/AdminRole
```

## Automation Scripts

### EC2 Instance Management

```bash
#!/bin/bash
# ec2-manage.sh - Start/stop EC2 instances by tag

ACTION="$1"  # start, stop, status
TAG_KEY="${2:-Environment}"
TAG_VALUE="${3:-dev}"

get_instances() {
  aws ec2 describe-instances \
    --filters "Name=tag:$TAG_KEY,Values=$TAG_VALUE" \
    --query 'Reservations[].Instances[].[InstanceId,State.Name,Tags[?Key==`Name`].Value|[0]]' \
    --output text
}

case "$ACTION" in
  start)
    INSTANCE_IDS=$(aws ec2 describe-instances \
      --filters "Name=tag:$TAG_KEY,Values=$TAG_VALUE" "Name=instance-state-name,Values=stopped" \
      --query 'Reservations[].Instances[].InstanceId' --output text)

    if [ -n "$INSTANCE_IDS" ]; then
      echo "Starting: $INSTANCE_IDS"
      aws ec2 start-instances --instance-ids $INSTANCE_IDS
    else
      echo "No stopped instances found"
    fi
    ;;

  stop)
    INSTANCE_IDS=$(aws ec2 describe-instances \
      --filters "Name=tag:$TAG_KEY,Values=$TAG_VALUE" "Name=instance-state-name,Values=running" \
      --query 'Reservations[].Instances[].InstanceId' --output text)

    if [ -n "$INSTANCE_IDS" ]; then
      echo "Stopping: $INSTANCE_IDS"
      aws ec2 stop-instances --instance-ids $INSTANCE_IDS
    else
      echo "No running instances found"
    fi
    ;;

  status)
    echo "Instances with $TAG_KEY=$TAG_VALUE:"
    get_instances | column -t
    ;;

  *)
    echo "Usage: $0 {start|stop|status} [tag-key] [tag-value]"
    exit 1
    ;;
esac
```

### S3 Backup Script

```bash
#!/bin/bash
# s3-backup.sh - Backup directory to S3 with timestamp

SOURCE_DIR="$1"
BUCKET="$2"
PREFIX="${3:-backups}"

if [ -z "$SOURCE_DIR" ] || [ -z "$BUCKET" ]; then
  echo "Usage: $0 <source-dir> <bucket> [prefix]"
  exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DEST="s3://$BUCKET/$PREFIX/$TIMESTAMP/"

echo "Backing up $SOURCE_DIR to $DEST"

aws s3 sync "$SOURCE_DIR" "$DEST" \
  --exclude "*.log" \
  --exclude "*.tmp" \
  --exclude ".git/*"

if [ $? -eq 0 ]; then
  echo "Backup completed: $DEST"

  # Clean up old backups (keep last 7)
  aws s3 ls "s3://$BUCKET/$PREFIX/" | \
    sort -r | \
    tail -n +8 | \
    awk '{print $2}' | \
    while read dir; do
      echo "Removing old backup: $dir"
      aws s3 rm "s3://$BUCKET/$PREFIX/$dir" --recursive
    done
else
  echo "Backup failed"
  exit 1
fi
```

### CloudWatch Log Export

```bash
#!/bin/bash
# export-logs.sh - Export CloudWatch logs to S3

LOG_GROUP="$1"
BUCKET="$2"
DAYS_AGO="${3:-1}"

if [ -z "$LOG_GROUP" ] || [ -z "$BUCKET" ]; then
  echo "Usage: $0 <log-group> <bucket> [days-ago]"
  exit 1
fi

# Calculate time range (milliseconds)
END_TIME=$(date +%s)000
START_TIME=$(date -d "$DAYS_AGO days ago" +%s)000

TASK_ID=$(aws logs create-export-task \
  --log-group-name "$LOG_GROUP" \
  --from "$START_TIME" \
  --to "$END_TIME" \
  --destination "$BUCKET" \
  --destination-prefix "logs/$(basename $LOG_GROUP)/$(date +%Y/%m/%d)" \
  --query 'taskId' --output text)

echo "Export task started: $TASK_ID"

# Wait for completion
while true; do
  STATUS=$(aws logs describe-export-tasks \
    --task-id "$TASK_ID" \
    --query 'exportTasks[0].status.code' --output text)

  echo "Status: $STATUS"

  if [ "$STATUS" == "COMPLETED" ]; then
    echo "Export completed successfully"
    break
  elif [ "$STATUS" == "FAILED" ] || [ "$STATUS" == "CANCELLED" ]; then
    echo "Export failed"
    exit 1
  fi

  sleep 10
done
```

### Lambda Batch Invoke

```bash
#!/bin/bash
# batch-invoke.sh - Invoke Lambda for each item in a file

FUNCTION_NAME="$1"
INPUT_FILE="$2"

if [ -z "$FUNCTION_NAME" ] || [ -z "$INPUT_FILE" ]; then
  echo "Usage: $0 <function-name> <input-file>"
  echo "Input file should have one JSON payload per line"
  exit 1
fi

TOTAL=$(wc -l < "$INPUT_FILE")
COUNT=0
ERRORS=0

while IFS= read -r payload; do
  COUNT=$((COUNT + 1))
  echo -n "[$COUNT/$TOTAL] Invoking... "

  RESPONSE=$(aws lambda invoke \
    --function-name "$FUNCTION_NAME" \
    --payload "$payload" \
    --cli-binary-format raw-in-base64-out \
    /tmp/lambda-response.json 2>&1)

  if echo "$RESPONSE" | grep -q "FunctionError"; then
    echo "ERROR"
    ERRORS=$((ERRORS + 1))
    cat /tmp/lambda-response.json
  else
    echo "OK"
  fi
done < "$INPUT_FILE"

echo "Completed: $COUNT invocations, $ERRORS errors"
```

## Cost Analysis Scripts

### Cost Report by Service

```bash
#!/bin/bash
# cost-by-service.sh - Generate cost report grouped by service

START_DATE="${1:-$(date -d 'first day of last month' +%Y-%m-%d)}"
END_DATE="${2:-$(date -d 'first day of this month' +%Y-%m-%d)}"

echo "Cost report: $START_DATE to $END_DATE"
echo "=========================================="

aws ce get-cost-and-usage \
  --time-period "Start=$START_DATE,End=$END_DATE" \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --query 'ResultsByTime[].Groups[].{Service:Keys[0],Cost:Metrics.UnblendedCost.Amount}' \
  --output json | \
jq -r 'sort_by(.Cost | tonumber) | reverse | .[] | "\(.Cost | tonumber | . * 100 | round / 100)\t\(.Service)"' | \
column -t -s $'\t'
```

### Unused Resources Finder

```bash
#!/bin/bash
# find-unused.sh - Find potentially unused AWS resources

echo "=== Unattached EBS Volumes ==="
aws ec2 describe-volumes \
  --filters "Name=status,Values=available" \
  --query 'Volumes[].[VolumeId,Size,CreateTime]' \
  --output table

echo ""
echo "=== Unused Elastic IPs ==="
aws ec2 describe-addresses \
  --query 'Addresses[?AssociationId==null].[PublicIp,AllocationId]' \
  --output table

echo ""
echo "=== Old Snapshots (>90 days) ==="
CUTOFF=$(date -d '90 days ago' +%Y-%m-%dT%H:%M:%S)
aws ec2 describe-snapshots \
  --owner-ids self \
  --query "Snapshots[?StartTime<='$CUTOFF'].[SnapshotId,VolumeSize,StartTime,Description]" \
  --output table

echo ""
echo "=== Stopped EC2 Instances ==="
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=stopped" \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType,Tags[?Key==`Name`].Value|[0],StateTransitionReason]' \
  --output table

echo ""
echo "=== Unused Load Balancers ==="
for arn in $(aws elbv2 describe-load-balancers --query 'LoadBalancers[].LoadBalancerArn' --output text); do
  TG_COUNT=$(aws elbv2 describe-target-groups --load-balancer-arn "$arn" --query 'length(TargetGroups)' --output text)
  if [ "$TG_COUNT" == "0" ]; then
    aws elbv2 describe-load-balancers --load-balancer-arns "$arn" \
      --query 'LoadBalancers[].[LoadBalancerName,CreatedTime]' --output text
  fi
done
```

### Tag Compliance Checker

```bash
#!/bin/bash
# tag-compliance.sh - Check resources for required tags

REQUIRED_TAGS=("Environment" "Owner" "CostCenter")
RESOURCE_TYPES=("ec2:instance" "rds:db" "lambda:function")

echo "Tag Compliance Report"
echo "Required tags: ${REQUIRED_TAGS[*]}"
echo "=========================================="

for resource_type in "${RESOURCE_TYPES[@]}"; do
  echo ""
  echo "=== $resource_type ==="

  aws resourcegroupstaggingapi get-resources \
    --resource-type-filters "$resource_type" \
    --query 'ResourceTagMappingList[].[ResourceARN,Tags[].Key]' \
    --output json | \
  jq -r --argjson required "$(printf '%s\n' "${REQUIRED_TAGS[@]}" | jq -R . | jq -s .)" '
    .[] |
    . as $resource |
    ($required - ($resource[1] // [])) as $missing |
    select(($missing | length) > 0) |
    "\($resource[0])\tMissing: \($missing | join(", "))"
  ' | column -t -s $'\t'
done
```

## Security Scripts

### IAM Access Key Audit

```bash
#!/bin/bash
# iam-key-audit.sh - Audit IAM access keys for age and usage

MAX_AGE_DAYS="${1:-90}"
CUTOFF=$(date -d "$MAX_AGE_DAYS days ago" +%Y-%m-%dT%H:%M:%S)

echo "IAM Access Key Audit (max age: $MAX_AGE_DAYS days)"
echo "=========================================="

aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | while read user; do
  aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].[UserName,AccessKeyId,Status,CreateDate]' --output text | while read line; do
    KEY_DATE=$(echo "$line" | awk '{print $4}')
    if [[ "$KEY_DATE" < "$CUTOFF" ]]; then
      LAST_USED=$(aws iam get-access-key-last-used --access-key-id $(echo "$line" | awk '{print $2}') --query 'AccessKeyLastUsed.LastUsedDate' --output text 2>/dev/null || echo "Never")
      echo "$line LastUsed: $LAST_USED"
    fi
  done
done | column -t
```

### Security Group Audit

```bash
#!/bin/bash
# sg-audit.sh - Find security groups with overly permissive rules

echo "Security Groups with 0.0.0.0/0 Ingress"
echo "=========================================="

aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName,IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]].[FromPort,ToPort,IpProtocol]]' \
  --output json | \
jq -r '.[] | "\(.[0])\t\(.[1])\t\(.[2] | map("\(.[2]):\(.[0])-\(.[1])") | join(", "))"' | \
column -t -s $'\t'
```

### Public S3 Bucket Check

```bash
#!/bin/bash
# public-buckets.sh - Find S3 buckets with public access

echo "Checking S3 bucket public access..."
echo "=========================================="

for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  # Check public access block
  PAB=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)

  if [ -z "$PAB" ]; then
    echo "WARNING: $bucket - No public access block configured"
  else
    BLOCK_PUBLIC=$(echo "$PAB" | jq -r '.PublicAccessBlockConfiguration | .BlockPublicAcls and .BlockPublicPolicy')
    if [ "$BLOCK_PUBLIC" != "true" ]; then
      echo "WARNING: $bucket - Public access not fully blocked"
    fi
  fi

  # Check bucket ACL
  ACL=$(aws s3api get-bucket-acl --bucket "$bucket" 2>/dev/null)
  PUBLIC_ACL=$(echo "$ACL" | jq -r '.Grants[] | select(.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" or .Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")')

  if [ -n "$PUBLIC_ACL" ]; then
    echo "WARNING: $bucket - Public ACL detected"
  fi
done
```

## LocalStack Testing

### LocalStack Setup

```bash
#!/bin/bash
# localstack-setup.sh - Start LocalStack and configure AWS CLI

# Start LocalStack
docker run -d \
  --name localstack \
  -p 4566:4566 \
  -e SERVICES=s3,dynamodb,lambda,sqs \
  localstack/localstack

# Wait for LocalStack to be ready
echo "Waiting for LocalStack..."
until aws --endpoint-url=http://localhost:4566 s3 ls 2>/dev/null; do
  sleep 1
done
echo "LocalStack ready!"

# Create test resources
aws --endpoint-url=http://localhost:4566 s3 mb s3://test-bucket
aws --endpoint-url=http://localhost:4566 dynamodb create-table \
  --table-name test-table \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### LocalStack Profile

```ini
# ~/.aws/config
[profile localstack]
region = us-east-1
endpoint_url = http://localhost:4566

[profile localstack.services.s3]
endpoint_url = http://localhost:4566

[profile localstack.services.dynamodb]
endpoint_url = http://localhost:4566
```

```bash
# Use with profile
aws s3 ls --profile localstack

# Or with endpoint override
aws --endpoint-url=http://localhost:4566 s3 ls
```

## Pagination Helpers

### Process All Pages

```bash
#!/bin/bash
# paginate.sh - Process all pages of AWS CLI output

# Example: Get all Lambda functions
NEXT_TOKEN=""

while true; do
  if [ -z "$NEXT_TOKEN" ]; then
    RESPONSE=$(aws lambda list-functions --max-items 50)
  else
    RESPONSE=$(aws lambda list-functions --max-items 50 --starting-token "$NEXT_TOKEN")
  fi

  # Process this page
  echo "$RESPONSE" | jq -r '.Functions[].FunctionName'

  # Check for more pages
  NEXT_TOKEN=$(echo "$RESPONSE" | jq -r '.NextToken // empty')
  if [ -z "$NEXT_TOKEN" ]; then
    break
  fi
done
```

### Parallel Pagination with xargs

```bash
#!/bin/bash
# Get all S3 objects and process in parallel

aws s3api list-objects-v2 --bucket my-bucket \
  --query 'Contents[].Key' --output text | \
tr '\t' '\n' | \
xargs -P 4 -I {} aws s3api head-object --bucket my-bucket --key {}
```

## Error Handling Patterns

### Retry with Backoff

```bash
#!/bin/bash
# retry.sh - Retry AWS command with exponential backoff

MAX_RETRIES=5
RETRY_DELAY=1

retry_command() {
  local retries=0
  local delay=$RETRY_DELAY

  until "$@"; do
    retries=$((retries + 1))
    if [ $retries -ge $MAX_RETRIES ]; then
      echo "Failed after $MAX_RETRIES attempts"
      return 1
    fi
    echo "Retry $retries/$MAX_RETRIES in ${delay}s..."
    sleep $delay
    delay=$((delay * 2))
  done
}

# Usage
retry_command aws s3 cp large-file.zip s3://bucket/
```

### Error Handling Wrapper

```bash
#!/bin/bash
# safe-aws.sh - AWS CLI wrapper with error handling

safe_aws() {
  local output
  local exit_code

  output=$(aws "$@" 2>&1)
  exit_code=$?

  if [ $exit_code -ne 0 ]; then
    # Check for specific errors
    if echo "$output" | grep -q "ExpiredToken"; then
      echo "ERROR: Session expired. Please re-authenticate." >&2
      return 1
    elif echo "$output" | grep -q "AccessDenied"; then
      echo "ERROR: Access denied. Check IAM permissions." >&2
      return 1
    elif echo "$output" | grep -q "ThrottlingException"; then
      echo "ERROR: Rate limited. Retrying with backoff..." >&2
      sleep 5
      safe_aws "$@"
      return $?
    else
      echo "ERROR: $output" >&2
      return $exit_code
    fi
  fi

  echo "$output"
}

# Usage
safe_aws s3 ls s3://my-bucket/
```
