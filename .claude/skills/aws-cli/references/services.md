# AWS Service Commands Reference

Detailed command reference for commonly used AWS services.

## S3

```bash
# List buckets
aws s3 ls

# List bucket contents
aws s3 ls s3://bucket-name/prefix/

# Copy (local to S3, S3 to local, S3 to S3)
aws s3 cp file.txt s3://bucket/
aws s3 cp s3://bucket/file.txt ./
aws s3 cp s3://source/ s3://dest/ --recursive

# Sync (mirror directories)
aws s3 sync ./local-dir s3://bucket/prefix/
aws s3 sync s3://bucket/prefix/ ./local-dir --delete

# Presigned URL
aws s3 presign s3://bucket/file.txt --expires-in 3600

# Remove
aws s3 rm s3://bucket/file.txt
aws s3 rm s3://bucket/prefix/ --recursive

# Bucket operations
aws s3 mb s3://new-bucket
aws s3 rb s3://empty-bucket
aws s3 rb s3://bucket --force  # Delete with contents
```

## EC2

```bash
# List instances
aws ec2 describe-instances
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running"
aws ec2 describe-instances --instance-ids i-1234567890abcdef0

# Start/stop/terminate
aws ec2 start-instances --instance-ids i-1234567890abcdef0
aws ec2 stop-instances --instance-ids i-1234567890abcdef0
aws ec2 terminate-instances --instance-ids i-1234567890abcdef0

# Launch instance
aws ec2 run-instances \
  --image-id ami-12345678 \
  --instance-type t3.micro \
  --key-name my-key \
  --security-group-ids sg-12345678 \
  --subnet-id subnet-12345678

# Security groups
aws ec2 describe-security-groups
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0

# Key pairs
aws ec2 create-key-pair --key-name my-key --query 'KeyMaterial' --output text > my-key.pem
aws ec2 describe-key-pairs

# AMIs
aws ec2 describe-images --owners self amazon
aws ec2 create-image --instance-id i-12345678 --name "My AMI"
```

## Lambda

```bash
# List functions
aws lambda list-functions
aws lambda get-function --function-name my-function

# Invoke
aws lambda invoke \
  --function-name my-function \
  --payload '{"key": "value"}' \
  response.json

# Invoke async
aws lambda invoke \
  --function-name my-function \
  --invocation-type Event \
  --payload '{"key": "value"}' \
  response.json

# Update code
aws lambda update-function-code \
  --function-name my-function \
  --zip-file fileb://function.zip

# Update config
aws lambda update-function-configuration \
  --function-name my-function \
  --timeout 30 \
  --memory-size 256

# Logs (recent)
aws logs tail /aws/lambda/my-function --follow
```

## ECS

```bash
# Clusters
aws ecs list-clusters
aws ecs describe-clusters --clusters my-cluster

# Services
aws ecs list-services --cluster my-cluster
aws ecs describe-services --cluster my-cluster --services my-service
aws ecs update-service --cluster my-cluster --service my-service --desired-count 3

# Tasks
aws ecs list-tasks --cluster my-cluster
aws ecs describe-tasks --cluster my-cluster --tasks <task-arn>
aws ecs run-task --cluster my-cluster --task-definition my-task

# Execute command (debug)
aws ecs execute-command \
  --cluster my-cluster \
  --task <task-id> \
  --container my-container \
  --interactive \
  --command "/bin/sh"
```

## RDS

```bash
# List instances
aws rds describe-db-instances
aws rds describe-db-instances --db-instance-identifier my-db

# Create snapshot
aws rds create-db-snapshot \
  --db-instance-identifier my-db \
  --db-snapshot-identifier my-snapshot

# Modify instance
aws rds modify-db-instance \
  --db-instance-identifier my-db \
  --db-instance-class db.t3.medium \
  --apply-immediately

# Stop/start
aws rds stop-db-instance --db-instance-identifier my-db
aws rds start-db-instance --db-instance-identifier my-db
```

## DynamoDB

```bash
# List tables
aws dynamodb list-tables

# Describe table
aws dynamodb describe-table --table-name my-table

# Get item
aws dynamodb get-item \
  --table-name my-table \
  --key '{"pk": {"S": "user#123"}}'

# Put item
aws dynamodb put-item \
  --table-name my-table \
  --item '{"pk": {"S": "user#123"}, "name": {"S": "John"}}'

# Query
aws dynamodb query \
  --table-name my-table \
  --key-condition-expression "pk = :pk" \
  --expression-attribute-values '{":pk": {"S": "user#123"}}'

# Scan (use sparingly)
aws dynamodb scan --table-name my-table --max-items 10
```

## IAM

```bash
# Users
aws iam list-users
aws iam get-user --user-name my-user
aws iam create-user --user-name new-user

# Roles
aws iam list-roles
aws iam get-role --role-name my-role
aws iam list-attached-role-policies --role-name my-role

# Policies
aws iam list-policies --scope Local
aws iam get-policy --policy-arn arn:aws:iam::123456789012:policy/my-policy
aws iam get-policy-version --policy-arn <arn> --version-id v1

# Simulate policy
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/my-user \
  --action-names s3:GetObject \
  --resource-arns arn:aws:s3:::my-bucket/*

# Access keys
aws iam list-access-keys --user-name my-user
aws iam create-access-key --user-name my-user
```

## CloudFormation

```bash
# List stacks
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE

# Describe stack
aws cloudformation describe-stacks --stack-name my-stack

# Create stack
aws cloudformation create-stack \
  --stack-name my-stack \
  --template-body file://template.yaml \
  --parameters ParameterKey=Env,ParameterValue=prod \
  --capabilities CAPABILITY_IAM

# Update stack
aws cloudformation update-stack \
  --stack-name my-stack \
  --template-body file://template.yaml

# Delete stack
aws cloudformation delete-stack --stack-name my-stack

# Wait for completion
aws cloudformation wait stack-create-complete --stack-name my-stack
```

## CloudWatch

```bash
# Logs
aws logs describe-log-groups
aws logs describe-log-streams --log-group-name /aws/lambda/my-function
aws logs tail /aws/lambda/my-function --follow
aws logs filter-log-events \
  --log-group-name /aws/lambda/my-function \
  --filter-pattern "ERROR"

# Metrics
aws cloudwatch list-metrics --namespace AWS/EC2
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=i-12345678 \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average

# Alarms
aws cloudwatch describe-alarms
aws cloudwatch set-alarm-state \
  --alarm-name my-alarm \
  --state-value OK \
  --state-reason "Manual reset"
```

## Secrets Manager

```bash
# List secrets
aws secretsmanager list-secrets

# Get secret value
aws secretsmanager get-secret-value --secret-id my-secret

# Get specific version
aws secretsmanager get-secret-value --secret-id my-secret --version-stage AWSPREVIOUS

# Create secret
aws secretsmanager create-secret \
  --name my-secret \
  --secret-string '{"username":"admin","password":"secret"}'

# Update secret
aws secretsmanager put-secret-value \
  --secret-id my-secret \
  --secret-string '{"username":"admin","password":"new-secret"}'

# Rotate
aws secretsmanager rotate-secret --secret-id my-secret
```

## STS (Security Token Service)

```bash
# Get caller identity (whoami for AWS)
aws sts get-caller-identity

# Get session token (MFA)
aws sts get-session-token \
  --serial-number arn:aws:iam::123456789012:mfa/my-user \
  --token-code 123456

# Assume role
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --role-session-name my-session

# Assume role with web identity (OIDC)
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --role-session-name my-session \
  --web-identity-token file://token.txt
```

## Cost Commands

### Cost Explorer

```bash
# Get monthly costs
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-02-01 \
  --granularity MONTHLY \
  --metrics "UnblendedCost"

# Cost by service
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-02-01 \
  --granularity MONTHLY \
  --metrics "UnblendedCost" \
  --group-by Type=DIMENSION,Key=SERVICE

# Cost forecast
aws ce get-cost-forecast \
  --time-period Start=2024-02-01,End=2024-03-01 \
  --metric UNBLENDED_COST \
  --granularity MONTHLY
```

### Budgets

```bash
# List budgets
aws budgets describe-budgets --account-id 123456789012

# Create budget alert
aws budgets create-budget \
  --account-id 123456789012 \
  --budget file://budget.json \
  --notifications-with-subscribers file://notifications.json
```

### Resource Tagging

```bash
# Tag resources for cost allocation
aws ec2 create-tags \
  --resources i-12345678 \
  --tags Key=Environment,Value=prod Key=CostCenter,Value=engineering

# Get resources by tag
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=Environment,Values=prod
```
