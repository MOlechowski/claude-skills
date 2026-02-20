# AWS CLI Quick Reference

Copy-paste ready commands organized by service.

## Identity & Access

```bash
# Who am I?
aws sts get-caller-identity

# List current config
aws configure list

# Switch profile
export AWS_PROFILE=production
```

## S3

```bash
# List buckets
aws s3 ls

# List objects
aws s3 ls s3://bucket/prefix/ --recursive --human-readable

# Copy
aws s3 cp file.txt s3://bucket/
aws s3 cp s3://bucket/file.txt ./
aws s3 cp s3://src/ s3://dest/ --recursive

# Sync
aws s3 sync . s3://bucket/ --exclude "*.log"
aws s3 sync s3://bucket/ . --delete

# Presigned URL (1 hour)
aws s3 presign s3://bucket/file.txt --expires-in 3600

# Delete
aws s3 rm s3://bucket/file.txt
aws s3 rm s3://bucket/prefix/ --recursive

# Bucket lifecycle
aws s3 mb s3://new-bucket --region us-west-2
aws s3 rb s3://empty-bucket
aws s3 rb s3://bucket --force

# Object info
aws s3api head-object --bucket bucket --key file.txt

# Storage class
aws s3 cp s3://bucket/file.txt s3://bucket/file.txt --storage-class GLACIER
```

**JMESPath queries:**
```bash
# Total size of bucket
aws s3api list-objects-v2 --bucket bucket \
  --query 'sum(Contents[].Size)'

# Find large files (>100MB)
aws s3api list-objects-v2 --bucket bucket \
  --query 'Contents[?Size>`104857600`].[Key,Size]'

# Count objects by storage class
aws s3api list-objects-v2 --bucket bucket \
  --query 'Contents[].StorageClass' | jq 'group_by(.) | map({class: .[0], count: length})'
```

## EC2

```bash
# List running instances
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType,PrivateIpAddress,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Find by name tag
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*web*" \
  --query 'Reservations[].Instances[].InstanceId'

# Start/stop/reboot/terminate
aws ec2 start-instances --instance-ids i-xxx
aws ec2 stop-instances --instance-ids i-xxx
aws ec2 reboot-instances --instance-ids i-xxx
aws ec2 terminate-instances --instance-ids i-xxx

# Get console output
aws ec2 get-console-output --instance-id i-xxx

# Create AMI
aws ec2 create-image --instance-id i-xxx --name "My AMI $(date +%Y%m%d)"

# Security groups
aws ec2 describe-security-groups \
  --query 'SecurityGroups[].[GroupId,GroupName,Description]' --output table

# Add ingress rule
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxx \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# Remove ingress rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxx \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# Volumes
aws ec2 describe-volumes \
  --query 'Volumes[].[VolumeId,Size,State,Attachments[0].InstanceId]' --output table

# Snapshots
aws ec2 create-snapshot --volume-id vol-xxx --description "Backup"
aws ec2 describe-snapshots --owner-ids self \
  --query 'sort_by(Snapshots, &StartTime)[-5:].[SnapshotId,StartTime,VolumeSize]' --output table
```

**JMESPath queries:**
```bash
# Instances by type
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].InstanceType' | jq 'group_by(.) | map({type: .[0], count: length})'

# Stopped instances
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=stopped" \
  --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`Name`].Value|[0]]'

# Instances without Name tag
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?!not_null(Tags[?Key==`Name`].Value|[0])].[InstanceId,LaunchTime]'
```

## Lambda

```bash
# List functions
aws lambda list-functions \
  --query 'Functions[].[FunctionName,Runtime,MemorySize,Timeout]' --output table

# Get function
aws lambda get-function --function-name my-func

# Invoke sync
aws lambda invoke --function-name my-func \
  --payload '{"key":"value"}' response.json && cat response.json

# Invoke async
aws lambda invoke --function-name my-func \
  --invocation-type Event \
  --payload '{"key":"value"}' /dev/null

# Update code
aws lambda update-function-code \
  --function-name my-func \
  --zip-file fileb://function.zip

# Update config
aws lambda update-function-configuration \
  --function-name my-func \
  --timeout 30 --memory-size 512

# Environment variables
aws lambda update-function-configuration \
  --function-name my-func \
  --environment "Variables={KEY1=value1,KEY2=value2}"

# Aliases
aws lambda list-aliases --function-name my-func
aws lambda update-alias --function-name my-func --name prod --function-version 5

# Concurrency
aws lambda put-function-concurrency --function-name my-func --reserved-concurrent-executions 100
```

## ECS

```bash
# List clusters
aws ecs list-clusters

# List services
aws ecs list-services --cluster my-cluster \
  --query 'serviceArns[]' --output text | xargs -n1 basename

# Service status
aws ecs describe-services --cluster my-cluster --services my-service \
  --query 'services[].[serviceName,desiredCount,runningCount,status]' --output table

# Scale service
aws ecs update-service --cluster my-cluster --service my-service --desired-count 5

# Force new deployment
aws ecs update-service --cluster my-cluster --service my-service --force-new-deployment

# List tasks
aws ecs list-tasks --cluster my-cluster --service-name my-service

# Task details
aws ecs describe-tasks --cluster my-cluster --tasks arn:aws:ecs:...

# Run one-off task
aws ecs run-task --cluster my-cluster --task-definition my-task

# Execute command (debug container)
aws ecs execute-command --cluster my-cluster --task task-id \
  --container my-container --interactive --command "/bin/sh"

# Stop task
aws ecs stop-task --cluster my-cluster --task task-id
```

## RDS

```bash
# List instances
aws rds describe-db-instances \
  --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceClass,Engine,DBInstanceStatus]' --output table

# Instance details
aws rds describe-db-instances --db-instance-identifier my-db

# Create snapshot
aws rds create-db-snapshot \
  --db-instance-identifier my-db \
  --db-snapshot-identifier my-snapshot-$(date +%Y%m%d)

# List snapshots
aws rds describe-db-snapshots --db-instance-identifier my-db \
  --query 'sort_by(DBSnapshots, &SnapshotCreateTime)[-5:].[DBSnapshotIdentifier,SnapshotCreateTime,Status]' --output table

# Stop/start
aws rds stop-db-instance --db-instance-identifier my-db
aws rds start-db-instance --db-instance-identifier my-db

# Modify
aws rds modify-db-instance \
  --db-instance-identifier my-db \
  --db-instance-class db.t3.medium \
  --apply-immediately

# Logs
aws rds describe-db-log-files --db-instance-identifier my-db
aws rds download-db-log-file-portion \
  --db-instance-identifier my-db \
  --log-file-name error/mysql-error.log
```

## DynamoDB

```bash
# List tables
aws dynamodb list-tables

# Describe table
aws dynamodb describe-table --table-name my-table \
  --query 'Table.[TableName,TableStatus,ItemCount,TableSizeBytes]'

# Get item
aws dynamodb get-item --table-name my-table \
  --key '{"pk":{"S":"user#123"}}'

# Put item
aws dynamodb put-item --table-name my-table \
  --item '{"pk":{"S":"user#123"},"name":{"S":"John"},"age":{"N":"30"}}'

# Query
aws dynamodb query --table-name my-table \
  --key-condition-expression "pk = :pk" \
  --expression-attribute-values '{":pk":{"S":"user#123"}}'

# Query with filter
aws dynamodb query --table-name my-table \
  --key-condition-expression "pk = :pk" \
  --filter-expression "age > :age" \
  --expression-attribute-values '{":pk":{"S":"user#123"},":age":{"N":"25"}}'

# Update item
aws dynamodb update-item --table-name my-table \
  --key '{"pk":{"S":"user#123"}}' \
  --update-expression "SET #n = :name" \
  --expression-attribute-names '{"#n":"name"}' \
  --expression-attribute-values '{":name":{"S":"Jane"}}'

# Delete item
aws dynamodb delete-item --table-name my-table \
  --key '{"pk":{"S":"user#123"}}'

# Scan (use sparingly)
aws dynamodb scan --table-name my-table --max-items 10
```

## IAM

```bash
# Users
aws iam list-users --query 'Users[].[UserName,CreateDate]' --output table
aws iam get-user --user-name my-user
aws iam list-user-policies --user-name my-user
aws iam list-attached-user-policies --user-name my-user

# Roles
aws iam list-roles --query 'Roles[].[RoleName,CreateDate]' --output table
aws iam get-role --role-name my-role
aws iam list-attached-role-policies --role-name my-role

# Policies
aws iam list-policies --scope Local --query 'Policies[].[PolicyName,Arn]' --output table
aws iam get-policy-version --policy-arn arn:aws:iam::xxx:policy/my-policy --version-id v1

# Access keys
aws iam list-access-keys --user-name my-user
aws iam get-access-key-last-used --access-key-id AKIA...

# Simulate permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::xxx:user/my-user \
  --action-names s3:GetObject s3:PutObject \
  --resource-arns arn:aws:s3:::my-bucket/*

# MFA devices
aws iam list-mfa-devices --user-name my-user
```

## CloudWatch Logs

```bash
# List log groups
aws logs describe-log-groups \
  --query 'logGroups[].[logGroupName,storedBytes]' --output table

# List streams
aws logs describe-log-streams \
  --log-group-name /aws/lambda/my-func \
  --order-by LastEventTime --descending --limit 5

# Tail logs (live)
aws logs tail /aws/lambda/my-func --follow

# Filter logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/my-func \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000

# Get specific events
aws logs get-log-events \
  --log-group-name /aws/lambda/my-func \
  --log-stream-name '2024/01/01/[$LATEST]xxx'

# Insights query
aws logs start-query \
  --log-group-name /aws/lambda/my-func \
  --start-time $(date -d '1 day ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, @message | filter @message like /ERROR/ | limit 20'
```

## Secrets Manager

```bash
# List secrets
aws secretsmanager list-secrets \
  --query 'SecretList[].[Name,LastChangedDate]' --output table

# Get secret value
aws secretsmanager get-secret-value --secret-id my-secret \
  --query SecretString --output text

# Get and parse JSON secret
aws secretsmanager get-secret-value --secret-id my-secret \
  --query SecretString --output text | jq -r '.password'

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

## Systems Manager (SSM)

```bash
# Parameter Store
aws ssm get-parameter --name /my/parameter
aws ssm get-parameter --name /my/parameter --with-decryption
aws ssm get-parameters-by-path --path /my/ --recursive

aws ssm put-parameter \
  --name /my/parameter \
  --value "secret" \
  --type SecureString

# Run command
aws ssm send-command \
  --instance-ids i-xxx \
  --document-name "AWS-RunShellScript" \
  --parameters commands=["uptime"]

# Start session (SSH alternative)
aws ssm start-session --target i-xxx

# List managed instances
aws ssm describe-instance-information \
  --query 'InstanceInformationList[].[InstanceId,PlatformName,PingStatus]' --output table
```

## CloudFormation

```bash
# List stacks
aws cloudformation list-stacks \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
  --query 'StackSummaries[].[StackName,StackStatus,CreationTime]' --output table

# Stack details
aws cloudformation describe-stacks --stack-name my-stack

# Stack resources
aws cloudformation list-stack-resources --stack-name my-stack \
  --query 'StackResourceSummaries[].[LogicalResourceId,ResourceType,ResourceStatus]' --output table

# Stack events
aws cloudformation describe-stack-events --stack-name my-stack \
  --query 'StackEvents[:10].[Timestamp,LogicalResourceId,ResourceStatus,ResourceStatusReason]' --output table

# Create stack
aws cloudformation create-stack \
  --stack-name my-stack \
  --template-body file://template.yaml \
  --parameters ParameterKey=Env,ParameterValue=prod \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM

# Update stack
aws cloudformation update-stack \
  --stack-name my-stack \
  --template-body file://template.yaml

# Delete stack
aws cloudformation delete-stack --stack-name my-stack

# Wait for operation
aws cloudformation wait stack-create-complete --stack-name my-stack
aws cloudformation wait stack-update-complete --stack-name my-stack
aws cloudformation wait stack-delete-complete --stack-name my-stack

# Validate template
aws cloudformation validate-template --template-body file://template.yaml
```

## Route 53

```bash
# List hosted zones
aws route53 list-hosted-zones \
  --query 'HostedZones[].[Id,Name,ResourceRecordSetCount]' --output table

# List records
aws route53 list-resource-record-sets --hosted-zone-id Z123... \
  --query 'ResourceRecordSets[].[Name,Type,TTL]' --output table

# Change record
aws route53 change-resource-record-sets --hosted-zone-id Z123... \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "test.example.com",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "1.2.3.4"}]
      }
    }]
  }'
```

## SQS

```bash
# List queues
aws sqs list-queues

# Get queue URL
aws sqs get-queue-url --queue-name my-queue

# Send message
aws sqs send-message \
  --queue-url https://sqs.region.amazonaws.com/123/my-queue \
  --message-body '{"key":"value"}'

# Receive messages
aws sqs receive-message \
  --queue-url https://sqs.region.amazonaws.com/123/my-queue \
  --max-number-of-messages 10 \
  --wait-time-seconds 20

# Delete message
aws sqs delete-message \
  --queue-url https://sqs.region.amazonaws.com/123/my-queue \
  --receipt-handle "AQEBwJnKyrHigUMZj..."

# Purge queue
aws sqs purge-queue --queue-url https://sqs.region.amazonaws.com/123/my-queue

# Queue attributes
aws sqs get-queue-attributes \
  --queue-url https://sqs.region.amazonaws.com/123/my-queue \
  --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible
```

## SNS

```bash
# List topics
aws sns list-topics

# Publish message
aws sns publish \
  --topic-arn arn:aws:sns:region:123:my-topic \
  --message "Hello"

# Publish JSON
aws sns publish \
  --topic-arn arn:aws:sns:region:123:my-topic \
  --message '{"default":"Hello","email":"Hello via email"}' \
  --message-structure json

# List subscriptions
aws sns list-subscriptions-by-topic --topic-arn arn:aws:sns:region:123:my-topic
```

## Cost Explorer

```bash
# Monthly costs
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-02-01 \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --query 'ResultsByTime[].Total.UnblendedCost'

# Cost by service
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-02-01 \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --query 'ResultsByTime[].Groups[].{Service:Keys[0],Cost:Metrics.UnblendedCost.Amount}'

# Cost forecast
aws ce get-cost-forecast \
  --time-period Start=$(date -d 'tomorrow' +%Y-%m-%d),End=$(date -d '+30 days' +%Y-%m-%d) \
  --metric UNBLENDED_COST \
  --granularity MONTHLY
```

## Organizations

```bash
# List accounts
aws organizations list-accounts \
  --query 'Accounts[].[Id,Name,Email,Status]' --output table

# Account details
aws organizations describe-account --account-id 123456789012

# List OUs
aws organizations list-roots
aws organizations list-organizational-units-for-parent --parent-id r-xxxx
```
