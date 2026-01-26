---
name: awslocal
description: "Thin wrapper around AWS CLI for LocalStack. Automatically sets endpoint URL to localhost:4566. Use for: running AWS commands against LocalStack without --endpoint-url, local development, testing AWS workflows locally. Triggers: awslocal, aws local, localstack aws cli, awscli-local."
---

# awslocal

Thin wrapper around AWS CLI that automatically configures the endpoint URL for LocalStack.

## Install

```bash
# With AWS CLI v1 (recommended)
pip install "awscli-local[ver1]"

# Wrapper only (manage AWS CLI separately)
pip install awscli-local

# Verify
awslocal --version
```

Note: AWS CLI v2 works but cannot be auto-installed via pip.

## Quick Start

```bash
# Instead of:
aws --endpoint-url=http://localhost:4566 s3 ls

# Use:
awslocal s3 ls
```

All standard AWS CLI commands work identically.

## Usage

`awslocal` is a drop-in replacement for `aws`:

```bash
# S3
awslocal s3 mb s3://my-bucket
awslocal s3 cp file.txt s3://my-bucket/
awslocal s3 ls s3://my-bucket

# DynamoDB
awslocal dynamodb create-table \
  --table-name users \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

awslocal dynamodb list-tables
awslocal dynamodb scan --table-name users

# SQS
awslocal sqs create-queue --queue-name my-queue
awslocal sqs list-queues
awslocal sqs send-message --queue-url http://localhost:4566/000000000000/my-queue --message-body "test"

# SNS
awslocal sns create-topic --name my-topic
awslocal sns list-topics

# Lambda
awslocal lambda create-function \
  --function-name my-func \
  --runtime python3.9 \
  --handler index.handler \
  --zip-file fileb://function.zip \
  --role arn:aws:iam::000000000000:role/lambda-role

awslocal lambda invoke --function-name my-func output.json

# IAM
awslocal iam create-role --role-name my-role --assume-role-policy-document file://trust.json
awslocal iam list-roles

# Secrets Manager
awslocal secretsmanager create-secret --name my-secret --secret-string "password123"
awslocal secretsmanager get-secret-value --secret-id my-secret

# CloudFormation
awslocal cloudformation deploy --template-file template.yaml --stack-name my-stack
awslocal cloudformation describe-stacks
```

## Configuration

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AWS_ENDPOINT_URL` | Custom endpoint (takes precedence) | - |
| `LOCALSTACK_HOST` | LocalStack host:port | `localhost:4566` |
| `USE_SSL` | Enable HTTPS | `false` |
| `DEFAULT_REGION` | AWS region | `us-east-1` |

```bash
# Custom LocalStack host
LOCALSTACK_HOST=localstack:4566 awslocal s3 ls

# Or use AWS_ENDPOINT_URL
AWS_ENDPOINT_URL=http://localstack:4566 awslocal s3 ls
```

### Shell Completion

Add to `~/.bashrc` or `~/.zshrc`:

```bash
complete -C '/usr/local/bin/aws_completer' awslocal
```

### Credentials

Use dummy credentials (LocalStack doesn't validate):

```bash
# ~/.aws/credentials
[default]
aws_access_key_id = test
aws_secret_access_key = test
```

Or set environment:

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
```

## Common Patterns

### Create Test Infrastructure

```bash
#!/bin/bash
# setup-local.sh

# S3 bucket
awslocal s3 mb s3://test-bucket

# DynamoDB table
awslocal dynamodb create-table \
  --table-name test-table \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# SQS queue
awslocal sqs create-queue --queue-name test-queue

# Wait for resources
awslocal dynamodb wait table-exists --table-name test-table

echo "Local infrastructure ready"
```

### Debug Mode

```bash
awslocal --debug s3 ls
```

## Limitations

- CloudFormation `package` command with AWS CLI v2 cannot specify S3 endpoint
- Some features work better with AWS CLI v1

## Integration

- Use `localstack` skill to start/stop the LocalStack container
- Use `localstack-expert` skill for testing strategies and CI/CD patterns
