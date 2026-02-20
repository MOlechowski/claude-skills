# CI/CD Patterns for LocalStack

## GitHub Actions

### Basic Setup

```yaml
name: Test with LocalStack

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start LocalStack
        uses: LocalStack/setup-localstack@v0.2.3
        with:
          image-tag: 'latest'
          install-awslocal: 'true'

      - name: Run tests
        run: |
          awslocal s3 mb s3://test-bucket
          pytest tests/
```

### With Pro Features

```yaml
name: Test with LocalStack Pro

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start LocalStack Pro
        uses: LocalStack/setup-localstack@v0.2.3
        with:
          image-tag: 'latest'
          install-awslocal: 'true'
          use-pro: 'true'
        env:
          LOCALSTACK_AUTH_TOKEN: ${{ secrets.LOCALSTACK_AUTH_TOKEN }}

      - name: Load Cloud Pod
        run: localstack pod load my-test-pod

      - name: Run tests
        run: pytest tests/
```

### With Configuration Options

```yaml
- name: Start LocalStack
  uses: LocalStack/setup-localstack@v0.2.3
  with:
    image-tag: 'latest'
    install-awslocal: 'true'
    configuration: 'DEBUG=1,SERVICES=s3,dynamodb,lambda'
```

### Caching Docker Images

```yaml
- name: Cache LocalStack image
  uses: actions/cache@v3
  with:
    path: /tmp/localstack-image.tar
    key: localstack-${{ hashFiles('.localstack-version') }}

- name: Load cached image
  run: |
    if [ -f /tmp/localstack-image.tar ]; then
      docker load < /tmp/localstack-image.tar
    fi

- name: Start LocalStack
  uses: LocalStack/setup-localstack@v0.2.3
  with:
    image-tag: 'latest'

- name: Save image to cache
  run: docker save localstack/aws-localstack > /tmp/localstack-image.tar
```

## GitLab CI

### Basic Setup

```yaml
test:
  image: python:3.11
  services:
    - name: localstack/aws-localstack
      alias: localstack
  variables:
    AWS_ENDPOINT_URL: http://aws-localstack:4566
    AWS_ACCESS_KEY_ID: test
    AWS_SECRET_ACCESS_KEY: test
    AWS_DEFAULT_REGION: us-east-1
  script:
    - pip install awscli-local pytest boto3
    - awslocal s3 mb s3://test-bucket
    - pytest tests/
```

### With Pro Features

```yaml
test:
  image: python:3.11
  services:
    - name: localstack/localstack-pro
      alias: localstack
  variables:
    AWS_ENDPOINT_URL: http://aws-localstack:4566
    LOCALSTACK_AUTH_TOKEN: $LOCALSTACK_AUTH_TOKEN
  script:
    - pip install localstack awscli-local
    - localstack pod load my-test-pod
    - pytest tests/
```

### With Service Limits

```yaml
test:
  services:
    - name: localstack/aws-localstack
      alias: localstack
      variables:
        SERVICES: s3,dynamodb,sqs
        DEBUG: "1"
```

## CircleCI

### Basic Setup

```yaml
version: 2.1

jobs:
  test:
    docker:
      - image: cimg/python:3.11
      - image: localstack/aws-localstack
        environment:
          SERVICES: s3,dynamodb
    environment:
      AWS_ENDPOINT_URL: http://localhost:4566
      AWS_ACCESS_KEY_ID: test
      AWS_SECRET_ACCESS_KEY: test
    steps:
      - checkout
      - run:
          name: Wait for LocalStack
          command: |
            pip install awscli-local
            timeout 60 bash -c 'until awslocal s3 ls; do sleep 1; done'
      - run:
          name: Run tests
          command: pytest tests/

workflows:
  test:
    jobs:
      - test
```

## Jenkins

### Declarative Pipeline

```groovy
pipeline {
    agent {
        docker {
            image 'python:3.11'
        }
    }

    environment {
        AWS_ENDPOINT_URL = 'http://aws-localstack:4566'
        AWS_ACCESS_KEY_ID = 'test'
        AWS_SECRET_ACCESS_KEY = 'test'
    }

    stages {
        stage('Start LocalStack') {
            steps {
                script {
                    docker.image('localstack/aws-localstack').withRun('-p 4566:4566') { c ->
                        sh 'pip install awscli-local'
                        sh 'timeout 60 bash -c "until awslocal s3 ls; do sleep 1; done"'
                        sh 'pytest tests/'
                    }
                }
            }
        }
    }
}
```

## Docker Compose for CI

```yaml
# docker-compose.ci.yml
version: '3.8'

services:
  localstack:
    image: localstack/aws-localstack
    ports:
      - "4566:4566"
    environment:
      - SERVICES=s3,dynamodb,sqs,sns,lambda
      - DEBUG=1
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4566/_localstack/health"]
      interval: 5s
      timeout: 5s
      retries: 10

  test:
    build: .
    depends_on:
      localstack:
        condition: service_healthy
    environment:
      - AWS_ENDPOINT_URL=http://aws-localstack:4566
      - AWS_ACCESS_KEY_ID=test
      - AWS_SECRET_ACCESS_KEY=test
    command: pytest tests/
```

```bash
# Run in CI
docker compose -f docker-compose.ci.yml up --abort-on-container-exit --exit-code-from test
```

## Cloud Pods Commands

### Save State

```bash
# Save current state
localstack pod save my-pod

# Save with message
localstack pod save my-pod --message "Initial test data setup"

# Save to custom remote
localstack pod save my-pod s3-remote
```

### Load State

```bash
# Load latest version
localstack pod load my-pod

# Load specific version
localstack pod load my-pod:v2

# Load with merge strategy
localstack pod load my-pod --strategy overwrite

# Dry run (preview)
localstack pod load my-pod --dry-run
```

### Manage Pods

```bash
# List all pods
localstack pod list

# Show versions
localstack pod versions my-pod

# Inspect contents
localstack pod inspect my-pod

# Delete pod
localstack pod delete my-pod
```

### Auto-Load in CI

```yaml
# GitHub Actions
- name: Start LocalStack
  uses: LocalStack/setup-localstack@v0.2.3
  env:
    AUTO_LOAD_POD: my-test-pod
```

```bash
# Environment variable
AUTO_LOAD_POD=pod1,pod2 localstack start
```

## Init Scripts Pattern

Create initialization scripts for reproducible state:

```bash
# init-aws.sh
#!/bin/bash
set -e

# Wait for LocalStack
until awslocal s3 ls 2>/dev/null; do
  sleep 1
done

# Create resources
awslocal s3 mb s3://test-bucket
awslocal dynamodb create-table \
  --table-name users \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# Seed data
awslocal s3 cp fixtures/data.json s3://test-bucket/
awslocal dynamodb batch-write-item --request-items file://fixtures/users.json

echo "LocalStack initialized"
```

Mount as init hook:

```yaml
# docker-compose.yml
volumes:
  - "./init-aws.sh:/etc/localstack/init/ready.d/init-aws.sh"
```
