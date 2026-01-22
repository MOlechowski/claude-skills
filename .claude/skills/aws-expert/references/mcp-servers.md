# AWS MCP Servers Reference

Complete catalog of 64+ official AWS MCP servers from [awslabs/mcp](https://github.com/awslabs/mcp).

## Overview

### What is MCP?

Model Context Protocol (MCP) is an open standard that enables AI assistants to connect with external data sources and tools. AWS MCP servers provide AI agents with real-time access to AWS services, documentation, and infrastructure management capabilities.

### Repository

- **GitHub:** [github.com/awslabs/mcp](https://github.com/awslabs/mcp)
- **Documentation:** [awslabs.github.io/mcp](https://awslabs.github.io/mcp/)
- **License:** Apache-2.0

### Installation Methods

**uvx (Recommended):**
```bash
uvx awslabs.<server-name>@latest
```

**Docker:**
```bash
docker run -e AWS_PROFILE=default awslabs/<server-name>
```

**IDE Integration:** Kiro, Cursor, VS Code, Claude Desktop

## Quick Start

### Basic Configuration

Claude Code (`~/.claude/settings.json`):
```json
{
  "mcpServers": {
    "aws-pricing": {
      "command": "uvx",
      "args": ["awslabs.aws-pricing-mcp-server@latest"],
      "env": {
        "AWS_PROFILE": "default",
        "AWS_REGION": "us-east-1",
        "FASTMCP_LOG_LEVEL": "ERROR"
      }
    }
  }
}
```

### Common Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AWS_PROFILE` | AWS credential profile | `default` |
| `AWS_REGION` | AWS region for API calls | `us-east-1` |
| `FASTMCP_LOG_LEVEL` | Logging verbosity | `INFO` |
| `AWS_ACCESS_KEY_ID` | Direct credentials (not recommended) | - |
| `AWS_SECRET_ACCESS_KEY` | Direct credentials (not recommended) | - |

### Authentication

Configure AWS credentials via:
1. `aws configure` (creates `~/.aws/credentials`)
2. IAM role (for EC2/Lambda)
3. Environment variables
4. AWS SSO (`aws sso login`)

---

## Core & Documentation

### AWS Documentation MCP Server

Access to latest AWS documentation, APIs, and service information.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-documentation-mcp-server` |
| Purpose | Query AWS docs, get API references, search service documentation |
| IAM Permissions | None required (public documentation) |
| Use Cases | Learning AWS services, finding API methods, troubleshooting |

### AWS Knowledge MCP Server

Official AWS content including code samples, best practices, and guides.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-knowledge-mcp-server` |
| Purpose | Access code samples, official tutorials, architecture guidance |
| IAM Permissions | None required |
| Use Cases | Finding code examples, learning patterns, architecture research |

### Core MCP Server

Intelligent planning and orchestration of other AWS MCP servers.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.core-mcp-server` |
| Purpose | Coordinate multiple MCP servers, intelligent task planning |
| IAM Permissions | Depends on orchestrated servers |
| Use Cases | Complex multi-service workflows, automated planning |

### AWS API MCP Server

Direct interaction with AWS services via CLI commands.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-api-mcp-server` |
| Purpose | Execute AWS CLI commands, manage resources |
| IAM Permissions | Service-specific (varies by command) |
| Use Cases | Resource management, automation, CLI operations |

---

## Infrastructure & Deployment

### AWS CDK MCP Server

AWS Cloud Development Kit development with security compliance.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-cdk-mcp-server` |
| Purpose | CDK app development, construct guidance, security scanning |
| IAM Permissions | `cloudformation:*`, deployment permissions |
| Use Cases | IaC development, CDK best practices, secure deployments |

### AWS Terraform MCP Server

Terraform workflows with integrated security scanning.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-terraform-mcp-server` |
| Purpose | Terraform plan/apply, security scanning, drift detection |
| IAM Permissions | Service-specific for managed resources |
| Use Cases | Multi-cloud IaC, Terraform development, compliance |

### AWS CloudFormation MCP Server

Direct CloudFormation resource management via Cloud Control API.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-cloudformation-mcp-server` |
| Purpose | Stack management, template validation, resource operations |
| IAM Permissions | `cloudformation:*`, resource permissions |
| Use Cases | Stack deployments, template development, resource management |

### AWS Cloud Control API MCP Server

Comprehensive AWS resource management with security scanning.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-cloudcontrol-mcp-server` |
| Purpose | Create/read/update/delete any AWS resource |
| IAM Permissions | `cloudcontrol:*`, resource-specific permissions |
| Use Cases | Universal resource management, automation |

### Amazon EKS MCP Server

Kubernetes cluster management and operations.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-eks-mcp-server` |
| Purpose | EKS cluster management, kubectl operations, node groups |
| IAM Permissions | `eks:*`, `ec2:Describe*` |
| Use Cases | Kubernetes workloads, cluster operations, scaling |

### Amazon ECS MCP Server

Container orchestration and ECS deployment management.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-ecs-mcp-server` |
| Purpose | ECS services, task definitions, container deployments |
| IAM Permissions | `ecs:*`, `ecr:*`, `logs:*` |
| Use Cases | Container deployments, service management, scaling |

### Finch MCP Server

Local container building with Amazon ECR integration.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.finch-mcp-server` |
| Purpose | Build containers locally, push to ECR |
| IAM Permissions | `ecr:*` |
| Use Cases | Local development, container builds, ECR publishing |

### AWS Serverless MCP Server

Serverless application lifecycle with AWS SAM CLI.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-serverless-mcp-server` |
| Purpose | SAM templates, local testing, serverless deployments |
| IAM Permissions | `cloudformation:*`, `lambda:*`, `apigateway:*` |
| Use Cases | Serverless development, SAM applications, local testing |

### AWS Lambda Tool MCP Server

Execute Lambda functions as AI tools.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-lambda-tool-mcp-server` |
| Purpose | Invoke Lambda functions, manage function tools |
| IAM Permissions | `lambda:InvokeFunction` |
| Use Cases | Custom AI tools, function invocation, automation |

### AWS Support MCP Server

Create and manage AWS Support cases.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-support-mcp-server` |
| Purpose | Support case management, issue tracking |
| IAM Permissions | `support:*` |
| Use Cases | Support automation, case creation, issue resolution |

---

## AI & Machine Learning

### Amazon Bedrock Knowledge Bases Retrieval MCP Server

Query enterprise knowledge bases for RAG applications.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-bedrock-kb-retrieval-mcp-server` |
| Purpose | Knowledge base queries, semantic search, RAG |
| IAM Permissions | `bedrock:Retrieve`, `bedrock:RetrieveAndGenerate` |
| Use Cases | Enterprise search, RAG pipelines, knowledge retrieval |

### Amazon Kendra Index MCP Server

Enterprise search and RAG enhancement.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-kendra-index-mcp-server` |
| Purpose | Enterprise search, document indexing, query enhancement |
| IAM Permissions | `kendra:Query`, `kendra:Retrieve` |
| Use Cases | Document search, enterprise knowledge, Q&A systems |

### Amazon Q Business Anonymous MCP Server

AI assistant with anonymous access to Q Business.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-q-business-mcp-server` |
| Purpose | Q Business queries without user authentication |
| IAM Permissions | `qbusiness:ChatSync` |
| Use Cases | Enterprise Q&A, anonymous access scenarios |

### Amazon Q Index MCP Server

Search enterprise Q index.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-q-index-mcp-server` |
| Purpose | Query Q Business indexes |
| IAM Permissions | `qbusiness:*` |
| Use Cases | Enterprise search, indexed content queries |

### Document Loader MCP Server

Document parsing and content extraction.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.document-loader-mcp-server` |
| Purpose | Parse PDFs, Word docs, extract text and structure |
| IAM Permissions | `s3:GetObject` (if loading from S3) |
| Use Cases | Document processing, content extraction, RAG prep |

### Amazon Nova Canvas MCP Server

AI image generation with Amazon Nova.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-nova-canvas-mcp-server` |
| Purpose | Generate images, creative AI content |
| IAM Permissions | `bedrock:InvokeModel` |
| Use Cases | Image generation, creative content, visual AI |

### Amazon Bedrock Data Automation MCP Server

Analyze documents, images, videos, and audio.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-bedrock-data-automation-mcp-server` |
| Purpose | Multi-modal analysis, content processing |
| IAM Permissions | `bedrock:InvokeModel`, `s3:GetObject` |
| Use Cases | Document analysis, media processing, content extraction |

### Amazon Bedrock Custom Model Import MCP Server

Manage custom models in Amazon Bedrock.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-bedrock-custom-model-mcp-server` |
| Purpose | Import and manage custom foundation models |
| IAM Permissions | `bedrock:*` |
| Use Cases | Custom model deployment, model management |

### Amazon SageMaker AI MCP Server

SageMaker resource management and model development.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-sagemaker-mcp-server` |
| Purpose | Training jobs, endpoints, model registry |
| IAM Permissions | `sagemaker:*`, `s3:*`, `ecr:*` |
| Use Cases | ML model training, deployment, MLOps |

---

## Data & Analytics

### Amazon DynamoDB MCP Server

Complete DynamoDB operations and table management.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-dynamodb-mcp-server` |
| Purpose | CRUD operations, table management, queries |
| IAM Permissions | `dynamodb:*` |
| Use Cases | NoSQL operations, table management, data queries |

### Amazon Aurora PostgreSQL MCP Server

PostgreSQL database operations via RDS Data API.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-aurora-postgresql-mcp-server` |
| Purpose | SQL queries, database management |
| IAM Permissions | `rds-data:*`, `secretsmanager:GetSecretValue` |
| Use Cases | PostgreSQL operations, database queries, analytics |

### Amazon Aurora MySQL MCP Server

MySQL database operations via RDS Data API.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-aurora-mysql-mcp-server` |
| Purpose | SQL queries, database management |
| IAM Permissions | `rds-data:*`, `secretsmanager:GetSecretValue` |
| Use Cases | MySQL operations, database queries, analytics |

### Amazon Aurora DSQL MCP Server

Distributed SQL with PostgreSQL compatibility.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-aurora-dsql-mcp-server` |
| Purpose | Distributed SQL operations, global databases |
| IAM Permissions | `dsql:*` |
| Use Cases | Global databases, distributed transactions |

### Amazon DocumentDB MCP Server

MongoDB-compatible document database operations.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-documentdb-mcp-server` |
| Purpose | Document operations, MongoDB-compatible queries |
| IAM Permissions | VPC access, `secretsmanager:GetSecretValue` |
| Use Cases | Document storage, MongoDB workloads |

### Amazon Neptune MCP Server

Graph database queries with openCypher and Gremlin.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-neptune-mcp-server` |
| Purpose | Graph queries, relationship analysis |
| IAM Permissions | `neptune-db:*` |
| Use Cases | Graph databases, knowledge graphs, relationship data |

### Amazon Keyspaces MCP Server

Apache Cassandra-compatible operations.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-keyspaces-mcp-server` |
| Purpose | Cassandra-compatible queries, wide-column data |
| IAM Permissions | `cassandra:*` |
| Use Cases | Time-series data, wide-column workloads |

### Amazon Timestream for InfluxDB MCP Server

InfluxDB-compatible time-series operations.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-timestream-influxdb-mcp-server` |
| Purpose | Time-series queries, InfluxDB compatibility |
| IAM Permissions | `timestream-influxdb:*` |
| Use Cases | IoT data, metrics, time-series analytics |

### Amazon ElastiCache MCP Server

Complete ElastiCache operations.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-elasticache-mcp-server` |
| Purpose | Cache management, Redis/Memcached operations |
| IAM Permissions | `elasticache:*` |
| Use Cases | Caching, session management, real-time data |

### Amazon ElastiCache / MemoryDB for Valkey MCP Server

Advanced data structures and caching with Valkey.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-elasticache-valkey-mcp-server` |
| Purpose | Valkey operations, advanced caching |
| IAM Permissions | `elasticache:*`, `memorydb:*` |
| Use Cases | High-performance caching, data structures |

### Amazon ElastiCache for Memcached MCP Server

High-speed caching operations.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-elasticache-memcached-mcp-server` |
| Purpose | Memcached operations, simple caching |
| IAM Permissions | `elasticache:*` |
| Use Cases | Simple caching, session storage |

### AWS S3 Tables MCP Server

Manage and query S3-based tables.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-s3-tables-mcp-server` |
| Purpose | S3 table operations, Iceberg tables |
| IAM Permissions | `s3:*`, `s3-tables:*` |
| Use Cases | Data lakes, Iceberg workloads, analytics |

### AWS AppSync MCP Server

AWS AppSync backend API management.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-appsync-mcp-server` |
| Purpose | GraphQL API management, resolvers |
| IAM Permissions | `appsync:*` |
| Use Cases | GraphQL APIs, real-time subscriptions |

### AWS IoT SiteWise MCP Server

Industrial IoT asset management and analytics.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-iot-sitewise-mcp-server` |
| Purpose | Industrial assets, sensor data, analytics |
| IAM Permissions | `iotsitewise:*` |
| Use Cases | Industrial IoT, manufacturing analytics |

### Amazon Data Processing MCP Server

Data processing tools for AWS Glue and Amazon EMR.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-data-processing-mcp-server` |
| Purpose | ETL jobs, Spark processing, data pipelines |
| IAM Permissions | `glue:*`, `elasticmapreduce:*` |
| Use Cases | Data engineering, ETL, big data processing |

### Amazon Redshift MCP Server

Discover, explore, and query Redshift clusters.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-redshift-mcp-server` |
| Purpose | Data warehouse queries, analytics |
| IAM Permissions | `redshift:*`, `redshift-data:*` |
| Use Cases | Data warehousing, BI queries, analytics |

---

## Developer Tools & Support

### Git Repo Research MCP Server

Semantic code search and repository analysis.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.git-repo-research-mcp-server` |
| Purpose | Code search, repository analysis, semantic understanding |
| IAM Permissions | None (local git repos) |
| Use Cases | Code review, repository exploration, search |

### Code Documentation Generation MCP Server

Automated documentation from code.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.code-documentation-mcp-server` |
| Purpose | Generate docs from code, API documentation |
| IAM Permissions | None |
| Use Cases | Documentation automation, API docs |

### AWS Diagram MCP Server

Generate architecture diagrams.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-diagram-mcp-server` |
| Purpose | Create AWS architecture diagrams |
| IAM Permissions | None |
| Use Cases | Architecture visualization, documentation |

### Frontend MCP Server

React and modern web development guidance.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.frontend-mcp-server` |
| Purpose | React patterns, frontend best practices |
| IAM Permissions | None |
| Use Cases | Frontend development, React applications |

### Synthetic Data MCP Server

Generate realistic test data.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.synthetic-data-mcp-server` |
| Purpose | Generate test data, mock data |
| IAM Permissions | None |
| Use Cases | Testing, development, data mocking |

### AWS IAM MCP Server

IAM user, role, group, and policy management.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-iam-mcp-server` |
| Purpose | IAM management, policy creation, security |
| IAM Permissions | `iam:*` |
| Use Cases | Security management, access control, policies |

### AWS MSK MCP Server

Manage and monitor Amazon MSK clusters.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-msk-mcp-server` |
| Purpose | Kafka cluster management, monitoring |
| IAM Permissions | `kafka:*` |
| Use Cases | Kafka operations, streaming data |

---

## Integration & Messaging

### OpenAPI MCP Server

Dynamic API integration through OpenAPI specifications.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.openapi-mcp-server` |
| Purpose | REST API integration, OpenAPI spec parsing |
| IAM Permissions | Varies by API |
| Use Cases | API integration, REST operations |

### Amazon SNS / SQS MCP Server

Event-driven messaging and queue management.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-sns-sqs-mcp-server` |
| Purpose | Message publishing, queue operations |
| IAM Permissions | `sns:*`, `sqs:*` |
| Use Cases | Messaging, event-driven architecture |

### Amazon MQ MCP Server

Message broker management for RabbitMQ and ActiveMQ.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-mq-mcp-server` |
| Purpose | Message broker operations |
| IAM Permissions | `mq:*` |
| Use Cases | Enterprise messaging, broker management |

### AWS Step Functions MCP Server

Execute complex workflows and business processes.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-stepfunctions-mcp-server` |
| Purpose | Workflow execution, state machine management |
| IAM Permissions | `states:*` |
| Use Cases | Orchestration, workflows, business processes |

### Amazon Location Service MCP Server

Place search, geocoding, and route optimization.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-location-mcp-server` |
| Purpose | Geolocation, mapping, routing |
| IAM Permissions | `geo:*` |
| Use Cases | Location-based apps, mapping, navigation |

---

## Cost & Operations

### AWS Pricing MCP Server

Pre-deployment cost estimation and optimization.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-pricing-mcp-server` |
| Purpose | Cost estimation, pricing queries, multi-region comparison |
| IAM Permissions | `pricing:*` (free API) |
| Use Cases | Cost planning, architecture decisions, budgeting |

**Features:**
- Natural language pricing queries
- Multi-region cost comparison
- IaC project cost scanning
- Service discovery

### AWS Cost Explorer MCP Server

Detailed cost analysis and reporting.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-cost-explorer-mcp-server` |
| Purpose | Historical cost analysis, forecasting, anomaly detection |
| IAM Permissions | `ce:*` |
| Use Cases | Cost optimization, budget tracking, reporting |

### AWS Billing and Cost Management MCP Server

AWS billing and cost management operations.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-billing-mcp-server` |
| Purpose | Billing management, budget alerts |
| IAM Permissions | `aws-portal:*`, `budgets:*` |
| Use Cases | Billing automation, budget management |

### AWS Managed Prometheus MCP Server

Prometheus-compatible monitoring operations.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-amp-mcp-server` |
| Purpose | Prometheus queries, metric management |
| IAM Permissions | `aps:*` |
| Use Cases | Kubernetes monitoring, Prometheus queries |

### Amazon CloudWatch Application Signals MCP Server

Application monitoring and observability.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-cloudwatch-appsignals-mcp-server` |
| Purpose | Application performance monitoring |
| IAM Permissions | `cloudwatch:*`, `application-signals:*` |
| Use Cases | APM, application health, SLOs |

### Amazon CloudWatch MCP Server

Metrics, alarms, and logs analysis.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.amazon-cloudwatch-mcp-server` |
| Purpose | Metrics queries, alarm management, log analysis |
| IAM Permissions | `cloudwatch:*`, `logs:*` |
| Use Cases | Monitoring, alerting, log analysis |

### AWS CloudTrail MCP Server

AWS API activity and resource analysis.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-cloudtrail-mcp-server` |
| Purpose | Audit logs, API activity tracking |
| IAM Permissions | `cloudtrail:*` |
| Use Cases | Security audit, compliance, activity tracking |

### AWS Well-Architected Security Assessment Tool MCP Server

Security pillar assessment against Well-Architected Framework.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-well-architected-mcp-server` |
| Purpose | Security assessment, Well-Architected reviews |
| IAM Permissions | `wellarchitected:*` |
| Use Cases | Security reviews, compliance, architecture assessment |

---

## Healthcare & Lifesciences

### AWS HealthOmics MCP Server

Generate, run, and optimize lifescience workflows.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.aws-healthomics-mcp-server` |
| Purpose | Genomics workflows, bioinformatics |
| IAM Permissions | `omics:*` |
| Use Cases | Genomics, life sciences, bioinformatics pipelines |

### HealthLake MCP Server

FHIR interactions and AWS HealthLake datastores.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.healthlake-mcp-server` |
| Purpose | Healthcare data management, FHIR operations |
| IAM Permissions | `healthlake:*` |
| Use Cases | Healthcare data, FHIR, medical records |

---

## Advanced Analytics

### Amazon SageMaker Unified Studio MCP for Spark Troubleshooting

Apache Spark error analysis and debugging.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.sagemaker-spark-troubleshooting-mcp-server` |
| Purpose | Spark job debugging, error analysis |
| IAM Permissions | `sagemaker:*`, `emr:*` |
| Use Cases | Spark troubleshooting, job debugging |

### Amazon SageMaker Unified Studio MCP for Spark Upgrade

Spark application upgrades and migration.

| Attribute | Value |
|-----------|-------|
| Package | `awslabs.sagemaker-spark-upgrade-mcp-server` |
| Purpose | Spark version upgrades, migration assistance |
| IAM Permissions | `sagemaker:*` |
| Use Cases | Spark upgrades, migration planning |

---

## Configuration Examples

### Multi-Server Setup

```json
{
  "mcpServers": {
    "aws-docs": {
      "command": "uvx",
      "args": ["awslabs.aws-documentation-mcp-server@latest"]
    },
    "aws-pricing": {
      "command": "uvx",
      "args": ["awslabs.aws-pricing-mcp-server@latest"],
      "env": { "AWS_PROFILE": "default" }
    },
    "aws-cdk": {
      "command": "uvx",
      "args": ["awslabs.aws-cdk-mcp-server@latest"],
      "env": { "AWS_PROFILE": "dev" }
    },
    "aws-dynamodb": {
      "command": "uvx",
      "args": ["awslabs.amazon-dynamodb-mcp-server@latest"],
      "env": { "AWS_PROFILE": "prod", "AWS_REGION": "us-west-2" }
    }
  }
}
```

### Profile-Based Configuration

```json
{
  "mcpServers": {
    "aws-dev": {
      "command": "uvx",
      "args": ["awslabs.aws-api-mcp-server@latest"],
      "env": {
        "AWS_PROFILE": "dev-account",
        "AWS_REGION": "us-east-1"
      }
    },
    "aws-prod": {
      "command": "uvx",
      "args": ["awslabs.aws-api-mcp-server@latest"],
      "env": {
        "AWS_PROFILE": "prod-account",
        "AWS_REGION": "us-west-2"
      }
    }
  }
}
```

### Docker Deployment

```bash
# Run with default credentials
docker run -v ~/.aws:/root/.aws \
  -e AWS_PROFILE=default \
  awslabs/aws-pricing-mcp-server

# Run with explicit credentials
docker run \
  -e AWS_ACCESS_KEY_ID=AKIA... \
  -e AWS_SECRET_ACCESS_KEY=... \
  -e AWS_REGION=us-east-1 \
  awslabs/aws-pricing-mcp-server
```

---

## Use Case Mappings

| Task | Recommended Servers |
|------|---------------------|
| Architecture review | `aws-well-architected-mcp-server`, `aws-pricing-mcp-server`, `aws-documentation-mcp-server` |
| Cost optimization | `aws-pricing-mcp-server`, `aws-cost-explorer-mcp-server`, `aws-billing-mcp-server` |
| IaC development | `aws-cdk-mcp-server`, `aws-terraform-mcp-server`, `aws-cloudformation-mcp-server` |
| Container workloads | `amazon-ecs-mcp-server`, `amazon-eks-mcp-server`, `finch-mcp-server` |
| Database operations | `amazon-dynamodb-mcp-server`, `amazon-aurora-postgresql-mcp-server`, `amazon-neptune-mcp-server` |
| ML/AI projects | `amazon-bedrock-kb-retrieval-mcp-server`, `amazon-sagemaker-mcp-server`, `amazon-kendra-index-mcp-server` |
| Serverless apps | `aws-serverless-mcp-server`, `aws-lambda-tool-mcp-server`, `amazon-dynamodb-mcp-server` |
| Monitoring & Ops | `amazon-cloudwatch-mcp-server`, `aws-cloudtrail-mcp-server`, `aws-amp-mcp-server` |
| Security audit | `aws-iam-mcp-server`, `aws-well-architected-mcp-server`, `aws-cloudtrail-mcp-server` |
| Data engineering | `amazon-data-processing-mcp-server`, `amazon-redshift-mcp-server`, `aws-s3-tables-mcp-server` |
| Event-driven | `amazon-sns-sqs-mcp-server`, `aws-stepfunctions-mcp-server`, `amazon-mq-mcp-server` |
| Healthcare | `aws-healthomics-mcp-server`, `healthlake-mcp-server` |

---

## References

- [AWS MCP Servers GitHub](https://github.com/awslabs/mcp)
- [AWS MCP Documentation](https://awslabs.github.io/mcp/)
- [MCP Specification](https://modelcontextprotocol.io/)
