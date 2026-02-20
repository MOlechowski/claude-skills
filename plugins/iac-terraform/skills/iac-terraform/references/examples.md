# Terraform Examples

## AWS Infrastructure

### VPC with Subnets

```hcl
# variables.tf
variable "environment" {
  type    = string
  default = "dev"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

# main.tf
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.environment}-public-${count.index + 1}"
    Type = "public"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.environment}-private-${count.index + 1}"
    Type = "private"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# outputs.tf
output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}
```

### EC2 with Security Group

```hcl
resource "aws_security_group" "web" {
  name        = "${var.environment}-web-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-web-sg"
  }
}

resource "aws_instance" "web" {
  count                  = var.instance_count
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public[count.index % length(aws_subnet.public)].id
  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    Name        = "${var.environment}-web-${count.index + 1}"
    Environment = var.environment
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}
```

### RDS Database

```hcl
resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-db-subnet"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${var.environment}-db-subnet-group"
  }
}

resource "aws_security_group" "rds" {
  name        = "${var.environment}-rds-sg"
  description = "Security group for RDS"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  tags = {
    Name = "${var.environment}-rds-sg"
  }
}

resource "aws_db_instance" "main" {
  identifier             = "${var.environment}-db"
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = var.db_instance_class
  allocated_storage      = 20
  storage_type           = "gp3"
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  skip_final_snapshot    = var.environment != "production"
  multi_az               = var.environment == "production"

  tags = {
    Name        = "${var.environment}-db"
    Environment = var.environment
  }
}
```

## Terraform Cloud/Enterprise

### Basic Cloud Configuration

```hcl
terraform {
  cloud {
    organization = "my-organization"

    workspaces {
      name = "production-us-east"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}
```

### Multiple Workspaces with Tags

```hcl
terraform {
  cloud {
    organization = "my-organization"

    workspaces {
      tags = ["app:web-frontend", "region:us-east"]
    }
  }
}

# Select workspace at runtime
# terraform workspace select production-us-east
```

### Variable Sets in TFC

```hcl
# Variables configured in Terraform Cloud UI/API:
# - AWS_ACCESS_KEY_ID (environment, sensitive)
# - AWS_SECRET_ACCESS_KEY (environment, sensitive)
# - common_tags (terraform, HCL)

variable "common_tags" {
  type = map(string)
  # Value set in TFC Variable Set
}

resource "aws_instance" "web" {
  # ...
  tags = merge(var.common_tags, {
    Name = "web-server"
  })
}
```

### Run Triggers

```hcl
# In child workspace (app)
# Configure run trigger in TFC UI to watch parent workspace (networking)

data "terraform_remote_state" "networking" {
  backend = "remote"

  config = {
    organization = "my-organization"
    workspaces = {
      name = "networking-production"
    }
  }
}

resource "aws_instance" "web" {
  subnet_id = data.terraform_remote_state.networking.outputs.subnet_id
}
```

### Cost Estimation

```hcl
# Cost estimation is automatic in Terraform Cloud
# View estimated monthly cost changes in run output

# Enable cost estimation in workspace settings
# Costs appear in plan output for supported resources
```

## Sentinel Policies (Enterprise)

### Require Tags Policy

```sentinel
# require-tags.sentinel
import "tfplan/v2" as tfplan

required_tags = ["Environment", "Owner", "CostCenter"]

# Get all AWS resources that support tags
aws_resources = filter tfplan.resource_changes as _, rc {
  rc.provider_name matches "(.*)aws$" and
  rc.mode is "managed" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

# Check each resource has required tags
tags_check = rule {
  all aws_resources as _, resource {
    all required_tags as tag {
      resource.change.after.tags else {} contains tag
    }
  }
}

main = rule {
  tags_check
}
```

### Restrict Instance Types

```sentinel
# restrict-instance-types.sentinel
import "tfplan/v2" as tfplan

allowed_types = ["t3.micro", "t3.small", "t3.medium"]

ec2_instances = filter tfplan.resource_changes as _, rc {
  rc.type is "aws_instance" and
  (rc.change.actions contains "create" or rc.change.actions contains "update")
}

instance_type_check = rule {
  all ec2_instances as _, instance {
    instance.change.after.instance_type in allowed_types
  }
}

main = rule {
  instance_type_check
}
```

### Working Hours Policy

```sentinel
# working-hours.sentinel
import "time"

# Only allow applies during business hours (9 AM - 5 PM EST, weekdays)
param allowed_hours = [9, 10, 11, 12, 13, 14, 15, 16, 17]
param allowed_days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

current_time = time.now
current_hour = current_time.hour
current_day = current_time.weekday_name

main = rule {
  current_hour in allowed_hours and current_day in allowed_days
}
```

## Multi-Cloud Patterns

### GCP Compute Instance

```hcl
provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_compute_network" "vpc" {
  name                    = "${var.environment}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.environment}-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.vpc.id
}

resource "google_compute_instance" "web" {
  name         = "${var.environment}-web"
  machine_type = "e2-medium"
  zone         = "${var.region}-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.subnet.id
    access_config {}
  }

  tags = ["web", var.environment]
}
```

### Azure Resource Group and VM

```hcl
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "main" {
  name     = "${var.environment}-rg"
  location = var.location
}

resource "azurerm_virtual_network" "main" {
  name                = "${var.environment}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_subnet" "internal" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_linux_virtual_machine" "web" {
  name                = "${var.environment}-vm"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = "Standard_B2s"
  admin_username      = "adminuser"

  network_interface_ids = [azurerm_network_interface.main.id]

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}
```

## Module Patterns

### Reusable VPC Module

```hcl
# modules/vpc/variables.tf
variable "name" {
  type        = string
  description = "Name prefix for resources"
}

variable "cidr" {
  type        = string
  description = "VPC CIDR block"
}

variable "azs" {
  type        = list(string)
  description = "Availability zones"
}

variable "private_subnets" {
  type        = list(string)
  description = "Private subnet CIDRs"
}

variable "public_subnets" {
  type        = list(string)
  description = "Public subnet CIDRs"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags"
}

# modules/vpc/main.tf
resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.tags, {
    Name = var.name
  })
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnets)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.name}-public-${count.index + 1}"
    Type = "public"
  })
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = var.azs[count.index]

  tags = merge(var.tags, {
    Name = "${var.name}-private-${count.index + 1}"
    Type = "private"
  })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {
    Name = "${var.name}-igw"
  })
}

# modules/vpc/outputs.tf
output "vpc_id" {
  value       = aws_vpc.this.id
  description = "VPC ID"
}

output "public_subnet_ids" {
  value       = aws_subnet.public[*].id
  description = "Public subnet IDs"
}

output "private_subnet_ids" {
  value       = aws_subnet.private[*].id
  description = "Private subnet IDs"
}
```

### Module Composition

```hcl
# Root module using child modules
module "vpc" {
  source = "./modules/vpc"

  name            = "${var.project}-${var.environment}"
  cidr            = var.vpc_cidr
  azs             = var.availability_zones
  public_subnets  = var.public_subnet_cidrs
  private_subnets = var.private_subnet_cidrs

  tags = local.common_tags
}

module "web" {
  source = "./modules/ec2-cluster"

  name           = "${var.project}-web"
  instance_count = var.web_instance_count
  instance_type  = var.web_instance_type
  subnet_ids     = module.vpc.public_subnet_ids
  vpc_id         = module.vpc.vpc_id

  tags = local.common_tags
}

module "db" {
  source = "./modules/rds"

  name               = "${var.project}-db"
  engine             = "postgres"
  instance_class     = var.db_instance_class
  subnet_ids         = module.vpc.private_subnet_ids
  vpc_id             = module.vpc.vpc_id
  allowed_sg_ids     = [module.web.security_group_id]

  tags = local.common_tags
}
```

## State Migration

### Migrate from Local to S3

```bash
# 1. Add backend configuration
cat >> backend.tf << 'EOF'
terraform {
  backend "s3" {
    bucket         = "my-tf-state"
    key            = "project/iac-terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tf-locks"
    encrypt        = true
  }
}
EOF

# 2. Initialize with migration
terraform init -migrate-state

# 3. Verify
terraform plan  # Should show no changes
```

### Migrate to Terraform Cloud

```bash
# 1. Login to Terraform Cloud
terraform login

# 2. Update configuration
cat > backend.tf << 'EOF'
terraform {
  cloud {
    organization = "my-org"
    workspaces {
      name = "production"
    }
  }
}
EOF

# 3. Initialize with migration
terraform init -migrate-state

# 4. Verify in TFC UI
```

### Move Resources Between States

```bash
# Backup both states
terraform state pull > old-state.backup
cd ../new-project && terraform state pull > new-state.backup

# Move resource from old to new
cd ../old-project
terraform state mv -state-out=../new-project/iac-terraform.tfstate \
  aws_instance.web aws_instance.web

# Verify both projects
terraform plan  # Old project - should want to create
cd ../new-project && terraform plan  # New project - no changes
```

## CI/CD Integration

### GitHub Actions Complete Workflow

```yaml
name: Terraform

on:
  pull_request:
    paths:
      - 'terraform/**'
  push:
    branches:
      - main
    paths:
      - 'terraform/**'

env:
  TF_VERSION: '1.6.0'
  WORKING_DIR: './iac-terraform'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}

      - name: Terraform Format Check
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform fmt -check -recursive

      - name: Terraform Init
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform init -backend=false

      - name: Terraform Validate
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform validate

  plan:
    needs: validate
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Terraform Init
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform init

      - name: Terraform Plan
        id: plan
        working-directory: ${{ env.WORKING_DIR }}
        run: |
          terraform plan -out=tfplan -no-color 2>&1 | tee plan.txt
          echo "plan<<EOF" >> $GITHUB_OUTPUT
          cat plan.txt >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT

      - name: Upload Plan
        uses: actions/upload-artifact@v4
        with:
          name: tfplan
          path: ${{ env.WORKING_DIR }}/tfplan

      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const plan = `${{ steps.plan.outputs.plan }}`;
            const output = `## Terraform Plan
            \`\`\`
            ${plan.substring(0, 65000)}
            \`\`\`
            `;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: output
            });

  apply:
    needs: plan
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TF_VERSION }}

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Download Plan
        uses: actions/download-artifact@v4
        with:
          name: tfplan
          path: ${{ env.WORKING_DIR }}

      - name: Terraform Init
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform init

      - name: Terraform Apply
        working-directory: ${{ env.WORKING_DIR }}
        run: terraform apply -auto-approve tfplan
```

### Terraform Cloud with GitHub Actions

```yaml
name: Terraform Cloud

on:
  pull_request:
  push:
    branches: [main]

jobs:
  terraform:
    runs-on: ubuntu-latest
    env:
      TF_CLOUD_ORGANIZATION: "my-org"
      TF_API_TOKEN: ${{ secrets.TF_API_TOKEN }}
      TF_WORKSPACE: "production"
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          cli_config_credentials_token: ${{ secrets.TF_API_TOKEN }}

      - name: Terraform Init
        run: terraform init

      - name: Terraform Plan
        run: terraform plan
        # Plan runs in Terraform Cloud

      - name: Terraform Apply
        if: github.ref == 'refs/heads/main'
        run: terraform apply -auto-approve
        # Apply runs in Terraform Cloud
```

## Security Patterns

### Secrets Management with AWS Secrets Manager

```hcl
data "aws_secretsmanager_secret" "db_credentials" {
  name = "production/db/credentials"
}

data "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = data.aws_secretsmanager_secret.db_credentials.id
}

locals {
  db_creds = jsondecode(data.aws_secretsmanager_secret_version.db_credentials.secret_string)
}

resource "aws_db_instance" "main" {
  # ... other config ...
  username = local.db_creds["username"]
  password = local.db_creds["password"]
}
```

### Sensitive Variables

```hcl
variable "db_password" {
  type      = string
  sensitive = true
}

output "db_connection_string" {
  value     = "postgresql://${var.db_username}:${var.db_password}@${aws_db_instance.main.endpoint}/${var.db_name}"
  sensitive = true
}
```

### Least Privilege IAM

```hcl
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "lambda_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.data.arn}/*"]
  }
}

resource "aws_iam_role" "lambda" {
  name               = "lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "lambda" {
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}
```

## Troubleshooting

### Common Errors and Fixes

**Provider not found**
```bash
# Error: provider registry.terraform.io/hashicorp/aws not found
terraform init -upgrade
```

**State lock stuck**
```bash
# Error: Error acquiring the state lock
# Get lock ID from error message
terraform force-unlock LOCK_ID
```

**Resource already exists**
```bash
# Error: aws_instance.web already exists
# Import the existing resource
terraform import aws_instance.web i-1234567890abcdef0
```

**Cycle detected**
```bash
# Error: Cycle: aws_instance.a, aws_instance.b
# Review depends_on and remove circular references
# Use explicit depends_on only when necessary
```

**Timeout errors**
```bash
# Error: timeout while waiting for state
# Increase timeout in resource
resource "aws_db_instance" "main" {
  # ...
  timeouts {
    create = "60m"
    delete = "60m"
  }
}
```

**State out of sync**
```bash
# Refresh state from real infrastructure
terraform refresh

# Or use plan with refresh
terraform plan -refresh=true
```

**Terraform Cloud authentication**
```bash
# Error: unauthorized
terraform login
# Or set TF_TOKEN_app_terraform_io environment variable
```
