# OpenTofu Examples

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
tofu init -migrate-state

# 3. Verify
tofu plan  # Should show no changes
```

### Move Resources Between States

```bash
# Backup both states
tofu state pull > old-state.backup
cd ../new-project && tofu state pull > new-state.backup

# Move resource from old to new
cd ../old-project
tofu state mv -state-out=../new-project/iac-terraform.tfstate \
  aws_instance.web aws_instance.web

# Verify both projects
tofu plan  # Old project - should want to create
cd ../new-project && tofu plan  # New project - no changes
```

### Rename Resources Without Recreation

```bash
# 1. Rename in state
tofu state mv aws_instance.old_name aws_instance.new_name

# 2. Update .tf file to match
# Change: resource "aws_instance" "old_name" to "new_name"

# 3. Verify no changes
tofu plan  # Should show no changes
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

      - uses: opentofu/setup-opentofu@v1
        with:
          tofu_version: ${{ env.TF_VERSION }}

      - name: Terraform Format Check
        working-directory: ${{ env.WORKING_DIR }}
        run: tofu fmt -check -recursive

      - name: Terraform Init
        working-directory: ${{ env.WORKING_DIR }}
        run: tofu init -backend=false

      - name: Terraform Validate
        working-directory: ${{ env.WORKING_DIR }}
        run: tofu validate

  plan:
    needs: validate
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - uses: opentofu/setup-opentofu@v1
        with:
          tofu_version: ${{ env.TF_VERSION }}

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Terraform Init
        working-directory: ${{ env.WORKING_DIR }}
        run: tofu init

      - name: Terraform Plan
        id: plan
        working-directory: ${{ env.WORKING_DIR }}
        run: |
          tofu plan -out=tfplan -no-color 2>&1 | tee plan.txt
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

      - uses: opentofu/setup-opentofu@v1
        with:
          tofu_version: ${{ env.TF_VERSION }}

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
        run: tofu init

      - name: Terraform Apply
        working-directory: ${{ env.WORKING_DIR }}
        run: tofu apply -auto-approve tfplan
```

### GitLab CI Pipeline

```yaml
stages:
  - validate
  - plan
  - apply

variables:
  TF_ROOT: ${CI_PROJECT_DIR}/iac-terraform

.terraform:
  image: ghcr.io/opentofu/opentofu:1.6
  before_script:
    - cd ${TF_ROOT}
    - tofu init

validate:
  extends: .terraform
  stage: validate
  script:
    - tofu fmt -check -recursive
    - tofu validate

plan:
  extends: .terraform
  stage: plan
  script:
    - tofu plan -out=plan.tfplan
  artifacts:
    paths:
      - ${TF_ROOT}/plan.tfplan
    expire_in: 1 week

apply:
  extends: .terraform
  stage: apply
  script:
    - tofu apply plan.tfplan
  dependencies:
    - plan
  when: manual
  only:
    - main
```

## Drift Detection

### Scheduled Drift Check

```bash
#!/bin/bash
# drift-check.sh

set -e

tofu init -input=false

# Check for drift
if tofu plan -detailed-exitcode -refresh-only; then
  echo "No drift detected"
  exit 0
else
  exit_code=$?
  if [ $exit_code -eq 2 ]; then
    echo "DRIFT DETECTED"
    tofu plan -refresh-only -no-color > drift-report.txt
    # Send notification (Slack, email, etc.)
    exit 1
  else
    echo "Error running plan"
    exit $exit_code
  fi
fi
```

### Drift Remediation

```bash
# Option 1: Accept current real-world state
tofu apply -refresh-only -auto-approve

# Option 2: Revert to desired state
tofu apply -auto-approve

# Option 3: Import the drifted resource
tofu import aws_instance.web i-1234567890abcdef0
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
# Error: provider registry.opentofu.org/hashicorp/aws not found
tofu init -upgrade
```

**State lock stuck**
```bash
# Error: Error acquiring the state lock
# Get lock ID from error message
tofu force-unlock LOCK_ID
```

**Resource already exists**
```bash
# Error: aws_instance.web already exists
# Import the existing resource
tofu import aws_instance.web i-1234567890abcdef0
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
tofu refresh

# Or use plan with refresh
tofu plan -refresh=true
```
