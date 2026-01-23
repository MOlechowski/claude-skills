# {{ project_name }} Infrastructure

Infrastructure as Code for {{ project_name }}.

## Structure

```
.
├── main.tf               # Main configuration
├── variables.tf          # Input variables
├── outputs.tf            # Outputs
├── versions.tf           # Provider versions
├── environments/         # Environment variable files
│   ├── dev.tfvars
│   ├── staging.tfvars
│   └── prod.tfvars
└── README.md
```

## Usage

```bash
# Initialize
terraform init

# Plan for specific environment
terraform plan -var-file=environments/dev.tfvars

# Apply
terraform apply -var-file=environments/prod.tfvars
```

## Environments

| Environment | Description |
|-------------|-------------|
| dev | Development environment |
| staging | Pre-production testing |
| prod | Production environment |

## Variables

| Name | Description | Type | Required |
|------|-------------|------|:--------:|
| environment | Environment name | string | yes |
| aws_region | AWS region | string | no |

## Outputs

| Name | Description |
|------|-------------|
| (define outputs) | |
