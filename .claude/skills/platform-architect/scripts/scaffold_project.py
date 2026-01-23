#!/usr/bin/env python3
"""
Scaffold a new Terraform/OpenTofu project with best-practice structure.

Usage:
    python3 scaffold_project.py --name my-platform --layout monorepo --environments dev,staging,prod --output ./my-platform
    python3 scaffold_project.py --name my-service --layout polyrepo --environments dev,prod --output ./infra
"""

import argparse
import os
import sys
from pathlib import Path


def create_file(path: Path, content: str) -> None:
    """Create a file with the given content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    print(f"  Created: {path}")


def scaffold_monorepo(output_dir: Path, name: str, environments: list) -> None:
    """Create monorepo project structure."""

    # Root README
    create_file(output_dir / "README.md", f'''# {name.title()} Infrastructure

Infrastructure as Code for {name}.

## Structure

```
.
├── environments/     # Environment-specific configurations
│   ├── dev/
│   ├── staging/
│   └── prod/
├── modules/          # Reusable modules
│   └── ...
└── .github/          # CI/CD workflows
    └── workflows/
```

## Quick Start

```bash
# Initialize dev environment
cd environments/dev
terraform init
terraform plan
```

## Environments

| Environment | Description |
|-------------|-------------|
''' + "\n".join([f"| {env} | {env.title()} environment |" for env in environments]) + '''

## CI/CD

- Pull Request → Plan → Review
- Merge to main → Apply to staging
- Tag release → Apply to prod
''')

    # .gitignore
    create_file(output_dir / ".gitignore", '''# Terraform
*.tfstate
*.tfstate.*
*.tfplan
.terraform/
.terraform.lock.hcl
crash.log
override.tf
override.tf.json
*_override.tf
*_override.tf.json

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Secrets (never commit)
*.tfvars
!*.example.tfvars
secrets/
''')

    # Makefile
    create_file(output_dir / "Makefile", f'''.PHONY: init plan apply destroy fmt validate

ENV ?= dev

init:
\tcd environments/$(ENV) && terraform init

plan:
\tcd environments/$(ENV) && terraform plan

apply:
\tcd environments/$(ENV) && terraform apply

destroy:
\tcd environments/$(ENV) && terraform destroy

fmt:
\tterraform fmt -recursive

validate:
\tfor dir in environments/*/; do \\
\t\techo "Validating $$dir"; \\
\t\tcd $$dir && terraform init -backend=false && terraform validate && cd ../..; \\
\tdone

docs:
\tfor dir in modules/*/; do \\
\t\tterraform-docs markdown table --output-file README.md $$dir; \\
\tdone
''')

    # Environment directories
    for env in environments:
        env_dir = output_dir / "environments" / env

        # main.tf
        create_file(env_dir / "main.tf", f'''# {env.title()} Environment

terraform {{
  required_version = ">= 1.5.0"

  # backend "s3" {{
  #   bucket         = "{name}-terraform-state"
  #   key            = "{env}/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }}
}}

provider "aws" {{
  region = var.aws_region

  default_tags {{
    tags = {{
      Environment = "{env}"
      Project     = "{name}"
      ManagedBy   = "terraform"
    }}
  }}
}}

# Example module usage:
# module "networking" {{
#   source = "../../modules/networking"
#
#   name        = "{name}"
#   environment = "{env}"
#   cidr_block  = var.vpc_cidr
# }}
''')

        # variables.tf
        create_file(env_dir / "variables.tf", '''variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR block"
}
''')

        # outputs.tf
        create_file(env_dir / "outputs.tf", '''# Outputs
# output "vpc_id" {
#   value = module.networking.vpc_id
# }
''')

        # terraform.tfvars.example
        is_prod = env == "prod"
        create_file(env_dir / "terraform.tfvars.example", f'''aws_region = "us-east-1"
vpc_cidr   = "{"10.0.0.0/16" if is_prod else "10.1.0.0/16"}"
''')

    # Placeholder module
    create_file(output_dir / "modules" / ".gitkeep", "")

    # GitHub Actions
    create_file(output_dir / ".github" / "workflows" / "terraform-plan.yml", f'''name: Terraform Plan
on:
  pull_request:
    paths:
      - 'environments/**'
      - 'modules/**'

jobs:
  plan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [{", ".join(environments)}]
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.6.0

      - name: Terraform Init
        run: terraform init
        working-directory: environments/${{{{ matrix.environment }}}}

      - name: Terraform Plan
        run: terraform plan -no-color
        working-directory: environments/${{{{ matrix.environment }}}}
''')

    create_file(output_dir / ".github" / "workflows" / "terraform-apply.yml", f'''name: Terraform Apply
on:
  push:
    branches: [main]
    paths:
      - 'environments/**'
      - 'modules/**'

jobs:
  apply-staging:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3

      - name: Terraform Init
        run: terraform init
        working-directory: environments/staging

      - name: Terraform Apply
        run: terraform apply -auto-approve
        working-directory: environments/staging
''')


def scaffold_polyrepo(output_dir: Path, name: str, environments: list) -> None:
    """Create polyrepo (single component) project structure."""

    # README
    create_file(output_dir / "README.md", f'''# {name.title()} Infrastructure

Infrastructure as Code for {name}.

## Usage

```bash
# Plan with environment-specific vars
terraform plan -var-file=environments/dev.tfvars

# Apply
terraform apply -var-file=environments/prod.tfvars
```

## Environments

''' + "\n".join([f"- {env}" for env in environments]))

    # .gitignore
    create_file(output_dir / ".gitignore", '''*.tfstate
*.tfstate.*
*.tfplan
.terraform/
.terraform.lock.hcl
crash.log
''')

    # main.tf
    create_file(output_dir / "main.tf", f'''terraform {{
  required_version = ">= 1.5.0"

  # backend "s3" {{
  #   bucket         = "{name}-terraform-state"
  #   key            = "terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }}
}}

provider "aws" {{
  region = var.aws_region

  default_tags {{
    tags = {{
      Environment = var.environment
      Project     = "{name}"
      ManagedBy   = "terraform"
    }}
  }}
}}

# Resources go here
''')

    # variables.tf
    create_file(output_dir / "variables.tf", f'''variable "environment" {{
  type        = string
  description = "Environment name"

  validation {{
    condition     = contains([{", ".join([f'"{e}"' for e in environments])}], var.environment)
    error_message = "Environment must be one of: {", ".join(environments)}."
  }}
}}

variable "aws_region" {{
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}}
''')

    # outputs.tf
    create_file(output_dir / "outputs.tf", '''# Outputs
''')

    # Environment var files
    for env in environments:
        create_file(output_dir / "environments" / f"{env}.tfvars", f'''environment = "{env}"
aws_region  = "us-east-1"
''')


def main():
    parser = argparse.ArgumentParser(
        description="Scaffold a new Terraform/OpenTofu project"
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Project name"
    )
    parser.add_argument(
        "--layout",
        choices=["monorepo", "polyrepo"],
        default="monorepo",
        help="Project layout: monorepo (multi-env directories) or polyrepo (tfvars-based)"
    )
    parser.add_argument(
        "--environments",
        required=True,
        help="Comma-separated list of environments (e.g., dev,staging,prod)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for the project"
    )

    args = parser.parse_args()

    output_dir = Path(args.output).resolve()
    environments = [e.strip() for e in args.environments.split(",")]

    if output_dir.exists() and any(output_dir.iterdir()):
        print(f"Error: Directory {output_dir} already exists and is not empty")
        sys.exit(1)

    print(f"Scaffolding {args.layout} project: {args.name}")
    print(f"Environments: {', '.join(environments)}")
    print(f"Output directory: {output_dir}")
    print()

    if args.layout == "monorepo":
        scaffold_monorepo(output_dir, args.name, environments)
    else:
        scaffold_polyrepo(output_dir, args.name, environments)

    print()
    print(f"Project '{args.name}' created successfully!")
    print()
    print("Next steps:")
    print(f"  1. cd {output_dir}")
    print("  2. Configure backend in main.tf")
    print("  3. Add modules to modules/ directory")
    if args.layout == "monorepo":
        print("  4. Run: make init ENV=dev")
    else:
        print("  4. Run: terraform init")


if __name__ == "__main__":
    main()
