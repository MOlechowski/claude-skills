#!/usr/bin/env python3
"""
Scaffold a new Terraform/OpenTofu module with best-practice structure.

Usage:
    python3 scaffold_module.py --name networking --type basic --output ./modules/networking
    python3 scaffold_module.py --name vpc --type enterprise --output ./modules/vpc
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


def scaffold_basic(output_dir: Path, name: str) -> None:
    """Create basic module structure."""

    # main.tf
    create_file(output_dir / "main.tf", f'''# {name} module
#
# This module manages {name} resources.

terraform {{
  required_version = ">= 1.5.0"
}}

# TODO: Add resources here
''')

    # variables.tf
    create_file(output_dir / "variables.tf", '''# Input variables

variable "name" {
  type        = string
  description = "Name prefix for resources"
}

variable "environment" {
  type        = string
  description = "Environment name (e.g., dev, staging, prod)"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to all resources"
  default     = {}
}
''')

    # outputs.tf
    create_file(output_dir / "outputs.tf", '''# Output values

# TODO: Add outputs here
# output "id" {
#   description = "The resource ID"
#   value       = aws_resource.main.id
# }
''')


def scaffold_enterprise(output_dir: Path, name: str) -> None:
    """Create enterprise module structure with tests and examples."""

    # Start with basic structure
    scaffold_basic(output_dir, name)

    # versions.tf
    create_file(output_dir / "versions.tf", '''terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}
''')

    # locals.tf
    create_file(output_dir / "locals.tf", '''locals {
  name_prefix = "${var.name}-${var.environment}"

  common_tags = merge(var.tags, {
    Module      = "''' + name + '''"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}
''')

    # README.md
    create_file(output_dir / "README.md", f'''# {name.title()} Module

## Description

This module manages {name} resources.

## Usage

```hcl
module "{name}" {{
  source = "git::https://github.com/org/modules.git//{name}?ref=v1.0.0"

  name        = "my-{name}"
  environment = "prod"

  tags = {{
    Owner = "platform-team"
  }}
}}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| name | Name prefix for resources | `string` | n/a | yes |
| environment | Environment name | `string` | n/a | yes |
| tags | Tags to apply to all resources | `map(string)` | `{{}}` | no |

## Outputs

| Name | Description |
|------|-------------|
| (none yet) | |

<!-- BEGIN_TF_DOCS -->
<!-- END_TF_DOCS -->
''')

    # tests/main_test.go
    create_file(output_dir / "tests" / "main_test.go", f'''package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func Test{name.title().replace("-", "")}Module(t *testing.T) {{
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{{
		TerraformDir: "../examples/basic",
	}})

	defer terraform.Destroy(t, terraformOptions)

	terraform.InitAndApply(t, terraformOptions)

	// TODO: Add assertions
	// output := terraform.Output(t, terraformOptions, "id")
	// assert.NotEmpty(t, output)
	assert.True(t, true) // Placeholder
}}
''')

    # examples/basic/main.tf
    create_file(output_dir / "examples" / "basic" / "main.tf", f'''# Basic example for {name} module

provider "aws" {{
  region = "us-east-1"
}}

module "{name}" {{
  source = "../../"

  name        = "example-{name}"
  environment = "dev"

  tags = {{
    Example = "basic"
  }}
}}
''')

    # examples/basic/outputs.tf
    create_file(output_dir / "examples" / "basic" / "outputs.tf", '''# Example outputs

# output "id" {
#   value = module.''' + name + '''.id
# }
''')

    # .terraform-docs.yml
    create_file(output_dir / ".terraform-docs.yml", '''formatter: "markdown table"

sections:
  show:
    - requirements
    - providers
    - inputs
    - outputs

output:
  file: README.md
  mode: inject
  template: |-
    <!-- BEGIN_TF_DOCS -->
    {{ .Content }}
    <!-- END_TF_DOCS -->

sort:
  enabled: true
  by: name
''')


def main():
    parser = argparse.ArgumentParser(
        description="Scaffold a new Terraform/OpenTofu module"
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Module name (e.g., networking, vpc, database)"
    )
    parser.add_argument(
        "--type",
        choices=["basic", "enterprise"],
        default="basic",
        help="Module type: basic (minimal) or enterprise (with tests, examples)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for the module"
    )

    args = parser.parse_args()

    output_dir = Path(args.output).resolve()

    if output_dir.exists() and any(output_dir.iterdir()):
        print(f"Error: Directory {output_dir} already exists and is not empty")
        sys.exit(1)

    print(f"Scaffolding {args.type} module: {args.name}")
    print(f"Output directory: {output_dir}")
    print()

    if args.type == "basic":
        scaffold_basic(output_dir, args.name)
    else:
        scaffold_enterprise(output_dir, args.name)

    print()
    print(f"Module '{args.name}' created successfully!")
    print()
    print("Next steps:")
    print(f"  1. cd {output_dir}")
    print("  2. Add resources to main.tf")
    print("  3. Define inputs in variables.tf")
    print("  4. Export outputs in outputs.tf")
    if args.type == "enterprise":
        print("  5. Update tests in tests/main_test.go")
        print("  6. Run: terraform-docs markdown table --output-file README.md .")


if __name__ == "__main__":
    main()
