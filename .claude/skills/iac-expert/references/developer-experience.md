# Developer Experience

## Contents
- [Local Development Setup](#local-development-setup) - Tools, versions, IDE
- [Fast Feedback Loops](#fast-feedback-loops) - Pre-commit, auto-format, validate
- [IDE Integration](#ide-integration) - VS Code, JetBrains, Neovim
- [CLI Productivity](#cli-productivity) - Aliases, tfenv, completions
- [Module Development](#module-development) - Local iteration, testing workflow
- [Debugging Workflows](#debugging-workflows) - Console, outputs, graph
- [Onboarding Guide](#onboarding-guide) - New developer checklist
- [DX Anti-patterns](#dx-anti-patterns) - Common mistakes

## Local Development Setup

### Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| terraform/iac-tofu | IAC engine | `brew install terraform` or `brew install opentofu` |
| tfenv/tofuenv | Version manager | `brew install tfenv` |
| tflint | Linter | `brew install tflint` |
| terraform-docs | Doc generator | `brew install terraform-docs` |
| pre-commit | Git hooks | `brew install pre-commit` |
| jq | JSON processor | `brew install jq` |

### Version Management

```bash
# Install tfenv
brew install tfenv

# List available versions
tfenv list-remote

# Install specific version
tfenv install 1.6.0

# Use version (creates .terraform-version)
tfenv use 1.6.0

# Pin version for project
echo "1.6.0" > .terraform-version
```

### OpenTofu Alternative

```bash
# Install tofuenv
brew install tofuenv

# Install and use
tofuenv install 1.6.0
tofuenv use 1.6.0

# Pin version
echo "1.6.0" > .opentofu-version
```

### Full Setup (macOS)

```bash
# Core tools
brew install tfenv tflint terraform-docs pre-commit jq

# Install terraform
tfenv install 1.6.0
tfenv use 1.6.0

# Verify
terraform version
tflint --version
terraform-docs --version
```

### Full Setup (Linux)

```bash
# tfenv
git clone https://github.com/tfutils/tfenv.git ~/.tfenv
echo 'export PATH="$HOME/.tfenv/bin:$PATH"' >> ~/.bashrc

# tflint
curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash

# terraform-docs
curl -sSLo ./terraform-docs.tar.gz https://terraform-docs.io/dl/v0.17.0/terraform-docs-v0.17.0-linux-amd64.tar.gz
tar -xzf terraform-docs.tar.gz
chmod +x terraform-docs
mv terraform-docs /usr/local/bin/

# pre-commit
pip install pre-commit
```

## Fast Feedback Loops

### Pre-commit Configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/antonbabenko/pre-commit-terraform
    rev: v1.83.5
    hooks:
      - id: terraform_fmt
      - id: terraform_validate
      - id: terraform_tflint
        args:
          - --args=--config=__GIT_WORKING_DIR__/.tflint.hcl
      - id: terraform_docs
        args:
          - --args=--config=.terraform-docs.yml

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-merge-conflict
```

```bash
# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files

# Skip hooks (emergency only)
git commit --no-verify -m "fix"
```

### tflint Configuration

```hcl
# .tflint.hcl
plugin "aws" {
  enabled = true
  version = "0.27.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

rule "terraform_naming_convention" {
  enabled = true
}

rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = true
}
```

### terraform-docs Configuration

```yaml
# .terraform-docs.yml
formatter: markdown table

output:
  file: README.md
  mode: inject

sort:
  enabled: true
  by: required

settings:
  anchor: true
  default: true
  required: true
  type: true
```

### Quick Validation Script

```bash
#!/bin/bash
# scripts/validate.sh

set -e

echo "Formatting..."
terraform fmt -recursive

echo "Validating..."
terraform init -backend=false
terraform validate

echo "Linting..."
tflint --recursive

echo "All checks passed"
```

## IDE Integration

### VS Code

**Extensions:**
- HashiCorp Terraform (hashicorp.terraform)
- Terraform doc snippets (optional)

**settings.json:**
```json
{
  "[terraform]": {
    "editor.defaultFormatter": "hashicorp.terraform",
    "editor.formatOnSave": true
  },
  "[terraform-vars]": {
    "editor.defaultFormatter": "hashicorp.terraform",
    "editor.formatOnSave": true
  },
  "terraform.languageServer.enable": true,
  "terraform.languageServer.args": ["serve"],
  "terraform.validation.enableEnhancedValidation": true
}
```

### JetBrains (IntelliJ, GoLand)

1. Install "HashiCorp Terraform / HCL language support" plugin
2. Settings > Languages & Frameworks > Terraform
3. Enable: Format on save, Auto-completion

### Neovim

```lua
-- LSP configuration for terraform-ls
require('lspconfig').terraformls.setup{
  cmd = { "terraform-ls", "serve" },
  filetypes = { "terraform", "terraform-vars" },
  root_dir = require('lspconfig').util.root_pattern(".terraform", ".git"),
}

-- Auto-format on save
vim.api.nvim_create_autocmd("BufWritePre", {
  pattern = { "*.tf", "*.tfvars" },
  callback = function()
    vim.lsp.buf.format()
  end,
})
```

Install terraform-ls:
```bash
brew install hashicorp/tap/terraform-ls
```

## CLI Productivity

### Shell Aliases

```bash
# ~/.bashrc or ~/.zshrc

# Terraform shortcuts
alias tf="terraform"
alias tfi="terraform init"
alias tfp="terraform plan"
alias tfa="terraform apply"
alias tfd="terraform destroy"
alias tfv="terraform validate"
alias tff="terraform fmt -recursive"
alias tfs="terraform state"
alias tfo="terraform output"

# Common workflows
alias tfpa="terraform plan -out=tfplan && terraform apply tfplan"
alias tfcheck="terraform fmt -check -recursive && terraform validate && tflint"

# State operations
alias tfsl="terraform state list"
alias tfss="terraform state show"
alias tfsp="terraform state pull | jq"

# OpenTofu alternatives
alias tofu="tofu"
alias tofui="tofu init"
alias tofup="tofu plan"
```

### Shell Completions

```bash
# Bash
terraform -install-autocomplete

# Zsh (add to .zshrc)
autoload -U +X bashcompinit && bashcompinit
complete -o nospace -C /usr/local/bin/iac-terraform terraform
```

### Useful Functions

```bash
# Quick plan with auto-approve for dev
tfdev() {
  terraform plan -var-file=environments/dev.tfvars "$@"
}

# Target specific module
tftarget() {
  terraform plan -target="module.$1"
}

# Show resource in state
tfshow() {
  terraform state show "$1" | less
}

# List resources matching pattern
tfgrep() {
  terraform state list | grep "$1"
}
```

### State Inspection with jq

```bash
# Pull state and inspect
terraform state pull > state.json

# List all resource types
jq -r '.resources[].type' state.json | sort -u

# Find specific resource
jq '.resources[] | select(.name == "main")' state.json

# Count resources by type
jq -r '.resources[].type' state.json | sort | uniq -c | sort -rn

# Extract outputs
jq '.outputs' state.json
```

## Module Development

### Local Module References

```hcl
# During development, reference local modules
module "vpc" {
  source = "../modules/vpc"  # Local path

  name = "dev-vpc"
  cidr = "10.0.0.0/16"
}

# After publishing, use versioned source
module "vpc" {
  source  = "git::https://github.com/org/modules.git//vpc?ref=v1.2.0"
  # or
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
}
```

### Rapid Iteration Workflow

```bash
# 1. Make changes to module
vim modules/vpc/main.tf

# 2. Re-init to pick up changes (if structure changed)
terraform init -upgrade

# 3. Plan to see effect
terraform plan

# 4. Repeat until satisfied
```

### Module Testing Directory Structure

```
modules/
├── vpc/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── README.md
│   ├── examples/
│   │   └── simple/
│   │       ├── main.tf
│   │       └── outputs.tf
│   └── test/
│       └── vpc_test.go
```

### Example Directory Pattern

```hcl
# modules/vpc/examples/simple/main.tf
module "vpc" {
  source = "../../"

  name            = "example-vpc"
  cidr            = "10.0.0.0/16"
  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
}

output "vpc_id" {
  value = module.vpc.vpc_id
}
```

Test the example:
```bash
cd modules/vpc/examples/simple
terraform init
terraform plan
terraform apply
terraform destroy
```

## Debugging Workflows

### Terraform Console

```bash
# Start interactive console
terraform console

# Test expressions
> var.environment
"dev"

> local.tags
{
  "Environment" = "dev"
  "Project" = "example"
}

> cidrsubnet("10.0.0.0/16", 8, 1)
"10.0.1.0/24"

> [for az in var.azs : "${az}-subnet"]
["us-east-1a-subnet", "us-east-1b-subnet"]
```

### Debug Outputs

```hcl
# Temporary debug outputs (remove before commit)
output "debug_subnets" {
  value = {
    private = aws_subnet.private[*]
    public  = aws_subnet.public[*]
  }
  description = "DEBUG: Remove before merge"
}

output "debug_locals" {
  value       = local.computed_tags
  description = "DEBUG"
}
```

### TF_LOG Levels

```bash
# Minimal - errors only
export TF_LOG=ERROR

# Moderate - see operations
export TF_LOG=INFO

# Detailed - debug issues
export TF_LOG=DEBUG

# Full - protocol dumps
export TF_LOG=TRACE

# Log to file
export TF_LOG_PATH=terraform.log

# Provider-specific
export TF_LOG_PROVIDER=DEBUG
```

### Graph Visualization

```bash
# Generate dependency graph
terraform graph > graph.dot

# Convert to image (requires graphviz)
terraform graph | dot -Tpng > graph.png

# View specific plan
terraform graph -type=plan > plan.dot
```

### Plan Output Analysis

```bash
# Save plan for inspection
terraform plan -out=tfplan

# Show human-readable plan
terraform show tfplan

# Show as JSON for scripting
terraform show -json tfplan > plan.json

# Extract changes
jq '.resource_changes[] | select(.change.actions != ["no-op"])' plan.json
```

## Onboarding Guide

### New Developer Checklist

- [ ] Install required tools (tfenv, tflint, terraform-docs, pre-commit)
- [ ] Clone repository
- [ ] Set up cloud credentials (AWS CLI, GCP gcloud, Azure CLI)
- [ ] Install pre-commit hooks: `pre-commit install`
- [ ] Run first terraform init in a module
- [ ] Run terraform plan (read-only, safe)
- [ ] Review CONTRIBUTING.md and team conventions

### First Terraform Plan

```bash
# 1. Navigate to environment
cd environments/dev

# 2. Initialize (downloads providers, modules)
terraform init

# 3. Plan (read-only, shows what would change)
terraform plan

# 4. Review output carefully before any apply
```

### Common First-Time Errors

**Error: Provider not found**
```bash
# Solution: Run init
terraform init
```

**Error: Credentials not configured**
```bash
# AWS solution
aws configure
# or
export AWS_PROFILE=myprofile
```

**Error: State locked**
```bash
# Check if someone else is running terraform
# If stale, force unlock (get ID from error)
terraform force-unlock LOCK_ID
```

**Error: Version constraint**
```bash
# Install correct version
tfenv install 1.6.0
tfenv use 1.6.0
```

### Resource Links

- [Terraform Documentation](https://developer.hashicorp.com/terraform/docs)
- [OpenTofu Documentation](https://opentofu.org/docs/)
- [Terraform Registry](https://registry.terraform.io/)
- [tflint Rules](https://github.com/terraform-linters/tflint-ruleset-aws)
- [terraform-docs](https://terraform-docs.io/)

## DX Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| No version pinning | Inconsistent builds | Use .terraform-version |
| Skipping terraform init | Stale providers/modules | Run init after pulls |
| No pre-commit hooks | Inconsistent formatting | Configure pre-commit |
| Manual formatting | Time waste, conflicts | Auto-format on save |
| No local testing | Slow feedback | Test examples locally |
| Hardcoded paths | Works only on your machine | Use relative paths |
| No shell aliases | Repetitive typing | Set up aliases |
| Ignoring tflint | Miss best practices | Run tflint in CI and locally |
| No debug outputs | Blind debugging | Use terraform console |
| Giant commits | Hard to review | Small, focused changes |
