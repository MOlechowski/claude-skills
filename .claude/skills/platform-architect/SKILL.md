---
name: platform-architect
description: "Infrastructure as Code architecture expertise: tool selection (Terraform, OpenTofu, Pulumi, CDK), module design, state management, multi-environment patterns, CI/CD pipelines, security (policy-as-code, secrets, compliance), testing strategies, cost optimization, platform engineering. Use for: architecture decisions, IAC tool selection, module composition, state strategies, enterprise patterns, migration planning. Triggers: iac architecture, infrastructure design, which iac tool, terraform vs pulumi, module structure, state management, platform engineering, iac patterns."
---

# Platform Architect

Strategic IAC architecture guidance. Handles design decisions; delegates operational tasks to tool-specific skills.

## Role and Orchestration

**This skill provides:** Architecture decisions, tool selection, design patterns, anti-pattern detection.

**Delegate to other skills:**
- `terraform` - Terraform CLI operations, HCL syntax, state commands
- `tofu` - OpenTofu CLI operations, HCL syntax, state commands
- `aws-expert` - AWS service selection, Well-Architected patterns
- `cloudflare-expert` - Cloudflare architecture, Zero Trust, Workers

**Adaptive expertise:** Match depth to project signals. Simple questions get concise answers. Complex architecture gets detailed analysis with trade-offs.

## Tool Selection Framework

### Decision Matrix

| Factor | Terraform | OpenTofu | Pulumi | CDK | CloudFormation |
|--------|-----------|----------|--------|-----|----------------|
| **License** | BSL 1.1 | MPL 2.0 | Apache 2.0 | Apache 2.0 | Proprietary |
| **Language** | HCL | HCL | TS/Py/Go/C# | TS/Py/Go/C# | YAML/JSON |
| **State** | Remote/local | Remote/local | Managed/self | CloudFormation | CloudFormation |
| **Provider ecosystem** | Largest | Same as TF | Growing | AWS-focused | AWS only |
| **Learning curve** | Medium | Medium | Higher | Higher | Lower |
| **Enterprise features** | Paid | Community | Paid | Free | Free |
| **Multi-cloud** | Native | Native | Native | Limited | No |

### Selection Guide

**Choose Terraform when:**
- Team knows HCL, existing TF codebase
- Need largest provider ecosystem
- Enterprise support required (Terraform Cloud/Enterprise)

**Choose OpenTofu when:**
- Want open-source (MPL 2.0)
- Same HCL, same providers, community-driven
- Avoiding HashiCorp licensing

**Choose Pulumi when:**
- Team prefers general-purpose languages
- Complex logic (loops, conditionals) needed
- Type safety important

**Choose CDK when:**
- AWS-only or AWS-primary
- Existing TypeScript/Python teams
- Want L2/L3 construct abstractions

**Choose CloudFormation when:**
- AWS-only, minimal tooling
- Compliance requires AWS-native
- Simple infrastructure

### Migration Paths

| From | To | Complexity | Approach |
|------|-----|------------|----------|
| CloudFormation | CDK | Low | `cdk migrate` or import |
| CloudFormation | Terraform | Medium | Import with `terraform import` |
| Terraform | OpenTofu | Low | Drop-in replacement |
| Terraform | Pulumi | Medium | `pulumi convert` or rewrite |

## Architecture Patterns

### Module Composition

**Principles:**
1. Single responsibility - one logical resource group per module
2. Explicit inputs/outputs - no hidden dependencies
3. Versioned releases - semantic versioning for breaking changes
4. Environment-agnostic - configuration via variables

**Module types:**
- **Resource modules** - Single cloud resource (VPC, RDS)
- **Pattern modules** - Opinionated combinations (3-tier app)
- **Root modules** - Environment instantiation

**Composition example:**
```
root/
├── main.tf          # Calls pattern modules
├── environments/
│   ├── dev.tfvars
│   ├── staging.tfvars
│   └── prod.tfvars
└── modules/
    ├── networking/  # Pattern: VPC + subnets + NAT
    ├── compute/     # Pattern: ASG + ALB + security groups
    └── database/    # Pattern: RDS + replica + backups
```

See [references/module-patterns.md](references/module-patterns.md) for detailed patterns.

### State Management

**Remote state backends:**
| Backend | Use case |
|---------|----------|
| S3 + DynamoDB | AWS, locking via DynamoDB |
| GCS | GCP, built-in locking |
| Azure Blob | Azure, built-in locking |
| Terraform Cloud | Managed, collaboration features |
| PostgreSQL | Self-hosted, existing DB infra |

**State isolation strategies:**
- **Workspace-based** - Same backend, different workspaces
- **Directory-based** - Separate state files per environment
- **Account-based** - Separate cloud accounts, separate state

See [references/state-management.md](references/state-management.md) for state surgery and recovery.

### Environment Patterns

| Pattern | Pros | Cons | Best for |
|---------|------|------|----------|
| **Directory-based** | Clear separation, different configs | Duplication | Divergent environments |
| **Workspace-based** | DRY, single codebase | Shared state backend | Similar environments |
| **Branch-based** | GitOps native | Merge complexity | Feature environments |

See [references/environments.md](references/environments.md) for promotion strategies.

## Anti-Pattern Quick Reference

### Top 10 Mistakes

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| Hardcoded values | No reuse, env drift | Use variables + tfvars |
| Monolithic state | Blast radius, slow plans | Split by domain/lifecycle |
| No remote state | Team conflicts, lost state | Use remote backend + locking |
| Copy-paste modules | Drift, maintenance burden | Publish versioned modules |
| Secrets in state | Security exposure | Use Vault/Secrets Manager |
| No `terraform plan` review | Unexpected changes | Plan in PR, review diffs |
| Giant modules | Hard to test, slow | Single responsibility |
| No versioning | Breaking changes surprise | Semantic versioning |
| Manual changes | Drift from code | Import or recreate |
| No tagging | Cost attribution fails | Enforce via policy |

### Security Red Flags

- `0.0.0.0/0` ingress rules without justification
- Wildcard IAM permissions (`*`)
- Secrets in `.tf` files or state (unencrypted)
- Public S3 buckets without explicit need
- No encryption at rest/transit

### Scale Blockers

- Single state file for entire org
- No module versioning in monorepo
- Inline provider configs (not reusable)
- No CI/CD automation (manual applies)

## Scaffolding

### Generate Module

```bash
python3 ~/.claude/skills/platform-architect/scripts/scaffold_module.py \
  --name networking \
  --type enterprise \
  --output ./modules/networking
```

Options:
- `--type basic` - Minimal: main.tf, variables.tf, outputs.tf
- `--type enterprise` - Full: + tests/, examples/, versions.tf, README.md

### Generate Project

```bash
python3 ~/.claude/skills/platform-architect/scripts/scaffold_project.py \
  --name my-platform \
  --layout monorepo \
  --environments dev,staging,prod \
  --output ./my-platform
```

Options:
- `--layout monorepo` - Single repo, environments/ and modules/
- `--layout polyrepo` - Per-component structure

### Analyze Existing IAC

```bash
python3 ~/.claude/skills/platform-architect/scripts/analyze_iac.py ./terraform
```

Reports: structure, module usage, state config, improvement suggestions.

### Detect Anti-patterns

```bash
python3 ~/.claude/skills/platform-architect/scripts/detect_antipatterns.py ./terraform
```

Checks: hardcoded values, secrets, oversized modules, missing versioning.

## Reference Navigation

**Read based on need:**

| Topic | Reference File |
|-------|---------------|
| Module design, versioning, registries | [module-patterns.md](references/module-patterns.md) |
| Remote backends, locking, state surgery | [state-management.md](references/state-management.md) |
| Dev/staging/prod, promotion, drift | [environments.md](references/environments.md) |
| GitOps, pipelines, approval gates | [cicd-patterns.md](references/cicd-patterns.md) |
| Policy-as-code, secrets, compliance | [security.md](references/security.md) |
| Unit, integration, contract, e2e | [testing.md](references/testing.md) |
| Infracost, tagging, right-sizing | [cost-optimization.md](references/cost-optimization.md) |
| terraform-docs, diagrams, ADRs | [documentation.md](references/documentation.md) |
| Platform engineering, governance, teams | [enterprise.md](references/enterprise.md) |
| Import, tool-to-tool, modernization | [migration.md](references/migration.md) |
| State backup, multi-region, failover | [disaster-recovery.md](references/disaster-recovery.md) |
| Common errors, drift, performance | [troubleshooting.md](references/troubleshooting.md) |

## Template Assets

Pre-built templates in `assets/`:

- `module-templates/basic/` - Minimal module structure
- `module-templates/enterprise/` - Full module with tests
- `project-layouts/monorepo/` - Multi-environment single repo
- `project-layouts/polyrepo/` - Component-per-repo structure
- `cicd-templates/github-actions/` - GHA workflows
- `cicd-templates/gitlab-ci/` - GitLab CI templates
- `cicd-templates/azure-devops/` - ADO pipelines
