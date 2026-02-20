# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Migrated to plugin marketplace architecture** — each of 94 skills is now an individual plugin in `plugins/<name>/` with its own `.claude-plugin/plugin.json`. Users install the marketplace once (`/plugin install`) then enable/disable individual skills. This replaces the flat `.claude/skills/` directory and `install.sh` that loaded all skills globally.
- **Standardized all 93 skill names with domain prefixes** — 66 skills renamed across 14 namespaces (`aws-`, `cf-`, `cli-`, `dev-`, `doc-`, `git-`, `go-`, `iac-`, `net-`, `oci-`, `re-`, `res-`, `sec-`, `speckit-`). Key renames include:
  - Git workflow: `commit` → `git-commit`, `commit-pr` → `git-land`, `commit-pr-ci-merge` → `git-ship`
  - Cloudflare: `cloudflared` → `cf-tunnel`, `flarectl` → `cf-ctl`, `wrangler` → `cf-wrangler`
  - Go: `go-golangci-lint` → `go-lint`, `go-goreleaser` → `go-release`, `go-lang-expert` → `go-expert`
  - AWS: `localstack` → `aws-localstack`, `awslocal` → `aws-local`
  - IaC: `platform-architect` → `iac-expert`, `terraform` → `iac-terraform`
  - Security: `bandit` → `sec-bandit`, `trivy` → `sec-trivy`, etc.
  - All cross-references between skills updated (71+ integration points)

### Added
- **hcloud skill** - Hetzner Cloud CLI for infrastructure management
  - Server lifecycle (create, resize, rebuild, snapshots, backups)
  - Networking (VPCs, firewalls, floating IPs, load balancers)
  - Storage (volumes), images, SSH keys
  - Multi-project context management
  - Quick reference for all resource commands
- **opa skill** - Open Policy Agent CLI and Rego policy language
  - CLI reference (eval, test, check, fmt, build, run, inspect)
  - Rego language syntax (rules, comprehensions, functions, iteration, mocking)
  - Policy patterns (Kubernetes admission, Terraform validation, API authz, CI/CD gates)
  - Bundle management, output formats, configuration
  - CI integration with GitHub Actions and conftest
- **aws-cli skill** - AWS CLI v2 expertise for command-line operations
  - Authentication methods (IAM, SSO, roles, profiles, environment variables)
  - Output formatting with JMESPath queries and jq integration
  - 20+ AWS service command references (EC2, S3, Lambda, ECS, RDS, DynamoDB, etc.)
  - Multi-account patterns and cross-account role assumption
  - CI/CD integration (GitHub Actions, GitLab CI with OIDC federation)
  - Local development tools (LocalStack, SAM CLI, CDK CLI)
  - Debugging and troubleshooting patterns
  - Quick reference cheatsheet and scripting examples
- **aws-expert skill** - AWS architecture expertise following Well-Architected Framework
  - Six pillars deep dive (Operational Excellence, Security, Reliability, Performance, Cost, Sustainability)
  - Comprehensive service selection matrices (Compute, Database, Storage, Messaging)
  - Architecture patterns (Serverless, Containers, Event-Driven, Data Lakes, Multi-Region)
  - Security patterns (IAM best practices, encryption, network security, compliance)
  - Cost optimization strategies (Savings Plans, Reserved Instances, Spot, right-sizing)
  - DR/HA patterns (Multi-AZ, multi-region, RTO/RPO planning)
  - IaC recommendations (CloudFormation vs CDK vs Terraform comparison)
- Initial repository setup following Anthropic's Skills framework
- Installation script for copying skills to `~/.claude/skills/`
- README with skills documentation and guidelines
- CLAUDE.md with repository guidance
- Directory structure for skill organization
- Template skill structure in `.claude/skills/`
- **fastmod skill** - Comprehensive expertise for large-scale codebase refactoring
  - Main SKILL.md with Rust regex syntax guidance
  - quick-reference.md for command lookup
  - examples.md with real-world refactoring patterns
- **Tier 1 Essential Skills** - Five foundational command-line tools
  - **jq skill** - JSON query language for data processing
    - Complete jq syntax reference with filters, operators, and functions
    - Real-world workflows for API processing, log analysis, config management
    - Advanced techniques: recursive descent, custom functions, reduce
  - **ripgrep skill** - High-performance code search tool
    - Type filtering, glob patterns, and advanced regex
    - Security auditing patterns and performance analysis
    - Integration with git, docker, kubernetes workflows
  - **ast-grep skill** - Semantic code search and transformation
    - AST-based pattern matching with metavariables
    - React, TypeScript, Python, Rust, Go patterns
    - Error handling, security, and refactoring patterns
  - **yq skill** - YAML/JSON/XML processor with jq-like syntax
    - Multi-format support (YAML, JSON, XML, CSV, TOML)
    - Kubernetes, Docker Compose, CI/CD configuration management
    - Format conversions and complex merging strategies
  - **fzf skill** - Interactive command-line fuzzy finder
    - Custom key bindings and preview windows
    - Git integration (branches, commits, files)
    - Docker/Kubernetes workflows and system administration
- **parallel skill** - GNU parallel shell tool for executing jobs in parallel
  - Input sources (arguments, files, stdin, cartesian products)
  - Replacement strings ({}, {.}, {/}, {//}, {/.}, {#}, {%})
  - Job control, progress tracking, and job logging
  - Remote execution via SSH
  - Error handling with halt conditions and retry logic
- **parallel-flow skill** - Autonomous parallelization of tasks
  - Analyzes tasks and identifies parallelizable units
  - Partitions work across Claude agents or shell commands
  - Decision matrix for agent vs shell parallelism
  - Result aggregation and error handling patterns

[Unreleased]: https://github.com/MOlechowski/claude-skills/commits/master
