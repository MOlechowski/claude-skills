# CI/CD Patterns

## Contents
- [GitOps Workflow](#gitops-workflow) - PR flow, branch strategy
- [GitHub Actions](#github-actions) - Plan on PR, apply on merge
- [GitLab CI](#gitlab-ci) - Pipeline configuration
- [Azure DevOps](#azure-devops) - Pipeline YAML
- [Approval Gates](#approval-gates) - Environments, manual approval
- [Security Scanning](#security-scanning) - Checkov, tfsec, Trivy
- [Cost Estimation](#cost-estimation) - Infracost integration
- [Module Release Pipeline](#module-release-pipeline) - Validate, test, release
- [Pipeline Anti-patterns](#pipeline-anti-patterns) - Common mistakes

## GitOps Workflow

### Pull Request Flow

```
1. Developer creates feature branch
2. Push triggers terraform plan
3. Plan output posted as PR comment
4. Reviewer approves PR + plan
5. Merge triggers terraform apply
6. Apply output posted, PR auto-closes
```

### Branch Strategy

```
main (protected)
  │
  ├── feature/add-vpc    → auto-plan on push
  │     └── PR to main   → plan + review
  │           └── merge  → apply to staging
  │
  └── release/v1.2.0     → apply to prod (manual trigger)
```

## GitHub Actions

### Plan on PR

```yaml
name: Terraform Plan
on:
  pull_request:
    paths:
      - 'terraform/**'

jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.6.0

      - name: Terraform Init
        run: terraform init
        working-directory: terraform

      - name: Terraform Plan
        id: plan
        run: terraform plan -no-color -out=tfplan
        working-directory: terraform
        continue-on-error: true

      - name: Post Plan to PR
        uses: actions/github-script@v7
        with:
          script: |
            const output = `#### Terraform Plan 📖
            \`\`\`
            ${{ steps.plan.outputs.stdout }}
            \`\`\`
            `;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: output
            });

      - name: Fail on Plan Error
        if: steps.plan.outcome == 'failure'
        run: exit 1
```

### Apply on Merge

```yaml
name: Terraform Apply
on:
  push:
    branches: [main]
    paths:
      - 'terraform/**'

jobs:
  apply:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3

      - name: Terraform Init
        run: terraform init
        working-directory: terraform

      - name: Terraform Apply
        run: terraform apply -auto-approve
        working-directory: terraform
```

### Multi-Environment Matrix

```yaml
name: Deploy Environments
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [dev, staging]
      max-parallel: 1
    environment: ${{ matrix.environment }}
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3

      - name: Deploy to ${{ matrix.environment }}
        run: |
          terraform init
          terraform apply -auto-approve \
            -var-file=environments/${{ matrix.environment }}.tfvars
```

## GitLab CI

### Pipeline Configuration

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - plan
  - apply

variables:
  TF_ROOT: ${CI_PROJECT_DIR}/iac-terraform

.terraform:
  image: hashicorp/iac-terraform:1.6
  before_script:
    - cd ${TF_ROOT}
    - terraform init

validate:
  extends: .terraform
  stage: validate
  script:
    - terraform validate
    - terraform fmt -check

plan:
  extends: .terraform
  stage: plan
  script:
    - terraform plan -out=plan.tfplan
  artifacts:
    paths:
      - ${TF_ROOT}/plan.tfplan
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

apply:
  extends: .terraform
  stage: apply
  script:
    - terraform apply plan.tfplan
  dependencies:
    - plan
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
  environment:
    name: production
```

## Azure DevOps

### Pipeline YAML

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
  paths:
    include:
      - terraform/*

pool:
  vmImage: ubuntu-latest

stages:
  - stage: Plan
    jobs:
      - job: TerraformPlan
        steps:
          - task: TerraformInstaller@0
            inputs:
              terraformVersion: '1.6.0'

          - task: TerraformTaskV4@4
            displayName: 'Terraform Init'
            inputs:
              provider: 'azurerm'
              command: 'init'
              workingDirectory: '$(System.DefaultWorkingDirectory)/iac-terraform'
              backendServiceArm: 'Azure-Service-Connection'
              backendAzureRmResourceGroupName: 'terraform-state-rg'
              backendAzureRmStorageAccountName: 'tfstate12345'
              backendAzureRmContainerName: 'tfstate'
              backendAzureRmKey: 'terraform.tfstate'

          - task: TerraformTaskV4@4
            displayName: 'Terraform Plan'
            inputs:
              provider: 'azurerm'
              command: 'plan'
              workingDirectory: '$(System.DefaultWorkingDirectory)/iac-terraform'
              environmentServiceNameAzureRM: 'Azure-Service-Connection'
              commandOptions: '-out=tfplan'

          - publish: $(System.DefaultWorkingDirectory)/terraform/tfplan
            artifact: tfplan

  - stage: Apply
    dependsOn: Plan
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: TerraformApply
        environment: production
        strategy:
          runOnce:
            deploy:
              steps:
                - download: current
                  artifact: tfplan

                - task: TerraformTaskV4@4
                  displayName: 'Terraform Apply'
                  inputs:
                    provider: 'azurerm'
                    command: 'apply'
                    workingDirectory: '$(System.DefaultWorkingDirectory)/iac-terraform'
                    commandOptions: '$(Pipeline.Workspace)/tfplan/tfplan'
```

## Approval Gates

### GitHub Environments

```yaml
# In repository settings, create environment "production" with:
# - Required reviewers
# - Wait timer
# - Deployment branch rules

jobs:
  deploy:
    environment: production  # Requires approval
    steps:
      - run: terraform apply
```

### GitLab Manual Approval

```yaml
apply:prod:
  stage: apply
  script:
    - terraform apply -auto-approve
  when: manual  # Requires click
  allow_failure: false
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

## Security Scanning

### Checkov Integration

```yaml
- name: Run Checkov
  uses: bridgecrewio/checkov-action@master
  with:
    directory: terraform/
    framework: terraform
    output_format: sarif
    soft_fail: true
```

### tfsec Integration

```yaml
- name: Run tfsec
  uses: aquasecurity/tfsec-action@v1.0.0
  with:
    working_directory: terraform/
```

### Trivy Integration

```yaml
- name: Run Trivy
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'config'
    scan-ref: 'terraform/'
```

## Cost Estimation

### Infracost Integration

```yaml
- name: Setup Infracost
  uses: infracost/actions/setup@v2
  with:
    api-key: ${{ secrets.INFRACOST_API_KEY }}

- name: Generate Infracost JSON
  run: infracost breakdown --path terraform/ --format json --out-file /tmp/infracost.json

- name: Post Infracost comment
  uses: infracost/actions/comment@v1
  with:
    path: /tmp/infracost.json
    behavior: update
```

## Module Release Pipeline

```yaml
name: Release Module
on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate
        run: |
          terraform init -backend=false
          terraform validate
          terraform fmt -check

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          generate_release_notes: true
```

## Pipeline Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| Apply without plan | Unknown changes | Always plan first |
| Auto-apply to prod | No review | Require approval |
| No state locking | Concurrent runs | Enable backend locking |
| Secrets in logs | Credential exposure | Mask outputs |
| No artifact caching | Slow pipelines | Cache providers |
| Single pipeline all envs | Blast radius | Separate pipelines |
