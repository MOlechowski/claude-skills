# Testing Strategies

## Contents
- [Testing Pyramid](#testing-pyramid) - Overview of test levels
- [Unit Testing](#unit-testing) - Validate, format, tflint, terraform-compliance
- [Integration Testing](#integration-testing) - Terratest, Kitchen-Terraform
- [Contract Testing](#contract-testing) - Output validation, module contracts
- [End-to-End Testing](#end-to-end-testing) - Full stack deployment
- [Ephemeral Environments](#ephemeral-environments) - Test fixtures, parallel isolation
- [Test Organization](#test-organization) - Directory structure, Makefile
- [CI/CD Integration](#cicd-integration) - GitHub Actions workflow
- [Testing Anti-patterns](#testing-anti-patterns) - Common mistakes

## Testing Pyramid

```
        /\
       /  \  E2E Tests
      /----\  (Full stack)
     /      \
    /--------\  Integration Tests
   /          \  (Real resources)
  /------------\
 /              \  Unit Tests
/----------------\  (Static analysis, mocks)
```

## Unit Testing

### Terraform Validate

```bash
terraform init -backend=false
terraform validate
```

### Terraform Format Check

```bash
terraform fmt -check -recursive
```

### tflint

```bash
# Install
brew install tflint

# Run
tflint --init
tflint --recursive
```

`.tflint.hcl`:
```hcl
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
```

### terraform-compliance

```gherkin
# features/tags.feature
Feature: Tags are required
  Scenario: Ensure all resources have tags
    Given I have resource that supports tags defined
    Then it must contain tags
    And its value must not be null
```

```bash
terraform plan -out=plan.out
terraform show -json plan.out > plan.json
terraform-compliance -p plan.json -f features/
```

## Integration Testing

### Terratest

```go
// test/vpc_test.go
package test

import (
    "testing"
    "github.com/gruntwork-io/terratest/modules/iac-terraform"
    "github.com/gruntwork-io/terratest/modules/aws"
    "github.com/stretchr/testify/assert"
)

func TestVpcCreation(t *testing.T) {
    t.Parallel()

    awsRegion := "us-east-1"

    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../modules/vpc",
        Vars: map[string]interface{}{
            "name": "test-vpc",
            "cidr": "10.0.0.0/16",
            "azs":  []string{"us-east-1a", "us-east-1b"},
        },
        EnvVars: map[string]string{
            "AWS_DEFAULT_REGION": awsRegion,
        },
    })

    defer terraform.Destroy(t, terraformOptions)

    terraform.InitAndApply(t, terraformOptions)

    vpcId := terraform.Output(t, terraformOptions, "vpc_id")
    assert.NotEmpty(t, vpcId)

    // Verify VPC exists in AWS
    vpc := aws.GetVpcById(t, vpcId, awsRegion)
    assert.Equal(t, "10.0.0.0/16", *vpc.CidrBlock)
}

func TestVpcWithSubnets(t *testing.T) {
    t.Parallel()

    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../modules/vpc",
        Vars: map[string]interface{}{
            "name":            "test-vpc",
            "cidr":            "10.0.0.0/16",
            "private_subnets": []string{"10.0.1.0/24", "10.0.2.0/24"},
            "public_subnets":  []string{"10.0.101.0/24", "10.0.102.0/24"},
        },
    })

    defer terraform.Destroy(t, terraformOptions)

    terraform.InitAndApply(t, terraformOptions)

    privateSubnetIds := terraform.OutputList(t, terraformOptions, "private_subnet_ids")
    publicSubnetIds := terraform.OutputList(t, terraformOptions, "public_subnet_ids")

    assert.Len(t, privateSubnetIds, 2)
    assert.Len(t, publicSubnetIds, 2)
}
```

### Kitchen-Terraform

```yaml
# kitchen.yml
driver:
  name: terraform
  root_module_directory: test/fixtures/default

provisioner:
  name: terraform

verifier:
  name: terraform
  systems:
    - name: default
      backend: aws
      controls:
        - vpc
        - subnets

platforms:
  - name: terraform

suites:
  - name: default
```

```ruby
# test/integration/default/controls/vpc.rb
control 'vpc' do
  describe aws_vpc(attribute('vpc_id')) do
    it { should exist }
    its('cidr_block') { should eq '10.0.0.0/16' }
    it { should be_available }
  end
end
```

## Contract Testing

### Output Validation

```hcl
# modules/vpc/outputs.tf
output "vpc_id" {
  description = "The VPC ID"
  value       = aws_vpc.main.id

  precondition {
    condition     = can(regex("^vpc-", aws_vpc.main.id))
    error_message = "VPC ID must start with 'vpc-'"
  }
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id

  precondition {
    condition     = length(aws_subnet.private) >= 2
    error_message = "At least 2 private subnets required"
  }
}
```

### Module Contract Test

```go
func TestModuleOutputContract(t *testing.T) {
    terraformOptions := &terraform.Options{
        TerraformDir: "../modules/vpc",
        Vars: map[string]interface{}{
            "name": "contract-test",
            "cidr": "10.0.0.0/16",
        },
    }

    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)

    // Validate output types and structure
    vpcId := terraform.Output(t, terraformOptions, "vpc_id")
    assert.Regexp(t, "^vpc-", vpcId)

    privateSubnets := terraform.OutputList(t, terraformOptions, "private_subnet_ids")
    assert.GreaterOrEqual(t, len(privateSubnets), 2)

    // Validate all subnet IDs are valid
    for _, subnet := range privateSubnets {
        assert.Regexp(t, "^subnet-", subnet)
    }
}
```

## End-to-End Testing

### Full Stack Test

```go
func TestFullStackDeployment(t *testing.T) {
    t.Parallel()

    // Deploy networking
    networkingOptions := &terraform.Options{
        TerraformDir: "../infrastructure/networking",
    }
    defer terraform.Destroy(t, networkingOptions)
    terraform.InitAndApply(t, networkingOptions)

    vpcId := terraform.Output(t, networkingOptions, "vpc_id")
    subnetIds := terraform.OutputList(t, networkingOptions, "private_subnet_ids")

    // Deploy compute using networking outputs
    computeOptions := &terraform.Options{
        TerraformDir: "../infrastructure/compute",
        Vars: map[string]interface{}{
            "vpc_id":     vpcId,
            "subnet_ids": subnetIds,
        },
    }
    defer terraform.Destroy(t, computeOptions)
    terraform.InitAndApply(t, computeOptions)

    // Verify application is accessible
    albDns := terraform.Output(t, computeOptions, "alb_dns_name")
    http_helper.HttpGetWithRetry(t, fmt.Sprintf("http://%s/health", albDns), nil, 200, "OK", 30, 10*time.Second)
}
```

## Ephemeral Environments

### Test Fixtures

```hcl
# test/fixtures/default/main.tf
module "vpc" {
  source = "../../../modules/vpc"

  name            = "test-${random_id.suffix.hex}"
  cidr            = "10.0.0.0/16"
  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
}

resource "random_id" "suffix" {
  byte_length = 4
}
```

### Parallel Test Isolation

```go
func TestVpcInParallel(t *testing.T) {
    t.Parallel()

    uniqueId := random.UniqueId()

    terraformOptions := &terraform.Options{
        TerraformDir: "../modules/vpc",
        Vars: map[string]interface{}{
            "name": fmt.Sprintf("test-%s", uniqueId),
        },
    }

    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
}
```

## Test Organization

### Directory Structure

```
modules/
├── vpc/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── test/
│       ├── fixtures/
│       │   └── default/
│       │       ├── main.tf
│       │       └── outputs.tf
│       └── vpc_test.go
```

### Makefile for Tests

```makefile
.PHONY: test test-unit test-integration

test: test-unit test-integration

test-unit:
	terraform fmt -check -recursive
	terraform validate
	tflint --recursive

test-integration:
	cd test && go test -v -timeout 30m ./...

test-fast:
	cd test && go test -v -short ./...
```

## CI/CD Integration

```yaml
name: Test
on: [pull_request]

jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform fmt -check -recursive
      - run: terraform init -backend=false
      - run: terraform validate

  integration:
    runs-on: ubuntu-latest
    needs: unit
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - name: Run Terratest
        run: |
          cd test
          go test -v -timeout 30m ./...
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

## Testing Anti-patterns

| Anti-pattern | Problem | Fix |
|--------------|---------|-----|
| No cleanup | Resource leaks | Always defer destroy |
| Shared state | Test interference | Unique names per test |
| Long timeouts | Slow feedback | Parallelize tests |
| No retry logic | Flaky tests | Use WithRetry helpers |
| Testing in prod | Risk | Dedicated test account |
| Testing everything | Slow | Prioritize critical paths |
