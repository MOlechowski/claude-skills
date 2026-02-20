---
name: iac-opa
description: "Open Policy Agent CLI and Rego policy language. Use for: (1) evaluating Rego policies against data/input, (2) writing and testing Rego rules, (3) building and signing OPA bundles, (4) Kubernetes admission control with Gatekeeper, (5) Terraform plan validation, (6) CI/CD policy gates with conftest. Triggers: opa eval, opa test, rego, policy as code, open policy agent, gatekeeper, admission control, conftest."
---

# OPA (Open Policy Agent)

General-purpose policy engine using Rego for policy-as-code across infrastructure, Kubernetes, and applications.

## Quick Start

```bash
# Evaluate a query against data
opa eval -d policy.rego -i input.json "data.authz.allow"

# Run unit tests
opa test ./policies -v

# Check Rego syntax
opa check policy.rego

# Format Rego files
opa fmt -w policy.rego

# Start interactive REPL
opa run
```

## CLI Reference

### Evaluate Policies

```bash
opa eval "1 + 1"                                          # Simple expression
opa eval -d policy.rego "data.example.allow"               # Query policy
opa eval -d policy.rego -i input.json "data.authz.allow"   # With input
opa eval -d policy/ -i input.json "data.authz"             # Policy directory
opa eval -b ./bundle "data.authz.allow"                    # From bundle
opa eval --format pretty -d policy.rego "data.example"     # Pretty output
opa eval --format raw -d policy.rego "data.example.msg"    # Raw string
opa eval --fail -d policy.rego "data.example.allow"        # Exit 1 if undefined/false
opa eval --fail-defined -d policy.rego "data.example.deny" # Exit 1 if defined
opa eval --partial -d policy.rego "data.authz.allow"       # Partial evaluation
opa eval --profile -d policy.rego "data.authz.allow"       # With profiling
```

### Test Policies

```bash
opa test ./policies                    # Run all tests in directory
opa test ./policies -v                 # Verbose output
opa test ./policies -r "test_admin"    # Run matching tests
opa test ./policies --coverage         # Show coverage
opa test ./policies --format json      # JSON output
opa test ./policies --bench            # Benchmark tests
opa test ./policies -b ./bundle        # Test with bundle data
```

### Check and Format

```bash
opa check policy.rego                  # Check syntax
opa check policy.rego --strict         # Strict mode (future compat)
opa check ./policies/                  # Check directory
opa fmt policy.rego                    # Print formatted to stdout
opa fmt -w policy.rego                 # Write formatted in place
opa fmt -d policy.rego                 # Show diff
opa fmt -l policy.rego                 # List files that differ
```

### Build Bundles

```bash
opa build ./policies                                       # Build bundle from directory
opa build ./policies -o bundle.tar.gz                      # Specify output
opa build ./policies -e "authz/allow"                      # Set entrypoint (optimized)
opa build ./policies -e "authz/allow" --optimize 1         # Partial eval optimization
opa build ./policies -e "authz/allow" --optimize 2         # Full optimization
opa build --revision "v1.2.3" ./policies                   # Set revision
```

### Run Server / REPL

```bash
opa run                                        # Interactive REPL
opa run policy.rego                            # REPL with policy loaded
opa run -s                                     # Start OPA server on :8181
opa run -s -a :8080                            # Custom address
opa run -s ./policies/                         # Server with policies
opa run -s -b ./bundle.tar.gz                  # Server with bundle
opa run -s --set decision_logs.console=true    # Enable decision logging
```

### Inspect and Debug

```bash
opa inspect ./bundle.tar.gz                                    # Inspect bundle contents
opa inspect ./policies/                                        # Inspect policy directory
opa deps -d policy.rego "data.authz.allow"                     # Query dependencies
opa bench -d policy.rego -i input.json "data.authz.allow"      # Benchmark
opa capabilities --current                                     # Print current capabilities
opa version                                                    # Print OPA version
```

## Rego Language

### Basic Rules

```rego
package authz

import rego.v1

# Complete rule (returns true/false)
default allow := false

allow if {
    input.user == "admin"
}

# Partial rules (set of values)
violations contains msg if {
    not input.user
    msg := "user is required"
}

# Rule with value assignment
role := "admin" if input.user == "root"
role := "viewer" if input.user != "root"
```

### Data Types and Operations

```rego
# Strings
contains(input.path, "/admin")
startswith(input.path, "/api")
sprintf("user: %s", [input.user])
lower(input.method)

# Numbers / comparison
input.age >= 18

# Objects
input.metadata.labels["app"]
object.get(input, ["metadata", "name"], "default")

# Arrays
count(input.items) > 0
input.items[0]
array.concat(a, b)

# Sets
s := {x | x := input.items[_]}
```

### Comprehensions

```rego
# Array comprehension
names := [name | name := input.users[_].name]

# Set comprehension
unique_roles := {role | role := input.users[_].role}

# Object comprehension
user_roles := {name: role |
    some user in input.users
    name := user.name
    role := user.role
}
```

### Functions

```rego
# Custom function
is_admin(user) if {
    user.role == "admin"
}

# Function with return value
full_name(user) := name if {
    name := sprintf("%s %s", [user.first, user.last])
}
```

### Iteration and Some

```rego
# Iterate with some
allow if {
    some role in input.user.roles
    role == "admin"
}

# Iterate with index
allow if {
    some i, val in input.items
    val.type == "approved"
}

# Every keyword (universal quantification)
all_approved if {
    every item in input.items {
        item.status == "approved"
    }
}
```

### Negation and Default

```rego
default allow := false

# Negation
deny if {
    not is_admin(input.user)
}

# Not with helper rule
is_admin(user) if user.role == "admin"
```

### With Keyword (Mocking)

```rego
# Override input in tests
test_allow_admin if {
    allow with input as {"user": "admin", "role": "admin"}
}

# Override data
test_with_custom_roles if {
    allow with input as {"user": "alice"}
          with data.roles as {"alice": "admin"}
}
```

## Policy Patterns

### Kubernetes Admission Control

```rego
package kubernetes.admission

import rego.v1

# Deny containers without resource limits
deny contains msg if {
    some container in input.request.object.spec.containers
    not container.resources.limits
    msg := sprintf("container '%s' missing resource limits", [container.name])
}

# Deny privileged containers
deny contains msg if {
    some container in input.request.object.spec.containers
    container.securityContext.privileged
    msg := sprintf("container '%s' cannot be privileged", [container.name])
}

# Require specific labels
deny contains msg if {
    not input.request.object.metadata.labels["app"]
    msg := "missing required label 'app'"
}
```

### Terraform Plan Validation

```rego
package terraform.analysis

import rego.v1

# Parse terraform plan JSON (from: terraform show -json plan.tfplan)

# Deny public S3 buckets
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read"
    msg := sprintf("S3 bucket '%s' must not be public", [resource.address])
}

# Require encryption on RDS
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_db_instance"
    not resource.change.after.storage_encrypted
    msg := sprintf("RDS '%s' must have encryption enabled", [resource.address])
}

# Enforce tagging
deny contains msg if {
    some resource in input.resource_changes
    resource.change.actions[_] == "create"
    not resource.change.after.tags.Environment
    msg := sprintf("resource '%s' missing Environment tag", [resource.address])
}
```

### API Authorization

```rego
package httpapi.authz

import rego.v1

default allow := false

allow if {
    input.method == "GET"
    input.path == ["health"]
}

allow if {
    input.method == "GET"
    input.path[0] == "api"
    token.payload.role == "viewer"
}

allow if {
    input.method in {"POST", "PUT", "DELETE"}
    input.path[0] == "api"
    token.payload.role == "admin"
}

token := {"payload": payload} if {
    [_, payload, _] := io.jwt.decode(input.token)
}
```

### CI/CD Policy Gates (Conftest)

```bash
# Conftest wraps OPA for CI/CD policy testing

# Test Kubernetes manifests
conftest test deployment.yaml -p ./policies

# Test Dockerfile
conftest test Dockerfile -p ./policies

# Test Terraform plan
terraform show -json plan.tfplan | conftest test - -p ./policies

# Multiple inputs
conftest test *.yaml -p ./policies --all-namespaces

# Output formats
conftest test deployment.yaml -p ./policies -o json
conftest test deployment.yaml -p ./policies -o tap
```

## Bundle Management

```bash
# Build optimized bundle with entrypoints
opa build ./policies \
  -e "authz/allow" \
  -e "authz/deny" \
  --optimize 1 \
  -o bundle.tar.gz

# Sign bundle
opa sign ./bundle.tar.gz \
  --signing-key key.pem \
  --signing-algorithm RS256

# Inspect bundle metadata
opa inspect ./bundle.tar.gz
```

Bundle directory structure:

```
bundle/
├── data.json           # Static data
├── policy.rego         # Policy files
└── .manifest           # Bundle metadata
```

## Output Formats

```bash
opa eval -d policy.rego "data.example" --format json       # JSON (default)
opa eval -d policy.rego "data.example" --format pretty     # Human-readable values
opa eval -d policy.rego "data.example.msg" --format raw    # Raw string
opa eval -d policy.rego "x := data.users[_]" --format bindings  # Variable assignments
opa eval -d policy.rego "data.example" --format source     # Compiled Rego
```

## Configuration

OPA server configuration file (for `opa run -s -c config.yaml`):

```yaml
services:
  bundle_service:
    url: https://example.com
    credentials:
      bearer:
        token: "${BUNDLE_TOKEN}"

bundles:
  authz:
    service: bundle_service
    resource: /bundles/authz/bundle.tar.gz
    polling:
      min_delay_seconds: 10
      max_delay_seconds: 30

decision_logs:
  console: true

status:
  console: true
```

## CI Integration

### GitHub Actions

```yaml
- name: OPA Policy Check
  run: |
    opa eval --fail \
      -d ./policies \
      -i input.json \
      "data.compliance.allow"

- name: Run OPA Tests
  run: |
    opa test ./policies -v --coverage

- name: Conftest Terraform
  run: |
    terraform show -json plan.tfplan > plan.json
    conftest test plan.json -p ./policies --no-color
```

### Exit Codes

```bash
# --fail: exit 1 if result is undefined or empty
opa eval --fail -d policy.rego "data.authz.allow"

# --fail-defined: exit 1 if result is defined and non-empty
opa eval --fail-defined -d policy.rego "data.authz.deny"

# Test exit codes
opa test ./policies    # exit 1 if any test fails
```

## Common Patterns

```bash
# Validate Terraform plan against policies
terraform show -json plan.tfplan | \
  opa eval -d ./policies -i /dev/stdin --fail "data.terraform.deny[x]"

# Test all policies with coverage threshold
opa test ./policies -v --coverage --threshold 80

# Build and serve bundle locally
opa build ./policies -o bundle.tar.gz && \
  opa run -s -b bundle.tar.gz

# Evaluate with external data
opa eval -d policy.rego \
  -d data.json \
  -i input.json \
  "data.authz.allow"

# Debug: profile query performance
opa eval -d policy.rego -i input.json \
  --format pretty \
  --profile \
  "data.authz"
```

## Integration

- For Terraform infrastructure validation, use `/terraform` or `/tofu`
- For Kubernetes security scanning, use `/trivy`
- For infrastructure architecture decisions, use `/platform-architect`
- For code-level static analysis, use `/semgrep`
