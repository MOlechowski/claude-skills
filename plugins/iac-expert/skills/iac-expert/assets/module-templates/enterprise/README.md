# {{ name }} Module

## Description

This module manages {{ description }}.

## Usage

```hcl
module "{{ name }}" {
  source  = "git::https://github.com/org/modules.git//{{ name }}?ref=v1.0.0"

  name        = "my-resource"
  environment = "prod"

  tags = {
    Owner = "platform-team"
  }
}
```

## Examples

- [Basic](examples/basic) - Minimal configuration
- [Complete](examples/complete) - Full configuration with all options

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| aws | >= 5.0 |

## Providers

| Name | Version |
|------|---------|
| aws | >= 5.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| name | Name prefix for all resources | `string` | n/a | yes |
| environment | Environment name | `string` | n/a | yes |
| tags | Additional tags | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| (define outputs) | |

<!-- BEGIN_TF_DOCS -->
<!-- END_TF_DOCS -->

## Testing

```bash
cd tests
go test -v -timeout 30m
```

## License

MIT
