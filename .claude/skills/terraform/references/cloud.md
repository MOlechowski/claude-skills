# Terraform Cloud/Enterprise

Terraform Cloud and HCP Terraform provide managed infrastructure automation.

## Login and Setup

```bash
# Login to Terraform Cloud
terraform login

# Login to Enterprise
terraform login app.terraform.example.com
```

## Cloud Backend Configuration

```hcl
terraform {
  cloud {
    organization = "my-org"

    workspaces {
      name = "my-workspace"
    }
  }
}

# Or with tags for multiple workspaces
terraform {
  cloud {
    organization = "my-org"

    workspaces {
      tags = ["app:web", "env:production"]
    }
  }
}
```

## Remote Execution

```bash
# Runs execute in Terraform Cloud
terraform plan   # Plan runs remotely
terraform apply  # Apply runs remotely

# Local planning with remote state
terraform plan -target=aws_instance.web
```

## Sentinel Policy (Enterprise)

```hcl
# Sentinel policy example - enforce tagging
import "tfplan/v2" as tfplan

required_tags = ["Environment", "Owner", "Project"]

main = rule {
  all tfplan.resources as _, r {
    all r.changes as _, c {
      all required_tags as tag {
        c.after.tags contains tag
      }
    }
  }
}
```

## Terraform Cloud vs Self-Managed

| Factor | Terraform Cloud | Self-Managed |
|--------|-----------------|--------------|
| State management | Automatic | Configure backend |
| Remote execution | Built-in | CI/CD pipeline |
| Policy enforcement | Sentinel | External tools |
| Cost estimation | Built-in | Manual |
| Team collaboration | Built-in | Git + reviews |
