# Cloudflare OpenTofu/Terraform Provider

## Provider Setup

### Provider v5 (Current)

```hcl
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
```

### Authentication

```hcl
# API Token (recommended)
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# Or via environment variable
# export CLOUDFLARE_API_TOKEN="your-token"
```

**Create API Token:**
1. Cloudflare Dashboard → My Profile → API Tokens
2. Create Token → Custom Token
3. Permissions: Zone:Read, Zone:Edit, DNS:Edit, etc.
4. Zone Resources: Include specific zones

## v4 to v5 Migration

Provider v5 has breaking changes (auto-generated from OpenAPI):

| v4 Resource | v5 Resource |
|-------------|-------------|
| `cloudflare_record` | `cloudflare_dns_record` |
| `cloudflare_rate_limit` | `cloudflare_ruleset` |
| `cloudflare_access_application` | `cloudflare_zero_trust_access_application` |
| `cloudflare_tunnel` | `cloudflare_zero_trust_tunnel_cloudflared` |

**Note:** `cloudflare_rate_limit` is deprecated since 2025-06-15.

## Common Resources

### Zone Data Source

```hcl
data "cloudflare_zone" "main" {
  filter {
    name = "example.com"
  }
}

# Use: data.cloudflare_zone.main.id
```

### DNS Record

```hcl
resource "cloudflare_dns_record" "www" {
  zone_id = data.cloudflare_zone.main.id
  name    = "www"
  content = "192.0.2.1"
  type    = "A"
  proxied = true
  ttl     = 1  # Auto when proxied
}

resource "cloudflare_dns_record" "cname" {
  zone_id = data.cloudflare_zone.main.id
  name    = "api"
  content = "origin.example.com"
  type    = "CNAME"
  proxied = true
}

resource "cloudflare_dns_record" "txt" {
  zone_id = data.cloudflare_zone.main.id
  name    = "_dmarc"
  content = "v=DMARC1; p=reject"
  type    = "TXT"
  ttl     = 3600
}
```

### Tunnel

```hcl
resource "cloudflare_zero_trust_tunnel_cloudflared" "main" {
  account_id = var.account_id
  name       = "gh-runner"
  secret     = base64encode(random_password.tunnel_secret.result)
}

resource "random_password" "tunnel_secret" {
  length = 32
}

# Tunnel config
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "main" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.main.id

  config {
    ingress_rule {
      hostname = "webhook.example.com"
      service  = "http://localhost:8080"
    }
    ingress_rule {
      service = "http_status:404"
    }
  }
}

# DNS record pointing to tunnel
resource "cloudflare_dns_record" "tunnel" {
  zone_id = data.cloudflare_zone.main.id
  name    = "webhook"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.main.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}
```

### Rate Limiting Ruleset

```hcl
resource "cloudflare_ruleset" "rate_limit" {
  zone_id = data.cloudflare_zone.main.id
  name    = "webhook-rate-limit"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules {
    action      = "block"
    description = "Rate limit webhook endpoint"
    expression  = "(http.request.uri.path eq \"/github-webhook\")"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 100
      mitigation_timeout  = 60
    }
  }
}
```

### Rate Limiting with Custom Response

```hcl
resource "cloudflare_ruleset" "rate_limit_custom" {
  zone_id = data.cloudflare_zone.main.id
  name    = "api-rate-limit"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules {
    action      = "block"
    description = "API rate limit"
    expression  = "(http.request.uri.path contains \"/api/\")"
    enabled     = true

    action_parameters {
      response {
        status_code  = 429
        content      = "{\"error\": \"Rate limit exceeded\"}"
        content_type = "application/json"
      }
    }

    ratelimit {
      characteristics     = ["ip.src", "http.request.headers[\"x-api-key\"]"]
      period              = 60
      requests_per_period = 1000
      mitigation_timeout  = 300
    }
  }
}
```

### Access Application

```hcl
resource "cloudflare_zero_trust_access_application" "internal" {
  account_id       = var.account_id
  name             = "Internal App"
  domain           = "internal.example.com"
  type             = "self_hosted"
  session_duration = "24h"
}

resource "cloudflare_zero_trust_access_policy" "allow_team" {
  account_id     = var.account_id
  application_id = cloudflare_zero_trust_access_application.internal.id
  name           = "Allow Engineering"
  decision       = "allow"
  precedence     = 1

  include {
    email_domain = ["company.com"]
  }
}
```

### Service Token

```hcl
resource "cloudflare_zero_trust_access_service_token" "ci" {
  account_id = var.account_id
  name       = "ci-cd-token"
}

# Use in policy
resource "cloudflare_zero_trust_access_policy" "ci_access" {
  account_id     = var.account_id
  application_id = cloudflare_zero_trust_access_application.internal.id
  name           = "CI/CD Access"
  decision       = "non_identity"
  precedence     = 2

  include {
    service_token = [cloudflare_zero_trust_access_service_token.ci.id]
  }
}
```

## Expression Syntax

Rate limiting and firewall rules use Cloudflare expression syntax:

```hcl
# Path matching
"(http.request.uri.path eq \"/webhook\")"
"(http.request.uri.path contains \"/api/\")"
"(http.request.uri.path matches \"^/v[0-9]+/\")"

# Method
"(http.request.method eq \"POST\")"

# Headers
"(http.request.headers[\"content-type\"] contains \"json\")"

# IP
"(ip.src eq 192.0.2.1)"
"(ip.src in {192.0.2.0/24})"

# Country
"(ip.geoip.country eq \"US\")"

# Combinations
"(http.request.uri.path eq \"/webhook\" and http.request.method eq \"POST\")"
"(http.request.uri.path contains \"/api/\" or http.request.uri.path contains \"/webhook\")"
```

## Variables

```hcl
variable "cloudflare_api_token" {
  description = "Cloudflare API token"
  type        = string
  sensitive   = true
}

variable "account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "zone_name" {
  description = "Domain name"
  type        = string
  default     = "example.com"
}
```

## Outputs

```hcl
output "tunnel_token" {
  description = "Token for cloudflared"
  value       = cloudflare_zero_trust_tunnel_cloudflared.main.tunnel_token
  sensitive   = true
}

output "webhook_url" {
  description = "Webhook URL"
  value       = "https://webhook.${var.zone_name}"
}
```

## Import Existing Resources

```bash
# Use cf-terraforming to generate config
brew install cloudflare/cloudflare/cf-terraforming

# Generate resource configuration
cf-terraforming generate \
  --resource-type "cloudflare_dns_record" \
  --zone <zone-id> \
  --token <api-token>

# Generate import commands
cf-terraforming import \
  --resource-type "cloudflare_dns_record" \
  --zone <zone-id> \
  --token <api-token>

# Then run generated import commands
tofu import cloudflare_dns_record.www <zone-id>/<record-id>
```

## Common Patterns

### Webhook Endpoint with Rate Limiting

```hcl
# Tunnel
resource "cloudflare_zero_trust_tunnel_cloudflared" "webhook" {
  account_id = var.account_id
  name       = "webhook-tunnel"
  secret     = base64encode(random_password.tunnel.result)
}

# DNS
resource "cloudflare_dns_record" "webhook" {
  zone_id = data.cloudflare_zone.main.id
  name    = "webhook"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.webhook.id}.cfargotunnel.com"
  type    = "CNAME"
  proxied = true
}

# Rate limit
resource "cloudflare_ruleset" "webhook_rate_limit" {
  zone_id = data.cloudflare_zone.main.id
  name    = "webhook-rate-limit"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules {
    action      = "block"
    expression  = "(http.host eq \"webhook.${var.zone_name}\")"
    enabled     = true
    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 100
      mitigation_timeout  = 60
    }
  }
}
```

### Environment-Specific Configuration

```hcl
locals {
  env = terraform.workspace

  config = {
    dev = {
      rate_limit = 1000
      tunnel_name = "webhook-dev"
    }
    prod = {
      rate_limit = 100
      tunnel_name = "webhook-prod"
    }
  }
}

resource "cloudflare_ruleset" "rate_limit" {
  # ...
  rules {
    ratelimit {
      requests_per_period = local.config[local.env].rate_limit
    }
  }
}
```
