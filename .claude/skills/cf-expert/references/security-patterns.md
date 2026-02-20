# Cloudflare Security Patterns

## WAF Strategy

### Managed Rules

Cloudflare provides pre-configured rulesets for common attack patterns:

| Ruleset | Purpose | Recommendation |
|---------|---------|----------------|
| Cloudflare Managed | SQLi, XSS, OWASP Top 10 | Enable on all zones |
| OWASP Core | ModSecurity rules implementation | Enable for strict compliance |
| Cloudflare Specials | Platform-specific protections | Enable for CMS/frameworks |

### WAF Deployment Workflow

```
1. Enable rulesets in Log mode
2. Analyze traffic for 1-2 weeks
3. Identify false positives
4. Create WAF Exceptions for legitimate traffic
5. Switch to Block mode
6. Monitor and adjust
```

### WAF Exceptions (Overrides)

Skip specific rules for legitimate traffic:

```hcl
resource "cloudflare_ruleset" "waf_override" {
  zone_id = var.zone_id
  name    = "WAF Exceptions"
  kind    = "zone"
  phase   = "http_request_firewall_managed"

  rules {
    action = "skip"
    action_parameters {
      ruleset = "efb7b8c949ac4650a09736fc376e9aee"  # Cloudflare Managed
    }
    expression  = "(http.request.uri.path contains \"/api/upload\")"
    description = "Skip WAF for file upload endpoint"
    enabled     = true
  }
}
```

### Custom Rules

Fine-tune protection beyond managed rules:

```hcl
resource "cloudflare_ruleset" "custom_waf" {
  zone_id = var.zone_id
  name    = "Custom WAF Rules"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  # Block requests without User-Agent
  rules {
    action      = "block"
    expression  = "(not http.user_agent ne \"\")"
    description = "Block empty User-Agent"
    enabled     = true
  }

  # Challenge suspicious patterns
  rules {
    action      = "managed_challenge"
    expression  = "(http.request.uri.query contains \"<script\")"
    description = "Challenge XSS attempts"
    enabled     = true
  }
}
```

### Body Inspection Limits

| Plan | Max Body Size |
|------|---------------|
| Free | 0 (headers only) |
| Pro | 0 (headers only) |
| Business | 128 KB |
| Enterprise | 128 KB (configurable) |

## Bot Management

### Bot Score Interpretation

| Score Range | Traffic Type | Recommended Action |
|-------------|--------------|-------------------|
| 1-29 | Likely automated | Block or Challenge |
| 30-49 | Possibly automated | Managed Challenge |
| 50-79 | Possibly human | Allow with logging |
| 80-99 | Likely human | Allow |

### Bot Rules (Terraform)

```hcl
resource "cloudflare_bot_management" "main" {
  zone_id           = var.zone_id
  auto_update_model = true
  fight_mode        = true
}

# Custom bot rules
resource "cloudflare_ruleset" "bot_protection" {
  zone_id = var.zone_id
  name    = "Bot Protection"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  # Block likely bots on login
  rules {
    action      = "block"
    expression  = "(http.request.uri.path eq \"/login\" and cf.bot_management.score lt 30)"
    description = "Block bots on login"
    enabled     = true
  }

  # Allow verified bots
  rules {
    action      = "skip"
    action_parameters {
      phases = ["http_request_firewall_managed"]
    }
    expression  = "(cf.bot_management.verified_bot)"
    description = "Allow verified bots"
    enabled     = true
  }
}
```

### Verified vs Known Bots

| Category | Examples | Default Behavior |
|----------|----------|------------------|
| Verified Bots | Googlebot, Bingbot, monitoring tools | Allowed |
| Known Bots | ChatGPT (2025+), scrapers | Not automatically allowed |

**Note:** As of 2025, ChatGPT moved from Verified to Known Bots category.

### Super Bot Fight Mode Settings

```hcl
resource "cloudflare_bot_management" "sbfm" {
  zone_id                  = var.zone_id
  fight_mode               = true
  enable_js                = true  # JavaScript detection
  suppress_session_score   = false
  optimize_wordpress       = true  # If using WordPress
}
```

## DDoS Protection

### Default Behavior

DDoS protection is enabled by default on all plans with autonomous edge detection.

### Sensitivity Tuning

```
High sensitivity: More aggressive detection (may cause false positives)
Medium: Balanced (default)
Low: More permissive (fewer false positives, slower detection)
```

### DDoS Override Rules

```hcl
resource "cloudflare_ruleset" "ddos_override" {
  zone_id = var.zone_id
  name    = "DDoS Overrides"
  kind    = "zone"
  phase   = "ddos_l7"

  rules {
    action = "execute"
    action_parameters {
      id = "4d21379b4f9f4bb088e0729962c8b3cf"  # HTTP DDoS ruleset
      overrides {
        sensitivity_level = "low"  # Reduce sensitivity
      }
    }
    expression  = "(http.request.uri.path contains \"/api/\")"
    description = "Lower DDoS sensitivity for API"
    enabled     = true
  }
}
```

### Under Attack Mode

Emergency protection during active attacks:

```bash
# Enable via API
curl -X PATCH \
  "https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level" \
  -H "Authorization: Bearer <token>" \
  -d '{"value": "under_attack"}'
```

**Before enabling:**
1. Whitelist legitimate API sources
2. Notify users about challenge pages
3. Monitor impact on legitimate traffic

## Rate Limiting

### Modern Rate Limiting (Rulesets)

```hcl
resource "cloudflare_ruleset" "rate_limits" {
  zone_id = var.zone_id
  name    = "Rate Limits"
  kind    = "zone"
  phase   = "http_ratelimit"

  # Login protection
  rules {
    action      = "managed_challenge"
    expression  = "(http.request.uri.path eq \"/login\")"
    description = "Challenge after 5 login attempts/min"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 5
      mitigation_timeout  = 600
    }
  }

  # Stricter limit for repeated failures
  rules {
    action      = "block"
    expression  = "(http.request.uri.path eq \"/login\")"
    description = "Block after 20 login attempts/min"
    enabled     = true

    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 20
      mitigation_timeout  = 3600
    }
  }

  # API rate limit by key
  rules {
    action      = "block"
    expression  = "(http.request.uri.path contains \"/api/\")"
    description = "API rate limit per key"
    enabled     = true

    action_parameters {
      response {
        status_code  = 429
        content      = "{\"error\": \"Rate limit exceeded\"}"
        content_type = "application/json"
      }
    }

    ratelimit {
      characteristics     = ["http.request.headers[\"x-api-key\"]"]
      period              = 60
      requests_per_period = 1000
      mitigation_timeout  = 60
    }
  }
}
```

### Rate Limit Characteristics

| Characteristic | Use Case |
|----------------|----------|
| `ip.src` | Per-IP limiting |
| `cf.unique_visitor_id` | Per-visitor (more accurate) |
| `http.request.headers["x-api-key"]` | Per API key |
| `http.request.headers["authorization"]` | Per auth token |
| `ip.src` + `http.request.uri.path` | Per-IP per-endpoint |

### Graduated Response Pattern

```
Rule 1: 5 req/min  → Managed Challenge (CAPTCHA)
Rule 2: 20 req/min → Block for 10 minutes
Rule 3: 50 req/min → Block for 1 hour
```

## IP Access Rules

### Allow/Block Lists

```hcl
resource "cloudflare_ip_list" "allowed_ips" {
  account_id  = var.account_id
  name        = "allowed-ips"
  description = "Trusted IPs"
  kind        = "ip"

  item {
    value = "192.0.2.0/24"
    comment = "Office network"
  }
  item {
    value = "203.0.113.50"
    comment = "VPN server"
  }
}

resource "cloudflare_ruleset" "ip_access" {
  zone_id = var.zone_id
  name    = "IP Access"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  # Allow trusted IPs
  rules {
    action      = "skip"
    action_parameters {
      phases = ["http_request_firewall_managed", "http_ratelimit"]
    }
    expression  = "(ip.src in $allowed_ips)"
    description = "Skip WAF for trusted IPs"
    enabled     = true
  }
}
```

## Security Headers

### Transform Rules for Headers

```hcl
resource "cloudflare_ruleset" "security_headers" {
  zone_id = var.zone_id
  name    = "Security Headers"
  kind    = "zone"
  phase   = "http_response_headers_transform"

  rules {
    action = "set"
    action_parameters {
      headers {
        name      = "X-Content-Type-Options"
        operation = "set"
        value     = "nosniff"
      }
      headers {
        name      = "X-Frame-Options"
        operation = "set"
        value     = "DENY"
      }
      headers {
        name      = "Strict-Transport-Security"
        operation = "set"
        value     = "max-age=31536000; includeSubDomains"
      }
      headers {
        name      = "Content-Security-Policy"
        operation = "set"
        value     = "default-src 'self'"
      }
    }
    expression  = "true"
    description = "Add security headers"
    enabled     = true
  }
}
```

## Logging & Monitoring

### WAF Event Logs

Access via:
- Dashboard: Security → Events
- API: `/zones/{zone_id}/security/events`
- Logpush: Stream to SIEM (S3, Splunk, etc.)

### Key Metrics to Monitor

| Metric | Alert Threshold |
|--------|-----------------|
| WAF blocks | Sudden spike (>2x baseline) |
| Bot score < 30 | High volume |
| Rate limit triggers | >100/hour |
| DDoS mitigation | Any activation |

### Logpush Configuration

```hcl
resource "cloudflare_logpush_job" "security" {
  account_id          = var.account_id
  enabled             = true
  name                = "security-logs"
  logpull_options     = "fields=RayID,ClientIP,Action,RuleID&timestamps=rfc3339"
  destination_conf    = "s3://bucket/logs?region=us-east-1"
  dataset             = "firewall_events"
  ownership_challenge = "..."
}
```
