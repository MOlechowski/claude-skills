# Cloudflare Zero Trust Reference

## Overview

Zero Trust replaces VPNs with identity-aware access controls. Key components:

- **Access**: Protect applications with identity verification
- **Gateway**: Secure DNS and HTTP filtering
- **WARP**: Device agent for secure connectivity
- **Tunnel**: Connect private networks to Cloudflare

## Access Applications

### Application Types

| Type | Use Case |
|------|----------|
| Self-hosted | Apps behind Cloudflare Tunnel |
| SaaS | Third-party apps (Salesforce, GitHub) |
| Bookmark | Links in App Launcher |
| Infrastructure | SSH, VNC, RDP access |

### Creating an Application (Dashboard)

1. Zero Trust → Access → Applications
2. Add an application
3. Select type (Self-hosted, SaaS, etc.)
4. Configure domain/path
5. Add access policies

## Access Policies

### Policy Actions

| Action | Description |
|--------|-------------|
| **Allow** | Grant access if rules match |
| **Block** | Deny access if rules match |
| **Bypass** | Skip Access entirely (no logging) |
| **Service Auth** | Machine-to-machine (tokens/mTLS) |

### Rule Types

- **Include**: Users must match (OR logic within)
- **Require**: Users must match ALL (AND logic)
- **Exclude**: Users are denied (NOT logic)

### Policy Structure

```
Policy: "Allow Engineering Team"
Action: Allow

Include (any of):
  - Email ends with @company.com
  - IdP Group = "Engineering"

Require (all of):
  - Country = United States
  - Device posture = Compliant

Exclude:
  - Email = contractor@company.com
```

### Common Selectors

| Selector | Description |
|----------|-------------|
| `email` | User email address |
| `email domain` | Email domain (@example.com) |
| `IdP groups` | Groups from identity provider |
| `IP ranges` | Source IP addresses |
| `Country` | Geographic location |
| `Device posture` | WARP client checks |
| `Service token` | Machine authentication |
| `mTLS certificate` | Client certificate |
| `Authentication method` | MFA, SSO, etc. |

## Service Tokens

For machine-to-machine authentication (APIs, CI/CD):

### Create Token (Dashboard)

1. Zero Trust → Access → Service Auth
2. Create Service Token
3. Copy `CF-Access-Client-Id` and `CF-Access-Client-Secret`

### Use Token

```bash
curl -H "CF-Access-Client-Id: <id>" \
     -H "CF-Access-Client-Secret: <secret>" \
     https://app.example.com/api
```

### Token in Application Policy

```
Policy: "Allow CI/CD"
Action: Service Auth

Include:
  - Service Token = "ci-cd-token"
```

## Tunnel + Access Integration

Secure internal apps via tunnel with Access policies:

```
Internet → Cloudflare Access → Tunnel → Internal App
              (identity)       (connectivity)
```

### Setup

1. Create tunnel connecting to internal app
2. Create Access application for tunnel hostname
3. Add Access policies (who can access)

### Example Config

```yaml
# ~/.cloudflared/config.yml
tunnel: internal-apps
credentials-file: ~/.cloudflared/tunnel-id.json

ingress:
  - hostname: internal.example.com
    service: http://localhost:3000
  - service: http_status:404
```

Then create Access application for `internal.example.com` with policies.

## Identity Providers

### Supported IdPs

- Okta
- Azure AD
- Google Workspace
- GitHub
- OneLogin
- Generic OIDC
- Generic SAML

### Adding IdP (Dashboard)

1. Zero Trust → Settings → Authentication
2. Add new identity provider
3. Configure OAuth/SAML settings
4. Test connection

## Device Posture

Verify device compliance before granting access:

### Posture Checks

| Check | Description |
|-------|-------------|
| WARP | WARP client is connected |
| Gateway | Traffic routes through Gateway |
| Disk encryption | FileVault/BitLocker enabled |
| OS version | Minimum OS version |
| Firewall | System firewall enabled |
| Domain joined | AD domain membership |

### Using in Policies

```
Policy: "Require Compliant Device"
Action: Allow

Include:
  - Email domain = company.com

Require:
  - Device posture = WARP running
  - Device posture = Disk encrypted
```

## App Launcher

Central portal for all protected applications:

- URL: `https://<team-name>.cloudflareaccess.com`
- Shows all apps user has access to
- Configurable in Zero Trust → Settings

## API Access

### Endpoints

```
Base URL: https://api.cloudflare.com/client/v4

# Access Applications
GET    /accounts/{account_id}/access/apps
POST   /accounts/{account_id}/access/apps
PUT    /accounts/{account_id}/access/apps/{app_id}
DELETE /accounts/{account_id}/access/apps/{app_id}

# Access Policies
GET    /accounts/{account_id}/access/apps/{app_id}/policies
POST   /accounts/{account_id}/access/apps/{app_id}/policies
```

### Authentication

```bash
# API Token (recommended)
curl -H "Authorization: Bearer <token>" \
     https://api.cloudflare.com/client/v4/accounts/<id>/access/apps

# Or Global API Key (legacy)
curl -H "X-Auth-Email: <email>" \
     -H "X-Auth-Key: <key>" \
     https://api.cloudflare.com/client/v4/...
```

## Common Patterns

### Public App with IdP Login

```
Policy: Allow
Include: Login method = Any IdP
```

### Internal Tool for Specific Team

```
Policy: Allow
Include: IdP Group = "Engineering"
Require: Device posture = WARP connected
```

### API Access for CI/CD

```
Policy: Service Auth
Include: Service Token = "github-actions"
```

### Temporary Contractor Access

```
Policy: Allow
Include: Email = contractor@external.com
Require: Valid until = 2025-03-01
```
