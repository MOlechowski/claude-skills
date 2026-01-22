# Cloudflare MCP Servers Reference

Official MCP servers from [cloudflare/mcp-server-cloudflare](https://github.com/cloudflare/mcp-server-cloudflare).

## Overview

### What is MCP?

Model Context Protocol (MCP) is an open standard for AI assistants to connect with external tools and data sources.

### Remote vs Local MCP

| Aspect | Cloudflare (Remote) | AWS (Local) |
|--------|---------------------|-------------|
| Hosting | Cloudflare-hosted URLs | Self-hosted via uvx |
| Installation | None required | `uvx awslabs.<server>@latest` |
| Configuration | URL-based | Command-based |
| Authentication | API tokens via OAuth | IAM credentials |
| Updates | Automatic | Manual |

**Key advantage:** No installation, instant access, always up-to-date.

## Quick Start

### Claude Code Configuration

Add to `.mcp.json` or `~/.claude/claude_code_config.json`:

```json
{
  "mcpServers": {
    "cloudflare-docs": {
      "url": "https://docs.mcp.cloudflare.com/mcp"
    }
  }
}
```

### Authentication

Most servers require Cloudflare API authentication. OAuth flow is triggered automatically on first use.

**Required for authenticated servers:**
1. Cloudflare account
2. API token with appropriate permissions
3. Account ID (for account-scoped resources)

### Environment Variables

Some servers accept environment variables for non-interactive auth:

| Variable | Purpose |
|----------|---------|
| `CLOUDFLARE_API_TOKEN` | API token authentication |
| `CLOUDFLARE_ACCOUNT_ID` | Account identifier |
| `CLOUDFLARE_ZONE_ID` | Zone identifier (for zone-scoped ops) |

## Servers by Category

### Documentation (2 servers)

| Server | URL | Purpose | Auth |
|--------|-----|---------|------|
| Documentation | `https://docs.mcp.cloudflare.com/mcp` | Search Cloudflare documentation | None |
| Agents SDK Docs | `https://agents.mcp.cloudflare.com/mcp` | Cloudflare Agents SDK documentation | None |

**Tools provided:**

**Documentation:**
- `cloudflare_documentation_search` - Search developer docs
- `cloudflare_documentation_read` - Read specific documentation pages

**Agents SDK Docs:**
- `agents_documentation_search` - Search Agents SDK documentation
- `agents_documentation_read` - Read Agents SDK guides

**Use cases:**
- Learning Cloudflare APIs
- Finding configuration examples
- Understanding Workers patterns
- Building AI agents on Cloudflare

### Workers Platform (3 servers)

| Server | URL | Purpose | Auth |
|--------|-----|---------|------|
| Workers Bindings | `https://bindings.mcp.cloudflare.com/mcp` | Manage Worker bindings (KV, R2, D1, etc.) | Required |
| Workers Builds | `https://builds.mcp.cloudflare.com/mcp` | Worker build and deployment info | Required |
| Container Registry | `https://container.mcp.cloudflare.com/mcp` | Cloudflare Container Registry | Required |

**Tools provided:**

**Workers Bindings:**
- `list_bindings` - List all bindings for a Worker
- `get_binding` - Get specific binding details
- `kv_list` - List KV namespace keys
- `kv_get` - Get KV value
- `r2_list` - List R2 bucket objects
- `r2_get` - Get R2 object
- `d1_query` - Execute D1 SQL query
- `d1_list_tables` - List D1 tables

**Workers Builds:**
- `list_builds` - List Worker builds
- `get_build` - Get build details
- `get_build_logs` - Retrieve build logs

**Container Registry:**
- `list_images` - List container images
- `get_image` - Get image details
- `list_tags` - List image tags

**Permissions required:**
- Workers: `Workers Scripts:Read`, `Workers KV Storage:Read`
- D1: `D1:Read`
- R2: `Workers R2 Storage:Read`
- Containers: `Containers:Read`

**Use cases:**
- Debugging Worker configurations
- Inspecting KV/R2/D1 data
- Troubleshooting builds
- Managing container deployments

### AI Services (2 servers)

| Server | URL | Purpose | Auth |
|--------|-----|---------|------|
| AI Gateway | `https://ai-gateway.mcp.cloudflare.com/mcp` | AI Gateway management and analytics | Required |
| AutoRAG | `https://autorag.mcp.cloudflare.com/mcp` | Automatic RAG pipeline management | Required |

**Tools provided:**

**AI Gateway:**
- `list_gateways` - List AI Gateway configurations
- `get_gateway` - Get gateway details
- `get_gateway_logs` - Retrieve gateway request logs
- `get_analytics` - AI Gateway usage analytics
- `list_providers` - List configured AI providers

**AutoRAG:**
- `list_indexes` - List RAG indexes
- `get_index` - Get index details
- `query_index` - Query a RAG index
- `get_documents` - List indexed documents
- `get_index_stats` - Index statistics

**Permissions required:**
- AI Gateway: `AI Gateway:Read`
- AutoRAG: `Vectorize:Read`, `AI Gateway:Read`

**Use cases:**
- Monitoring AI API usage
- Debugging AI requests
- Managing RAG pipelines
- Cost analysis for AI operations

### Observability (3 servers)

| Server | URL | Purpose | Auth |
|--------|-----|---------|------|
| Observability | `https://observability.mcp.cloudflare.com/mcp` | Logs, metrics, and tracing | Required |
| Logpush | `https://logpush.mcp.cloudflare.com/mcp` | Logpush job management | Required |
| Audit Logs | `https://audit-logs.mcp.cloudflare.com/mcp` | Account audit log access | Required |

**Tools provided:**

**Observability:**
- `query_logs` - Query Worker logs
- `get_metrics` - Get Worker metrics
- `get_traces` - Get distributed traces
- `list_workers` - List Workers with observability data
- `get_errors` - Get error reports

**Logpush:**
- `list_jobs` - List Logpush jobs
- `get_job` - Get job details
- `list_destinations` - List configured destinations
- `get_job_status` - Job health status

**Audit Logs:**
- `query_audit_logs` - Query account audit logs
- `get_audit_log` - Get specific audit event
- `list_actors` - List users who performed actions
- `list_actions` - List audit action types

**Permissions required:**
- Observability: `Logs:Read`, `Analytics:Read`
- Logpush: `Logs:Read`
- Audit Logs: `Audit Logs:Read`

**Use cases:**
- Debugging Worker issues
- Monitoring application health
- Security auditing
- Compliance reporting
- Troubleshooting log delivery

### Analytics (2 servers)

| Server | URL | Purpose | Auth |
|--------|-----|---------|------|
| Radar | `https://radar.mcp.cloudflare.com/mcp` | Cloudflare Radar internet insights | None |
| DNS Analytics | `https://dns-analytics.mcp.cloudflare.com/mcp` | DNS query analytics | Required |

**Tools provided:**

**Radar:**
- `get_traffic_trends` - Global internet traffic trends
- `get_attack_trends` - DDoS and attack trends
- `get_routing_stats` - BGP routing statistics
- `get_outages` - Internet outage detection
- `get_quality_metrics` - Network quality by region
- `get_adoption_stats` - Technology adoption (IPv6, HTTP/3, etc.)

**DNS Analytics:**
- `query_dns_analytics` - Query DNS analytics
- `get_top_queries` - Top queried domains
- `get_query_types` - Query type distribution
- `get_response_codes` - Response code breakdown
- `get_resolver_stats` - Resolver performance

**Permissions required:**
- Radar: None (public data)
- DNS Analytics: `DNS:Read`, `Analytics:Read`

**Use cases:**
- Internet trend analysis
- Security threat research
- DNS performance monitoring
- Traffic pattern analysis

### Security (2 servers)

| Server | URL | Purpose | Auth |
|--------|-----|---------|------|
| CASB | `https://casb.mcp.cloudflare.com/mcp` | Cloud Access Security Broker | Required |
| DEX | `https://dex.mcp.cloudflare.com/mcp` | Digital Experience monitoring | Required |

**Tools provided:**

**CASB:**
- `list_integrations` - List SaaS integrations
- `get_integration` - Get integration details
- `list_findings` - List security findings
- `get_finding` - Get finding details
- `get_posture` - Security posture summary

**DEX:**
- `get_device_health` - Device health metrics
- `list_tests` - List synthetic tests
- `get_test_results` - Get test results
- `get_network_path` - Network path analysis
- `get_user_experience` - User experience scores

**Permissions required:**
- CASB: `Access: CASB:Read`
- DEX: `DEX:Read`

**Use cases:**
- SaaS security monitoring
- Shadow IT detection
- Network performance analysis
- User experience monitoring
- Zero Trust posture assessment

### Browser & API (2 servers)

| Server | URL | Purpose | Auth |
|--------|-----|---------|------|
| Browser Rendering | `https://browser.mcp.cloudflare.com/mcp` | Browser Rendering API | Required |
| GraphQL API | `https://graphql.mcp.cloudflare.com/mcp` | Cloudflare GraphQL API | Required |

**Tools provided:**

**Browser Rendering:**
- `render_page` - Render a web page
- `take_screenshot` - Capture page screenshot
- `get_pdf` - Generate PDF from page
- `extract_content` - Extract page content
- `run_script` - Execute JavaScript on page

**GraphQL API:**
- `query` - Execute GraphQL query
- `get_schema` - Get API schema
- `list_datasets` - List available datasets
- `explore_type` - Explore GraphQL type

**Permissions required:**
- Browser Rendering: `Workers Browser Rendering:Read`
- GraphQL API: Depends on query (various permissions)

**Use cases:**
- Web scraping
- PDF generation
- Screenshot automation
- Custom analytics queries
- Advanced API exploration

## Configuration Examples

### Single Server (Documentation)

```json
{
  "mcpServers": {
    "cloudflare-docs": {
      "url": "https://docs.mcp.cloudflare.com/mcp"
    }
  }
}
```

### Development Setup (Workers + Docs)

```json
{
  "mcpServers": {
    "cloudflare-docs": {
      "url": "https://docs.mcp.cloudflare.com/mcp"
    },
    "cloudflare-bindings": {
      "url": "https://bindings.mcp.cloudflare.com/mcp"
    },
    "cloudflare-builds": {
      "url": "https://builds.mcp.cloudflare.com/mcp"
    }
  }
}
```

### Full Observability Setup

```json
{
  "mcpServers": {
    "cloudflare-observability": {
      "url": "https://observability.mcp.cloudflare.com/mcp"
    },
    "cloudflare-logpush": {
      "url": "https://logpush.mcp.cloudflare.com/mcp"
    },
    "cloudflare-audit": {
      "url": "https://audit-logs.mcp.cloudflare.com/mcp"
    }
  }
}
```

### AI Development Setup

```json
{
  "mcpServers": {
    "cloudflare-docs": {
      "url": "https://docs.mcp.cloudflare.com/mcp"
    },
    "cloudflare-agents": {
      "url": "https://agents.mcp.cloudflare.com/mcp"
    },
    "cloudflare-ai-gateway": {
      "url": "https://ai-gateway.mcp.cloudflare.com/mcp"
    },
    "cloudflare-autorag": {
      "url": "https://autorag.mcp.cloudflare.com/mcp"
    }
  }
}
```

### Complete Setup (All Servers)

```json
{
  "mcpServers": {
    "cf-docs": {
      "url": "https://docs.mcp.cloudflare.com/mcp"
    },
    "cf-agents": {
      "url": "https://agents.mcp.cloudflare.com/mcp"
    },
    "cf-bindings": {
      "url": "https://bindings.mcp.cloudflare.com/mcp"
    },
    "cf-builds": {
      "url": "https://builds.mcp.cloudflare.com/mcp"
    },
    "cf-container": {
      "url": "https://container.mcp.cloudflare.com/mcp"
    },
    "cf-ai-gateway": {
      "url": "https://ai-gateway.mcp.cloudflare.com/mcp"
    },
    "cf-autorag": {
      "url": "https://autorag.mcp.cloudflare.com/mcp"
    },
    "cf-observability": {
      "url": "https://observability.mcp.cloudflare.com/mcp"
    },
    "cf-logpush": {
      "url": "https://logpush.mcp.cloudflare.com/mcp"
    },
    "cf-audit": {
      "url": "https://audit-logs.mcp.cloudflare.com/mcp"
    },
    "cf-radar": {
      "url": "https://radar.mcp.cloudflare.com/mcp"
    },
    "cf-dns-analytics": {
      "url": "https://dns-analytics.mcp.cloudflare.com/mcp"
    },
    "cf-casb": {
      "url": "https://casb.mcp.cloudflare.com/mcp"
    },
    "cf-dex": {
      "url": "https://dex.mcp.cloudflare.com/mcp"
    },
    "cf-browser": {
      "url": "https://browser.mcp.cloudflare.com/mcp"
    },
    "cf-graphql": {
      "url": "https://graphql.mcp.cloudflare.com/mcp"
    }
  }
}
```

## Use Case Mappings

| Task | Recommended Servers |
|------|---------------------|
| Learning Cloudflare | docs, agents |
| Workers development | docs, bindings, builds |
| AI applications | docs, agents, ai-gateway, autorag |
| Debugging Workers | observability, bindings |
| Security auditing | audit-logs, casb |
| Performance monitoring | observability, dex, dns-analytics |
| Log management | logpush, observability |
| Container workloads | container, builds |
| Internet research | radar |
| Custom analytics | graphql |
| Web automation | browser |
| Zero Trust setup | casb, dex, audit-logs |

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| Authentication error | Missing/invalid token | Re-authenticate via OAuth flow |
| Permission denied | Insufficient API token scope | Create new token with required permissions |
| Server not responding | Network issue | Check connectivity, retry |
| Tool not found | Server doesn't support tool | Verify tool exists in server docs |
| Rate limited | Too many requests | Implement backoff, reduce request rate |

## API Token Permissions Summary

| Server | Minimum Permissions |
|--------|---------------------|
| Documentation | None |
| Agents SDK Docs | None |
| Workers Bindings | Workers Scripts:Read, Workers KV Storage:Read |
| Workers Builds | Workers Scripts:Read |
| Container Registry | Containers:Read |
| AI Gateway | AI Gateway:Read |
| AutoRAG | Vectorize:Read |
| Observability | Logs:Read, Analytics:Read |
| Logpush | Logs:Read |
| Audit Logs | Audit Logs:Read |
| Radar | None (public) |
| DNS Analytics | DNS:Read, Analytics:Read |
| CASB | Access: CASB:Read |
| DEX | DEX:Read |
| Browser Rendering | Workers Browser Rendering:Read |
| GraphQL API | Varies by query |

## Resources

- [MCP Server Repository](https://github.com/cloudflare/mcp-server-cloudflare)
- [MCP Specification](https://modelcontextprotocol.io/)
- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)
- [API Token Creation](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
