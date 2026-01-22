---
name: cloudflare-expert
description: "Cloudflare infrastructure expertise: architecture decisions, Zero Trust, security (WAF, DDoS, bots), rate limiting, caching, Workers AI, IaC. Use for: choosing tunnel types, storage selection, Access policies, security configuration, Workers vs Pages, caching strategy, AI patterns, migration. Triggers: cloudflare architecture, zero trust, rate limiting, cloudflare terraform, WAF, DDoS, bot management, tiered cache, argo, workers ai, vectorize."
---

# Cloudflare Expert

Domain expertise for Cloudflare infrastructure decisions, security, Zero Trust, and IaC.

For CLI usage, see: `cloudflared`, `wrangler`, `flarectl` skills.

For deeper research on any topic, use `/web-research` skill.

## Decision Matrices

### Tunnel Type

CLI: `cloudflared`

| Use Case | Type | Why |
|----------|------|-----|
| Quick demo/testing | Quick tunnel | No setup, instant URL |
| Production webhook | Named tunnel | Persistent URL, survives restarts |
| Internal tools | Named + Access | Identity-based protection |
| CI/CD access | Service token | Machine authentication |

### Storage (Workers)

CLI: `wrangler`

| Need | Service | Use Case |
|------|---------|----------|
| Key-value cache | KV | Sessions, config, feature flags |
| SQL database | D1 | Structured data, relationships |
| File storage | R2 | Images, documents, backups |
| Vector search | Vectorize | AI embeddings, similarity |

### Bot Management

| Plan | Product | Features |
|------|---------|----------|
| Free | Bot Fight Mode | Basic automation detection, challenges |
| Pro/Business | Super Bot Fight Mode | Sensitivity controls, JS detection |
| Enterprise | Bot Management | Bot score 1-99, detailed analytics |

## Security (WAF, Bots, DDoS)

### WAF Strategy

**Use both Managed Rules (baseline) + Custom Rules (fine-tuning):**

| Ruleset | Purpose |
|---------|---------|
| Cloudflare Managed | SQLi, XSS, OWASP Top 10 |
| OWASP Core | ModSecurity rules implementation |
| Cloudflare Specials | Platform-specific protections |

**Rate Limiting Pattern (login protection):**
```
Rule 1: 4 req/min  → Managed Challenge
Rule 2: 10 req/min → Block
```

**Best Practices:**
- Enable all managed rulesets, customize via overrides
- Start with Log mode to analyze traffic before blocking
- Body inspection limit: 128 KB (Enterprise), lower on other plans
- Integrate logs with SIEM for monitoring

### Bot Management

**Bot Score Usage:**
- Scores below 30 = likely bot traffic
- Use in WAF custom rules or Workers
- Combine with paths, headers, ASN, country

**Verified Bots:**
- Allow list for search engines, monitoring tools
- As of 2025: ChatGPT moved from Verified to Known Bots
- Create explicit Allow rules for bots you want

**Terraform config:**
```hcl
resource "cloudflare_bot_management" "example" {
  zone_id           = var.zone_id
  auto_update_model = true
  fight_mode        = true
}
```

### DDoS Protection

**Enabled by default** on all plans - autonomous edge detection.

**Tuning Steps:**
1. Set ruleset actions to **Log** first
2. Analyze flagged traffic
3. Adjust sensitivity for false positives
4. Switch back to default actions

**Under Attack Mode:**
- Use only during active DDoS
- Presents JS challenge to all visitors
- Whitelist legitimate API sources first

For detailed security patterns, see: [references/security-patterns.md](references/security-patterns.md)

## Pricing & Costs

**Get current prices:**
```bash
# Fetch live pricing from Cloudflare docs (uses uv for dependencies)
./scripts/fetch_prices.py workers  # or: d1, r2, kv, pages, plans, all
uv run scripts/fetch_prices.py r2  # explicit uv invocation
```

Or use `/web-research Cloudflare pricing [service]` or check [cloudflare.com/plans](https://www.cloudflare.com/plans/).

### Plan Tiers

| Plan | Best For | Key Features |
|------|----------|--------------|
| Free | Personal sites, blogs | Unlimited CDN bandwidth, basic DDoS, 100K Worker requests/day |
| Pro | Professional sites | WAF, image optimization, faster support |
| Business | E-commerce, high-traffic | Custom SSL, priority support, advanced analytics |
| Enterprise | Large organizations | Custom SLAs, dedicated support, advanced security |

### Free Tier Highlights

**Generous free limits (no credit card required):**
- CDN: Unlimited bandwidth
- Workers: 100K requests/day, 10ms CPU/request
- Pages: 500 builds/month, unlimited bandwidth
- KV/D1/R2: Daily free tiers (reset at 00:00 UTC)
- DNS: 1,000 records

### Workers Platform

**Paid plan includes:** Workers, Pages Functions, KV, D1, R2, Durable Objects, Hyperdrive

**Key cost factors:**
- Workers: Billed by CPU time (not wall time)
- D1: Billed by rows read/written
- R2: Billed by storage + operations
- **No egress fees** on any service

### Cost Optimization Strategies

**Workers:**
- Set CPU limits in wrangler.toml to prevent runaway bills
- Use Service Bindings between Workers (no extra request fees)
- Streaming responses not billed as CPU time

**D1 Database:**
- Create indexes on frequently queried columns (reduces rows_read)
- Scale-to-zero: no queries = no charges

**R2 Storage:**
- Zero egress fees (unlike AWS S3)
- Use for assets to avoid origin bandwidth costs

**Caching:**
- Maximize cache hit ratio
- Use Cache Rules for static assets
- Tiered Cache reduces origin requests

**General:**
- Start on Free plan, upgrade when limits hit
- Monitor usage in dashboard
- ~50% of Pro users started on Free

For detailed cost strategies, see: [references/cost-optimization.md](references/cost-optimization.md)

## Rate Limiting

**Note:** `cloudflare_rate_limit` resource is deprecated. Use `cloudflare_ruleset` with `phase = "http_ratelimit"`.

For OpenTofu/Terraform examples, see [references/tofu-provider.md](references/tofu-provider.md).

## Zero Trust Access

Protect apps with identity-aware policies:

```
Policy Actions: Allow | Block | Bypass | Service Auth
Rule Types:     Include (OR) | Require (AND) | Exclude (NOT)
Selectors:      email, IdP groups, IP, country, device posture
```

Service tokens for machine auth (CI/CD):
```bash
curl -H "CF-Access-Client-Id: <id>" \
     -H "CF-Access-Client-Secret: <secret>" \
     https://protected-app.example.com
```

For deep dive: See [references/zero-trust.md](references/zero-trust.md)

## OpenTofu Provider

Use provider v5 (`cloudflare/cloudflare ~> 5.0`). Key resources:

| Resource | Purpose |
|----------|---------|
| `cloudflare_dns_record` | DNS records (A, CNAME, TXT) |
| `cloudflare_zero_trust_tunnel_cloudflared` | Named tunnels |
| `cloudflare_ruleset` | Rate limiting, WAF rules |
| `cloudflare_zero_trust_access_application` | Access apps |
| `cloudflare_bot_management` | Bot protection settings |

**v4 → v5 changes:** Resources renamed (e.g., `cloudflare_record` → `cloudflare_dns_record`)

For setup, examples, and patterns: See [references/tofu-provider.md](references/tofu-provider.md)

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| 502 Bad Gateway | Origin not running | Start local service |
| Quick tunnel 429 | 200 request limit | Use named tunnel |
| DNS not resolving | Propagation delay | Wait 5-10 min, check `dig` |
| Config not loading | Wrong path | Use `--config path/config.yml` |
| Rate limit not working | Wrong phase | Use `phase = "http_ratelimit"` |
| False positives in WAF | Rules too aggressive | Use Log mode, adjust sensitivity |
| Bot blocking legit traffic | Missing Verified Bots rule | Add Allow rule for Verified Bots |

## Architecture Patterns

### Webhook Endpoint with Rate Limiting

```
Internet → Cloudflare (WAF + rate limit) → Tunnel → Origin
```

Components:
1. Named tunnel for persistent URL (`cloudflared`)
2. WAF managed rules for baseline protection
3. Rate limiting ruleset to prevent abuse (OpenTofu)
4. DNS record pointing to tunnel (`flarectl` or OpenTofu)

### Internal Tool with Access

```
Internet → Cloudflare Access → Tunnel → Internal App
              (identity)       (connectivity)
```

Components:
1. Named tunnel to internal service (`cloudflared`)
2. Access application with policies (Dashboard or OpenTofu)
3. IdP integration (Okta, Azure AD, Google)

### CI/CD with Service Token

```
GitHub Actions → Service Token → Access → Tunnel → API
```

Components:
1. Service token for machine auth (Dashboard)
2. Access policy allowing token (OpenTofu)
3. Tunnel to protected API (`cloudflared`)

## Performance (Caching & Argo)

### Tiered Cache

Reduces origin load by creating a hierarchy of cache tiers:

| Option | Description |
|--------|-------------|
| Smart Tiered Cache | Auto-selects closest upper-tier based on latency (recommended) |
| Generic Global | All data centers can serve as upper-tiers |
| Custom (Enterprise) | Custom topology for specific needs |

**Benefits:**
- Fewer requests to origin
- Higher cache hit ratios
- Regional content hashing routes same content to same upper-tier

**Note:** Cache API not compatible with Tiered Cache - use fetch API instead.

### Argo Smart Routing

Routes traffic around congestion for ~30% faster performance.

**When to enable:**
- Global audience (not purely local)
- Failing TTFB, FCP, or LCP metrics
- High-value traffic where latency impacts revenue

**Benefits:**
- 33% faster TTFB on average
- 40% reduced round-trip times
- 42% fewer connection timeouts (real-world example)

**Pricing:** Base fee + per-GB charges. DDoS-mitigated traffic not charged.

### Cache Rules

Fine-grained control over caching behavior:

```
Cache eligibility: Bypass cache | Eligible for cache
Edge TTL: Follow cache-control | Custom duration
Browser TTL: Respect origin | Override
```

**Best Practices:**
- Bypass cache for admin, AJAX, authenticated content
- Use Cache Rules instead of Page Rules (deprecated)
- Purge by URL/tag after updates, avoid full-zone purges
- Lower TTL before migrations

## Workers AI & Edge

### Platform Overview

| Service | Purpose |
|---------|---------|
| Workers AI | Run AI models serverless on Cloudflare GPUs |
| Vectorize | Vector database for embeddings, RAG |
| AI Gateway | Control plane for AI (analytics, caching, rate limiting) |

### RAG Pattern (Retrieval Augmented Generation)

```
1. Chunk documents → Workers AI embeddings
2. Store vectors → Vectorize
3. Query: embed question → retrieve top-k context
4. Generate: context + question → LLM response
```

**Code pattern:**
```javascript
// 1. Generate embedding
const embedding = await env.AI.run('@cf/baai/bge-base-en-v1.5', {
  text: query
});

// 2. Query Vectorize
const results = await env.VECTORIZE.query(embedding.data[0], { topK: 5 });

// 3. Get context and generate response
const context = results.matches.map(m => m.metadata.text).join('\n');
const response = await env.AI.run('@cf/meta/llama-2-7b-chat-int8', {
  messages: [{ role: 'user', content: `Context: ${context}\n\nQuestion: ${query}` }]
});
```

### AI Gateway Benefits

- Unified analytics across all AI providers
- Request caching (save costs on repeated queries)
- Rate limiting and spend controls
- Safety filters

## Workers vs Pages

**2025 Status:** Pages is in maintenance mode. Workers is the future.

### Decision Matrix

| Use Case | Recommendation |
|----------|---------------|
| New projects | **Workers** with static assets |
| Static sites, blogs | Pages (simpler) or Workers |
| APIs, complex routing | **Workers** |
| SSR apps (Next.js, Astro) | **Workers** |
| Existing JAMstack repos | Pages (if already working) |

### Key Differences

| Aspect | Pages | Workers |
|--------|-------|---------|
| CI/CD | Better built-in Git integration | Workers Builds (improving) |
| Routing | File-based automatic | Use Hono/itty-router |
| Features | Stable, no new development | All new features here |
| Durable Objects | No | Yes |
| Cron Triggers | No | Yes |

**Migration:** Workers now supports static assets directly. New projects should start with Workers.

## Migration to Cloudflare

### Zero-Downtime DNS Migration

**Pre-migration (1 week before):**
1. Lower DNS TTL to 2-5 minutes
2. Export DNS records (BIND format if available)
3. Disable DNSSEC at current registrar
4. Document all records (MX especially critical)

**Migration steps:**
1. Add site to Cloudflare, let it scan DNS records
2. Verify ALL records imported (auto-scan may miss some)
3. Change nameservers at registrar
4. Wait for propagation (check with `dig`)

**Post-migration:**
- Keep old server running 24-48 hours
- Monitor for issues
- Re-enable DNSSEC via Cloudflare

### Cloudflare Proxy Advantage

If using orange-cloud proxy mode, IP changes are instant (Cloudflare controls routing internally).

### Common Pitfalls

| Issue | Solution |
|-------|----------|
| Missing MX records | Email down - verify before switching |
| DNSSEC still enabled | Connectivity errors - disable first |
| Azure NS requirements | Use API/PowerShell to get auth code |
| Smart Tiered Cache + origin change | Expect cache miss spike during refill |

## What's New (2024-2025)

### Major Updates

- **FL2 (Rust rewrite):** Core systems rebuilt in Rust, 10x faster cold starts
- **Workers static assets:** Serve HTML/CSS/JS directly from Workers
- **Vectorize GA:** Expanded index sizes, faster queries
- **Workers Builds:** Open beta, free tier (1 concurrent build)
- **Python support:** Workflows now supports Python
- **R2 event notifications:** GA, event-driven apps

### Coming Soon

- Workers Builds GA with billing (early 2025)
- Tighter Vectorize + Workers AI integration
- SQLite Durable Objects billing (January 2026)

### Deprecations

- Page Rules → Use Cache Rules, Redirect Rules
- `cloudflare_rate_limit` → Use `cloudflare_ruleset`
- Pages new features → Workers is the focus

## References

### Local Reference Files
- [references/zero-trust.md](references/zero-trust.md) - Access policies, service tokens, IdP setup
- [references/tofu-provider.md](references/tofu-provider.md) - OpenTofu resources, HCL examples
- [references/security-patterns.md](references/security-patterns.md) - WAF, bots, DDoS, rate limiting
- [references/cost-optimization.md](references/cost-optimization.md) - Pricing, free tiers, optimization
- [scripts/fetch_prices.py](scripts/fetch_prices.py) - Fetch current pricing from Cloudflare docs

### Official Documentation
- [WAF Managed Rules](https://developers.cloudflare.com/waf/managed-rules/)
- [WAF Custom Rules](https://developers.cloudflare.com/waf/custom-rules/)
- [Rate Limiting Best Practices](https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/)
- [Bot Management](https://developers.cloudflare.com/bots/get-started/bot-management/)
- [DDoS Protection](https://developers.cloudflare.com/ddos-protection/get-started/)
- [Zero Trust Access](https://developers.cloudflare.com/cloudflare-one/policies/access/)
- [Cloudflare Terraform Provider](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs)

### Pricing (use /web-research for current rates)
- [Plans & Pricing](https://www.cloudflare.com/plans/)
- [Workers Pricing](https://developers.cloudflare.com/workers/platform/pricing/)
- [Workers Limits](https://developers.cloudflare.com/workers/platform/limits/)
- [D1 Pricing](https://developers.cloudflare.com/d1/platform/pricing/)
- [R2 Pricing](https://developers.cloudflare.com/r2/pricing/)
