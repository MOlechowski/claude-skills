# Cloudflare Cost Optimization

## Plan Comparison

| Feature | Free | Pro ($20/mo) | Business ($200/mo) | Enterprise |
|---------|------|--------------|-------------------|------------|
| CDN Bandwidth | Unlimited | Unlimited | Unlimited | Unlimited |
| DDoS Protection | Basic | Advanced | Advanced | Advanced + SLA |
| WAF | - | Managed rules | Custom rules | Full |
| Bot Management | Bot Fight Mode | Super Bot Fight Mode | SBFM + Analytics | Full |
| Support | Community | Email | Priority | Dedicated |
| Image Optimization | - | Polish + Mirage | Polish + Mirage | Full |

## Free Tier Limits

### Core Services (No Credit Card Required)

| Service | Free Limit | Reset |
|---------|-----------|-------|
| CDN | Unlimited bandwidth | - |
| DNS | 1,000 records | - |
| SSL | Universal SSL | - |
| Page Rules | 3 | - |
| DDoS | Always on | - |

### Workers Platform

| Resource | Free Limit | Reset |
|----------|-----------|-------|
| Workers Requests | 100,000/day | Daily at 00:00 UTC |
| Workers CPU | 10ms/invocation | Per request |
| KV Reads | 100,000/day | Daily |
| KV Writes | 1,000/day | Daily |
| D1 Rows Read | 5M/day | Daily |
| D1 Rows Written | 100,000/day | Daily |
| R2 Storage | 10 GB | - |
| R2 Class A ops | 1M/month | Monthly |
| R2 Class B ops | 10M/month | Monthly |
| Pages Builds | 500/month | Monthly |
| Pages Bandwidth | Unlimited | - |

## Workers Paid Plan ($5/month)

Includes all Workers Platform services with higher limits:

| Resource | Paid Limit | Overage |
|----------|-----------|---------|
| Workers Requests | 10M included | $0.30/M |
| Workers CPU | 30ms standard | $0.02/M ms |
| Workers Duration | 30s (Unbound) | Included |
| KV Reads | 10M included | $0.50/M |
| KV Writes | 1M included | $5.00/M |
| KV Storage | 1 GB included | $0.50/GB-mo |
| D1 Rows Read | 25B included | $0.001/M |
| D1 Rows Written | 50M included | $1.00/M |
| D1 Storage | 5 GB included | $0.75/GB-mo |
| R2 Storage | 10 GB included | $0.015/GB-mo |

## Service-Specific Pricing

### Workers

**Billing model:** CPU time (not wall-clock time)

```
Standard: First 10M requests included, then $0.30/M
Unbound:  First 400K GB-s included, then $12.50/M GB-s
```

**CPU time tiers:**
- Standard: Up to 10ms CPU per invocation
- Unbound: Up to 30s CPU per invocation

### D1 (SQLite Database)

| Metric | Free | Paid |
|--------|------|------|
| Rows read | 5M/day | 25B/mo included |
| Rows written | 100K/day | 50M/mo included |
| Storage | 5 GB | 5 GB + $0.75/GB |

**Optimization tip:** Create indexes to reduce rows_read.

### R2 (Object Storage)

| Operation | Price |
|-----------|-------|
| Storage | $0.015/GB-mo |
| Class A (PUT, POST, DELETE) | $4.50/M |
| Class B (GET, HEAD) | $0.36/M |
| Egress | **Free** |

**vs S3:** No egress fees is the key differentiator.

### KV (Key-Value)

| Operation | Price |
|-----------|-------|
| Reads | $0.50/M |
| Writes | $5.00/M |
| Deletes | $5.00/M |
| Storage | $0.50/GB-mo |

### Durable Objects

| Metric | Price |
|--------|-------|
| Requests | $0.15/M |
| Duration | $12.50/M GB-s |
| Storage | $0.20/GB-mo |

### Vectorize (Vector Database)

| Metric | Free | Paid |
|--------|------|------|
| Queried dimensions | 30M/mo | 50M included |
| Stored dimensions | 5M | 10M included |
| Overage | - | $0.01/M queried, $0.05/M stored |

### Stream (Video)

| Metric | Price |
|--------|-------|
| Storage | $5/1000 min stored/mo |
| Delivery | $1/1000 min viewed |

### Images

| Metric | Price |
|--------|-------|
| Storage | $5/100K images/mo |
| Transformations | $1/10K unique transformations |

## Cost Optimization Strategies

### Workers Optimization

1. **Use Service Bindings** between Workers - no extra request fees
2. **Set CPU limits** in wrangler.toml to prevent runaway costs:
   ```toml
   [limits]
   cpu_ms = 50
   ```
3. **Streaming responses** aren't billed as CPU time
4. **Use KV for caching** instead of recomputing

### D1 Optimization

1. **Create indexes** on frequently queried columns
2. **Use prepared statements** for repeated queries
3. **Batch writes** when possible
4. **Scale-to-zero:** No queries = no charges

### R2 Optimization

1. **Use R2 for static assets** - zero egress fees
2. **Lifecycle rules** for auto-deletion of old objects
3. **Prefer Class B operations** (reads) over Class A (writes)

### Caching Optimization

1. **Maximize cache hit ratio:**
   - Set appropriate Cache-Control headers
   - Use Cache Rules instead of origin headers
2. **Enable Tiered Cache** - reduces origin requests
3. **Use Argo Smart Routing** - 30% faster, reduces compute time

### General Strategies

| Strategy | Savings |
|----------|---------|
| Start on Free, upgrade when needed | 100% until limits hit |
| Use Tiered Cache | 40-60% origin reduction |
| R2 instead of S3 | 100% egress savings |
| Workers caching | Variable |
| Right-size CPU limits | Prevent overages |

## Monitoring Costs

### Dashboard

1. Analytics → Workers → Usage
2. R2 → Storage → Usage
3. D1 → Databases → Usage

### Alerts

Set up billing alerts:
1. Account Home → Billing
2. Usage-Based Billing → Set alerts
3. Configure thresholds per service

### API Usage Query

```bash
curl -X GET \
  "https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/account-settings/usage" \
  -H "Authorization: Bearer <token>"
```

## Argo Pricing

Smart Routing improves performance for ~$0.10/GB:

| Traffic Type | Price |
|--------------|-------|
| Argo routing | $5/mo base + $0.10/GB |
| DDoS-mitigated traffic | Not charged |

**ROI calculation:**
- Argo costs ~$0.10/GB
- If latency improvements increase conversion by 1%+, usually worth it
- Test with A/B before committing

## Enterprise Considerations

| Feature | Benefit |
|---------|---------|
| Committed use discounts | 10-30% off |
| Custom contracts | Predictable costs |
| Dedicated support | Faster issue resolution |
| SLAs | Uptime guarantees |

## Cost Comparison: Cloudflare vs AWS

### Static Site Hosting

| | Cloudflare Pages | AWS S3 + CloudFront |
|-|------------------|---------------------|
| Hosting | Free | $0.023/GB storage |
| Bandwidth | Free | $0.085/GB egress |
| Builds | 500/mo free | CodeBuild charges |

### Object Storage (1TB, 10M reads/mo)

| | Cloudflare R2 | AWS S3 |
|-|---------------|--------|
| Storage | $15/mo | $23/mo |
| Requests | $3.60/mo | $4/mo |
| Egress (100GB) | **$0** | $9/mo |
| **Total** | **$18.60** | **$36** |

### Serverless Functions (10M requests/mo)

| | Cloudflare Workers | AWS Lambda |
|-|-------------------|------------|
| Requests | $5 + overage | ~$2/mo |
| Compute | CPU-based | Duration-based |
| Cold starts | Minimal | Variable |
