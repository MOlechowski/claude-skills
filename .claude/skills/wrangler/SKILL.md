---
name: wrangler
description: "Cloudflare Workers/Pages CLI. Use for: deploying Workers, local dev, KV/D1/R2 storage, secrets management. Triggers: wrangler, workers, cloudflare pages, D1, KV."
---

# wrangler

Cloudflare Workers/Pages CLI for building and deploying serverless applications.

## Install

```bash
# Project-local (recommended)
npm install wrangler --save-dev

# Or global
npm install -g wrangler

# Authenticate
npx wrangler login
npx wrangler whoami  # Verify
```

## Project Setup

```bash
# Create new project (interactive)
npm create cloudflare@latest my-worker

# Or with wrangler
npx wrangler init my-worker
```

### wrangler.toml

```toml
name = "my-worker"
main = "src/index.ts"
compatibility_date = "2025-01-01"

# Account/Zone (optional - uses default)
# account_id = "abc123"

# Environment variables
[vars]
API_URL = "https://api.example.com"

# Secrets (set via CLI, not in file)
# wrangler secret put API_KEY

# KV Namespace binding
[[kv_namespaces]]
binding = "MY_KV"
id = "abc123"

# D1 Database binding
[[d1_databases]]
binding = "DB"
database_name = "my-database"
database_id = "abc123"

# R2 Bucket binding
[[r2_buckets]]
binding = "BUCKET"
bucket_name = "my-bucket"

# Environment-specific config
[env.staging]
name = "my-worker-staging"
vars = { API_URL = "https://staging-api.example.com" }

[env.production]
name = "my-worker-production"
```

## Development

```bash
# Local development (resources simulated locally)
npx wrangler dev

# Remote development (connects to real resources)
npx wrangler dev --remote

# Specify port
npx wrangler dev --port 8787

# Use specific environment
npx wrangler dev --env staging
```

## Deployment

```bash
# Deploy to production
npx wrangler deploy

# Deploy to specific environment
npx wrangler deploy --env staging

# Upload version without deploying
npx wrangler versions upload

# Deploy specific version
npx wrangler versions deploy

# Rollback
npx wrangler rollback
```

## Worker Script Structure

### Basic Worker (TypeScript)

```typescript
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/hello") {
      return new Response(JSON.stringify({ message: "Hello!" }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
```

### With KV

```typescript
interface Env {
  MY_KV: KVNamespace;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Read
    const value = await env.MY_KV.get("key");

    // Write
    await env.MY_KV.put("key", "value", { expirationTtl: 3600 });

    // Delete
    await env.MY_KV.delete("key");

    // List keys
    const keys = await env.MY_KV.list({ prefix: "user:" });

    return new Response(value);
  },
};
```

### With D1

```typescript
interface Env {
  DB: D1Database;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Query
    const { results } = await env.DB.prepare(
      "SELECT * FROM users WHERE id = ?"
    ).bind(1).all();

    // Insert
    await env.DB.prepare(
      "INSERT INTO users (name, email) VALUES (?, ?)"
    ).bind("John", "john@example.com").run();

    return Response.json(results);
  },
};
```

## KV Commands

```bash
# Create namespace
npx wrangler kv namespace create MY_KV
npx wrangler kv namespace create MY_KV --preview  # For dev

# List namespaces
npx wrangler kv namespace list

# Key operations
npx wrangler kv key put --namespace-id <id> "key" "value"
npx wrangler kv key get --namespace-id <id> "key"
npx wrangler kv key delete --namespace-id <id> "key"
npx wrangler kv key list --namespace-id <id>

# Bulk operations
npx wrangler kv bulk put --namespace-id <id> data.json
npx wrangler kv bulk delete --namespace-id <id> keys.json
```

## D1 Commands

```bash
# Create database
npx wrangler d1 create my-database

# Execute SQL
npx wrangler d1 execute my-database --command "SELECT * FROM users"
npx wrangler d1 execute my-database --file schema.sql

# Migrations
npx wrangler d1 migrations create my-database create_users
npx wrangler d1 migrations apply my-database
npx wrangler d1 migrations apply my-database --remote

# Export
npx wrangler d1 export my-database --output backup.sql

# Location hints
npx wrangler d1 create my-database --location weur  # Western Europe
# Options: weur, eeur, apac, oc, wnam, enam
```

## R2 Commands

```bash
# Create bucket
npx wrangler r2 bucket create my-bucket

# List buckets
npx wrangler r2 bucket list

# Object operations
npx wrangler r2 object put my-bucket/path/file.txt --file ./local-file.txt
npx wrangler r2 object get my-bucket/path/file.txt
npx wrangler r2 object delete my-bucket/path/file.txt
```

## Secrets

```bash
# Set secret
npx wrangler secret put API_KEY
# Enter value when prompted

# Set for specific environment
npx wrangler secret put API_KEY --env production

# List secrets
npx wrangler secret list

# Delete secret
npx wrangler secret delete API_KEY
```

## Logs and Debugging

```bash
# Stream production logs
npx wrangler tail

# Filter logs
npx wrangler tail --status error
npx wrangler tail --search "error"
npx wrangler tail --ip 1.2.3.4

# Specific environment
npx wrangler tail --env production
```

## Pages

```bash
# Create project
npx wrangler pages project create my-site

# Deploy
npx wrangler pages deploy ./dist

# List deployments
npx wrangler pages deployment list --project-name my-site

# Manage secrets
npx wrangler pages secret put API_KEY --project-name my-site
```
