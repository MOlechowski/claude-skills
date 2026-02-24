---
name: cli-web-scrape
description: "Scrapling CLI wrapper for web scraping with browser impersonation, stealth headers, CSS selectors, Cloudflare bypass, and JS rendering. Three fetcher tiers: HTTP (fast), Dynamic (Playwright), Stealthy (Camoufox). Output as HTML, Markdown, or text. Use when: scraping web pages, extracting content with CSS selectors, bypassing anti-bot protection, fetching JS-rendered pages. Triggers: scrape, scrapling, web scraping, extract page, fetch page content, bypass cloudflare."
---

# Scrapling CLI

Web scraping CLI with browser impersonation, anti-bot bypass, and CSS extraction.

## Prerequisites

```bash
# Install with all extras (CLI needs click, fetchers need playwright/camoufox)
uv tool install 'scrapling[all]'

# Install fetcher browser engines (one-time)
scrapling install
```

Verify: `scrapling --help`

## Fetcher Selection

| Tier | Command | Engine | Speed | Stealth | JS | Use When |
|------|---------|--------|-------|---------|----|----|
| **HTTP** | `extract get/post/put/delete` | httpx + TLS impersonation | Fast | Medium | No | Static pages, APIs, most sites |
| **Dynamic** | `extract fetch` | Playwright (headless browser) | Medium | Low | Yes | JS-rendered SPAs, wait-for-element |
| **Stealthy** | `extract stealthy-fetch` | Camoufox (patched Firefox) | Slow | High | Yes | Cloudflare, aggressive anti-bot |

**Default to HTTP tier** — only escalate when the page requires JS rendering or blocks HTTP requests.

## Output Format

Determined by output file extension:

| Extension | Output | Best For |
|-----------|--------|----------|
| `.html` | Raw HTML | Parsing, further processing |
| `.md` | HTML converted to Markdown | Reading, LLM context |
| `.txt` | Text content only | Clean text extraction |

Always use `/tmp/scrapling-*.{md,txt,html}` for output files. Read the file after extraction.

## Core Commands

### HTTP Tier: GET

```bash
scrapling extract get URL OUTPUT_FILE [OPTIONS]
```

| Flag | Purpose | Example |
|------|---------|---------|
| `-s, --css-selector` | Extract matching elements only | `-s ".article-body"` |
| `--impersonate` | Force specific browser | `--impersonate firefox` |
| `-H, --headers` | Custom headers (repeatable) | `-H "Authorization: Bearer tok"` |
| `--cookies` | Cookie string | `--cookies "session=abc123"` |
| `--proxy` | Proxy URL | `--proxy "http://user:pass@host:port"` |
| `-p, --params` | Query params (repeatable) | `-p "page=2" -p "limit=50"` |
| `--timeout` | Seconds (default: 30) | `--timeout 60` |
| `--no-verify` | Skip SSL verification | For self-signed certs |
| `--no-follow-redirects` | Don't follow redirects | For redirect inspection |
| `--no-stealthy-headers` | Disable stealth headers | For debugging |

Examples:

```bash
# Basic page fetch as markdown
scrapling extract get "https://example.com" /tmp/scrapling-out.md

# Extract only article content
scrapling extract get "https://news.site.com/article" /tmp/scrapling-out.txt -s "article"

# Multiple CSS selectors
scrapling extract get "https://hn.com" /tmp/scrapling-out.txt -s ".titleline > a"

# With auth header
scrapling extract get "https://api.example.com/data" /tmp/scrapling-out.txt -H "Authorization: Bearer TOKEN"

# Impersonate Firefox
scrapling extract get "https://example.com" /tmp/scrapling-out.md --impersonate firefox

# Random browser impersonation from list
scrapling extract get "https://example.com" /tmp/scrapling-out.md --impersonate "chrome,firefox,safari"

# With proxy
scrapling extract get "https://example.com" /tmp/scrapling-out.md --proxy "http://proxy:8080"
```

### HTTP Tier: POST

```bash
scrapling extract post URL OUTPUT_FILE [OPTIONS]
```

Additional options over GET:

| Flag | Purpose | Example |
|------|---------|---------|
| `-d, --data` | Form data | `-d "param1=value1&param2=value2"` |
| `-j, --json` | JSON body | `-j '{"key": "value"}'` |

```bash
# POST with form data
scrapling extract post "https://api.example.com/search" /tmp/scrapling-out.txt -d "q=test&page=1"

# POST with JSON
scrapling extract post "https://api.example.com/query" /tmp/scrapling-out.txt -j '{"query": "test"}'
```

PUT and DELETE share the same interface as POST and GET respectively.

### Dynamic Tier: fetch

For JS-rendered pages. Launches headless Playwright browser.

```bash
scrapling extract fetch URL OUTPUT_FILE [OPTIONS]
```

| Flag | Purpose | Default |
|------|---------|---------|
| `--headless/--no-headless` | Headless mode | True |
| `--disable-resources` | Drop images/CSS/fonts for speed | False |
| `--network-idle` | Wait for network idle | False |
| `--timeout` | Milliseconds | 30000 |
| `--wait` | Extra wait after load (ms) | 0 |
| `-s, --css-selector` | CSS selector extraction | — |
| `--wait-selector` | Wait for element before proceeding | — |
| `--real-chrome` | Use installed Chrome instead of bundled | False |
| `--proxy` | Proxy URL | — |
| `-H, --extra-headers` | Extra headers (repeatable) | — |

```bash
# Fetch JS-rendered SPA
scrapling extract fetch "https://spa-app.com" /tmp/scrapling-out.md

# Wait for specific element to load
scrapling extract fetch "https://dashboard.com" /tmp/scrapling-out.md --wait-selector ".data-table"

# Fast mode: skip images/CSS, wait for network idle
scrapling extract fetch "https://app.com" /tmp/scrapling-out.md --disable-resources --network-idle

# Extra wait for slow-loading content
scrapling extract fetch "https://lazy-site.com" /tmp/scrapling-out.md --wait 5000
```

### Stealthy Tier: stealthy-fetch

Maximum anti-detection. Uses Camoufox (patched Firefox).

```bash
scrapling extract stealthy-fetch URL OUTPUT_FILE [OPTIONS]
```

Additional options over `fetch`:

| Flag | Purpose | Default |
|------|---------|---------|
| `--solve-cloudflare` | Solve Cloudflare challenges | False |
| `--block-webrtc` | Block WebRTC (prevents IP leak) | False |
| `--hide-canvas` | Add noise to canvas fingerprinting | False |
| `--block-webgl` | Block WebGL fingerprinting | False (allowed) |

```bash
# Bypass Cloudflare
scrapling extract stealthy-fetch "https://cf-protected.com" /tmp/scrapling-out.md --solve-cloudflare

# Maximum stealth
scrapling extract stealthy-fetch "https://aggressive-antibot.com" /tmp/scrapling-out.md \
  --solve-cloudflare --block-webrtc --hide-canvas --block-webgl

# Stealthy with CSS selector
scrapling extract stealthy-fetch "https://protected.com" /tmp/scrapling-out.txt \
  --solve-cloudflare -s ".content"
```

## Auto-Escalation Protocol

**ALL scrapling usage must follow this protocol.** Never use `extract get` alone — always validate content and escalate if needed. Consumer skills (res-deep, res-price-compare, doc-daily-digest) MUST use this pattern, not a bare `extract get`.

### Step 1: HTTP Tier

```bash
scrapling extract get "URL" /tmp/scrapling-out.md
```

Read `/tmp/scrapling-out.md` and **validate content** before proceeding.

### Step 2: Validate Content

Check the scraped output for **thin content indicators** — signs that the site requires JS rendering:

| Indicator | Pattern | Example |
|-----------|---------|---------|
| JS disabled warning | "JavaScript", "enable JavaScript", "JS wyłączony" | iSpot.pl, many SPAs |
| No product/price data | Output has navigation and footer but no prices, specs, or product names | E-commerce SPAs |
| Mostly nav links | 80%+ of content is menu items, category links, cookie banners | React/Angular/Vue apps |
| Very short content | Less than ~20 meaningful lines after stripping nav/footer | Hydration-dependent pages |
| Login/loading wall | "Loading...", "Please wait", skeleton UI text | Dashboard apps |

**If ANY indicator is present → escalate to Dynamic tier.** Do NOT treat HTTP 200 with thin content as success.

### Step 3: Dynamic Tier (if content validation fails)

```bash
scrapling extract fetch "URL" /tmp/scrapling-out.md --network-idle --disable-resources
```

Read and validate again. If content is now rich → done. If still blocked (403, Cloudflare challenge, empty) → escalate.

### Step 4: Stealthy Tier (if Dynamic tier fails)

```bash
scrapling extract stealthy-fetch "URL" /tmp/scrapling-out.md --solve-cloudflare
```

If still blocked, add maximum stealth flags:
```bash
scrapling extract stealthy-fetch "URL" /tmp/scrapling-out.md \
  --solve-cloudflare --block-webrtc --hide-canvas --block-webgl
```

### Consumer Skill Integration

When a consumer skill says "retry with scrapling" or "scrapling fallback", it means: **follow the full auto-escalation protocol above**, not just the HTTP tier. The pattern:

1. `extract get` → Read → Validate content
2. Content thin? → `extract fetch --network-idle --disable-resources` → Read → Validate
3. Still blocked? → `extract stealthy-fetch --solve-cloudflare` → Read
4. All tiers fail? → Skip and label "scrapling blocked"

**Known JS-rendered sites** (always start at Dynamic tier):
- iSpot.pl — React SPA, HTTP tier returns only nav shell
- Single-page apps with client-side routing (hash or history API URLs)

## Interactive Shell

```bash
# Launch REPL
scrapling shell

# One-liner evaluation
scrapling shell -c 'Fetcher().get("https://example.com").css("title::text")'
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: click` | Reinstall: `uv tool install --force 'scrapling[all]'` |
| fetch/stealthy-fetch fails | Run `scrapling install` to install browser engines |
| Cloudflare still blocks | Add `--block-webrtc --hide-canvas` to stealthy-fetch |
| Timeout | Increase `--timeout` (seconds for HTTP, milliseconds for fetch/stealthy) |
| SSL error | Add `--no-verify` (HTTP tier only) |
| Empty output with selector | Try without `-s` first to verify page loads, then refine selector |

## Constraints

- Output file path is required — scrapling writes to file, not stdout
- CSS selectors return ALL matches concatenated
- HTTP tier timeout is in **seconds**, fetch/stealthy-fetch timeout is in **milliseconds**
- `--impersonate` only available on HTTP tier (fetch/stealthy handle it internally)
- `--solve-cloudflare` only on stealthy-fetch tier
- Stealth headers enabled by default on HTTP tier — disable with `--no-stealthy-headers` for debugging
