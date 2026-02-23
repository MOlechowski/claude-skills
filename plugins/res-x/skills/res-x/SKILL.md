---
name: res-x
description: "Fetch X/Twitter tweet content by URL and search X posts. Resolves tweet links that WebFetch cannot scrape. Use for: reading saved X/Twitter links, fetching tweet content from URLs, searching X for posts on a topic, batch-processing X links from notes. Triggers: x.com link, twitter.com link, fetch tweet, read tweet, what does this tweet say, X search, twitter search."
---

# X/Twitter Fetch & Search

Fetch tweet content by URL and search X posts using xAI Responses API with Grok's `x_search` tool. Solves the problem of X/Twitter blocking WebFetch with "JavaScript disabled" errors.

## Architecture

| Capability | API Tool | Cost |
|-----------|----------|------|
| Fetch tweet by URL | xAI `x_search` | ~$0.005/call |
| Search X | xAI `x_search` | ~$0.005/call |

Fetching batches URLs in groups of 3 per API call to reduce cost.

## Prerequisites

### Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| uv | Python package manager (handles dependencies) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

### API Key

| Service | Purpose | Required | Get Key |
|---------|---------|----------|---------|
| xAI | X/Twitter access via Grok | Yes | https://console.x.ai |

This skill requires an xAI API key. There is no fallback mode.

### Keychain Setup (One-Time)

```bash
# 1. Create a dedicated keychain (skip if already exists)
security create-keychain -p 'YourPassword' ~/Library/Keychains/claude-keys.keychain-db

# 2. Add keychain to search list
security list-keychains -s ~/Library/Keychains/claude-keys.keychain-db ~/Library/Keychains/login.keychain-db /Library/Keychains/System.keychain

# 3. Store your xAI API key
echo -n "Enter xAI API key: " && read -s key && security add-generic-password -s "xai-api" -a "$USER" -w "$key" ~/Library/Keychains/claude-keys.keychain-db && unset key && echo
```

Before using: `security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db`

## Script Usage

```bash
# Fetch single tweet
uv run scripts/x_fetch.py fetch "https://x.com/user/status/123456"

# Fetch multiple tweets (batched, 3 per API call)
uv run scripts/x_fetch.py fetch "url1" "url2" "url3" "url4" "url5"

# Force one-per-URL for max fidelity
uv run scripts/x_fetch.py fetch "url1" "url2" --single

# Search X
uv run scripts/x_fetch.py search "query terms"
uv run scripts/x_fetch.py search "query terms" --quick

# JSON output (both commands)
uv run scripts/x_fetch.py fetch "url" --json
uv run scripts/x_fetch.py search "query" --json
```

## Workflow

### Step 0: Detect xAI Key (Mandatory)

Run before every invocation:

```bash
security find-generic-password -s "xai-api" -w ~/Library/Keychains/claude-keys.keychain-db 2>/dev/null && echo "XAI_AVAILABLE=true" || echo "XAI_AVAILABLE=false"
```

If `XAI_AVAILABLE=false`, report that this skill requires an xAI key and show the keychain setup instructions above.

### Step 1: Detect Intent

- **URLs present** in user input or referenced note -> **fetch**
- **Query text only** -> **search**

### Step 2: Execute

**For fetch:**
1. Extract all X/Twitter URLs from user input or referenced file
2. Run the script with all URLs as arguments
3. The script batches them (3 per API call) automatically

**For search:**
1. Run the script with the search query
2. Use `--quick` for fast overview, omit for deeper results

### Step 3: Present Results

- For fetch: present tweet-by-tweet with full content, engagement, thread/quote context
- For search: present as a list with engagement metrics

## URL Patterns Accepted

```
https://x.com/{user}/status/{id}
https://twitter.com/{user}/status/{id}
https://x.com/{user}/status/{id}?s=20
https://x.com/{user}/status/{id}?t=...&s=...
https://x.com/i/article/{id}
```

Tweets normalized to `https://x.com/{user}/status/{id}`, articles to `https://x.com/i/article/{id}` before processing.

## Batch Processing

For processing saved X links from a file (e.g., Obsidian daily note):

1. Read the file content
2. Extract all X/Twitter URLs (tweets: `https?://(?:x\.com|twitter\.com)/\w+/status/\d+`, articles: `https?://(?:x\.com|twitter\.com)/i/article/[\w\-]+`)
3. Pass all URLs to the script: `uv run scripts/x_fetch.py fetch "url1" "url2" ...`
4. Present results organized by URL

## Cost

| Action | API Calls | Cost |
|--------|-----------|------|
| Fetch 1-3 tweets | 1 | ~$0.005 |
| Fetch 4-6 tweets | 2 | ~$0.010 |
| Fetch 10 tweets | 4 | ~$0.020 |
| Fetch 10 tweets (--single) | 10 | ~$0.050 |
| X search | 1 | ~$0.005 |
| X search (--quick) | 1 | ~$0.005 |

## Constraints

**DO:**
- Run Step 0 before every invocation
- Validate URLs before calling the script
- Use `--json` when parsing results programmatically
- Present full tweet content without truncation

**DON'T:**
- Try WebFetch on X URLs (fails with JS disabled)
- Skip the xAI key check
- Use this for general web search (use `res-web` or `res-deep`)

## Troubleshooting

**xAI key not found:**
```bash
security find-generic-password -s "xai-api" ~/Library/Keychains/claude-keys.keychain-db
```
If not found, run keychain setup above.

**Keychain locked:**
```bash
security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db
```

**Script errors:** Ensure uv is installed: `which uv`
