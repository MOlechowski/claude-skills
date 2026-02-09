---
name: trends-research
description: "Research trending topics using Claude Code WebSearch + xAI (X/Twitter). Multi-source synthesis with merged results, engagement metrics, intent parsing, and prompt generation. Use for: trend analysis, topic research, social listening, market research, competitive intelligence, prompt discovery. Triggers: trending topics, what's trending, research trends, X trends, Twitter trends, Reddit discussions, social pulse, market trends, find prompts for."
---

# Trends Research

Research trending topics across Reddit, X/Twitter, and the web with engagement-weighted synthesis, intent parsing, and prompt generation.

## Architecture

This skill uses a **hybrid search strategy** for maximum coverage:

| Source | Tool | Cost |
|--------|------|------|
| **Web** | Claude Code `WebSearch` + xAI `web_search` | Free + $0.005/call |
| **Reddit** | Claude Code `WebSearch` (site:reddit.com) + xAI `web_search` | Free + $0.005/call |
| **X/Twitter** | xAI `x_search` only | $0.005/call |

Results from multiple sources are **merged and deduplicated** for comprehensive coverage.

## Prerequisites

### Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| uv | Python package manager (handles dependencies) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

### API Keys

| Service | Purpose | Required | Get Key |
|---------|---------|----------|---------|
| xAI | X/Twitter search + supplemental web search | Recommended | https://console.x.ai |

**Note:** The skill works without xAI key (web-only mode via Claude Code), but X/Twitter data requires xAI.

### Keychain Setup (One-Time, for xAI)

**Step 1: Create a dedicated keychain**

```bash
security create-keychain -p 'YourPassword' ~/Library/Keychains/claude-keys.keychain-db
```

**Step 2: Add keychain to search list**

```bash
security list-keychains -s ~/Library/Keychains/claude-keys.keychain-db ~/Library/Keychains/login.keychain-db /Library/Keychains/System.keychain
```

**Step 3: Store your xAI API key**

```bash
echo -n "Enter xAI API key: " && read -s key && security add-generic-password -s "xai-api" -a "$USER" -w "$key" ~/Library/Keychains/claude-keys.keychain-db && unset key && echo
```

### Before Using This Skill

```bash
security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db
```

## Research Workflow

### Step 0: Detect xAI Key (MANDATORY — run before every research session)

Before parsing the query, check if the xAI API key is available:

```bash
security find-generic-password -s "xai-api" -w ~/Library/Keychains/claude-keys.keychain-db 2>/dev/null && echo "XAI_AVAILABLE=true" || echo "XAI_AVAILABLE=false"
```

- If **XAI_AVAILABLE=true**: Use **Full mode** — run Claude WebSearch AND xAI scripts in parallel for every search.
- If **XAI_AVAILABLE=false**: Use **Web-Only mode** — Claude WebSearch only. Append note to output suggesting xAI setup.

This step is NOT optional. Always check before starting research.

### Step 1: Parse User Query

Extract from user input:

1. **TOPIC** - The subject being researched
2. **TARGET_TOOL** - Optional destination tool (ask after research if unspecified)
3. **QUERY_TYPE** - Determines search strategy

### Step 2: Execute Parallel Searches

Run searches in parallel for speed:

**Web Search (merged):**
1. Use Claude Code `WebSearch` tool with query
2. Use xAI `web_search` via script (if key available)
3. Merge and deduplicate results by URL

**Reddit Search (merged):**
1. Use Claude Code `WebSearch` with `site:reddit.com {query}`
2. Use xAI `web_search` via script with Reddit focus (if key available)
3. Merge and deduplicate by thread URL

**X/Twitter Search:**
1. Use xAI `x_search` via script (requires key)
2. No Claude Code equivalent for X data

### Step 3: Merge Results

For each source type, merge results:

```
MERGED_WEB = dedupe(claude_web_results + xai_web_results)
MERGED_REDDIT = dedupe(claude_reddit_results + xai_reddit_results)
X_RESULTS = xai_x_results
```

Deduplication by URL, keeping the entry with more metadata.

### Step 4: Synthesize

Weight sources by engagement:

| Signal | Weight | Rationale |
|--------|--------|-----------|
| Reddit upvotes (100+) | High | Community validated |
| X engagement (50+ likes) | High | Viral/popular |
| Multiple sources agree | High | Cross-platform consensus |
| Found by both search engines | High | Validated coverage |
| Recent (< 7 days) | Medium | Fresh but unvalidated |
| Single source | Low | Needs verification |

## Operational Modes

| Mode | Sources | When |
|------|---------|------|
| **Full** | Claude WebSearch + xAI (web + X) | Step 0 returns XAI_AVAILABLE=true |
| **Web-Only** | Claude WebSearch only | Step 0 returns XAI_AVAILABLE=false |

Mode is determined by Step 0 — never skip it or assume Web-Only without checking.

## Intent Parsing

### Query Types

| Intent | Trigger Patterns | Example |
|--------|------------------|---------|
| **PROMPTING** | "prompts for", "how to prompt" | "Best prompts for Midjourney" |
| **RECOMMENDATIONS** | "best X", "top X", "recommend" | "Best Python libraries for ML" |
| **NEWS** | "latest", "what's happening" | "Latest OpenAI announcements" |
| **GENERAL** | Everything else | "What's happening in AI?" |

### Query Templates by Intent

| Intent | Search Queries |
|--------|---------------|
| **RECOMMENDATIONS** | `best {TOPIC}`, `top {TOPIC} 2026`, `{TOPIC} recommendations` |
| **NEWS** | `{TOPIC} news 2026`, `{TOPIC} announcement`, `{TOPIC} update` |
| **PROMPTING** | `{TOPIC} prompts`, `{TOPIC} techniques`, `how to prompt {TOPIC}` |
| **GENERAL** | `{TOPIC} 2026`, `{TOPIC} discussion`, `{TOPIC} trends` |

## Executing Searches

### Claude Code WebSearch (Built-in)

Use the `WebSearch` tool directly:

```
WebSearch: "AI agents trends 2026"
WebSearch: "site:reddit.com AI agents discussion"
```

### xAI Search Script

For X/Twitter and supplemental web search:

```bash
# X/Twitter only
uv run scripts/xai_search.py x "AI agents"

# Web search (supplements Claude Code)
uv run scripts/xai_search.py web "AI agents"

# Reddit (supplements Claude Code)
uv run scripts/xai_search.py reddit "AI agents"
```

### Parallel Execution Example

For a query like "What's trending in AI agents?":

1. **Step 0**: Check xAI key availability (mandatory, always first)

2. **Parallel batch** (run simultaneously — Full mode):
   - Claude Code `WebSearch`: "AI agents trends 2026"
   - Claude Code `WebSearch`: "site:reddit.com AI agents"
   - xAI script: `x "AI agents"` (background)
   - xAI script: `web "AI agents"` (background)

3. **Merge phase**: Combine results, dedupe by URL

4. **Synthesis phase**: Weight by engagement, generate summary

## Depth Control

| Flag | Sources per Platform | Use Case |
|------|---------------------|----------|
| `--quick` | 8-12 | Fast overview |
| (default) | 20-30 | Balanced research |
| `--deep` | 50-70 | Comprehensive analysis |

## Output Format

### 1. Summary Section

Varies by intent:
- **RECOMMENDATIONS**: Ranked list with mention counts
- **PROMPTING**: Copy-paste prompts with tips
- **NEWS**: Timeline of events
- **GENERAL**: 2-4 sentence synthesis

### 2. Statistics Section

```
✅ Research complete!
├─ 🟠 Reddit: {n} threads │ {upvotes} upvotes
├─ 🔵 X: {n} posts │ {likes} likes │ {reposts} reposts
├─ 🌐 Web: {n} pages │ {domains}
├─ 🔀 Merged: {n} from Claude + {n} from xAI
└─ Top voices: r/{sub1}, r/{sub2} │ @{handle1}, @{handle2}
```

**Web-Only Mode:**
```
✅ Research complete!
├─ 🟠 Reddit: {n} threads (via Claude WebSearch)
├─ 🌐 Web: {n} pages
└─ Top sources: {site1}, {site2}

🔑 Add X/Twitter data: Set up xAI API key
```

### 3. Resources List

```
📚 Resources:
├─ Reddit:
│  ├─ r/ClaudeAI: "Thread title" (234 upvotes)
│  └─ ...
├─ X/Twitter:
│  ├─ @user1: "Post excerpt..." (89 likes)
│  └─ ...
└─ Web:
   ├─ site.com: "Article title"
   └─ ...
```

### 4. Output Footer

```
📚 Expert in: {TOPIC} for {TARGET_TOOL}
📊 Based on: {n} Reddit + {n} X posts + {n} web pages

Want another prompt? Just tell me what you're creating next.
```

## Expert Mode

After research, enter Expert Mode:

- Answer follow-ups from cached results
- No new searches unless explicitly requested
- Cross-reference between sources

**New search triggers:**
- "Search again for..."
- "Find more about..."
- "Update the research..."

## Cost Awareness

| Source | Cost |
|--------|------|
| Claude Code WebSearch | Free (subscription) |
| xAI Web Search | $0.005/call |
| xAI X Search | $0.005/call |

**Cost-Saving Strategy:**
- Claude Code WebSearch handles most web/Reddit needs (free)
- xAI adds X/Twitter data (paid, unique value)
- xAI web search supplements for broader coverage (optional)

## Critical Constraints

**DO:**
- Run Step 0 (xAI key detection) before every research session — this is mandatory
- If xAI key exists: run Claude WebSearch AND xAI scripts in parallel (Full mode)
- If xAI key missing: use Claude WebSearch only (Web-Only mode)
- Merge and deduplicate results by URL
- Ground synthesis in actual research, not pre-existing knowledge
- Cite specific sources with URLs

**DON'T:**
- Skip Claude Code WebSearch (it's free)
- Run sequential searches when parallel is possible
- Display duplicate results from different search engines
- Quote more than 125 characters from any single source

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

**No X/Twitter results:**
- Requires valid xAI API key
- Check key at https://console.x.ai

## References

For advanced search patterns, see `references/search-patterns.md`.
