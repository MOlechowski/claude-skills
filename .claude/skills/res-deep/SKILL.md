---
name: res-deep
description: "Iterative multi-round deep research with structured analysis frameworks. Use for: deep research on a topic, compare X vs Y, landscape analysis, evaluate options for a decision, deep dive into a technology, comprehensive research with cross-referencing. Triggers: deep research, compare, landscape, evaluate, deep dive, comprehensive research, which is better, should we use."
---

# Deep Research

Iterative multi-round research across Web, Reddit, X/Twitter, GitHub, and Hacker News with structured output frameworks (comparison, landscape, deep-dive, decision).

## Architecture

| Source | Tool | Cost |
|--------|------|------|
| **Web** | Claude Code `WebSearch` + xAI `web_search` | Free + $0.005/call |
| **Reddit** | Claude Code `WebSearch` (site:reddit.com) + xAI `web_search` | Free + $0.005/call |
| **X/Twitter** | xAI `x_search` only | $0.005/call |
| **GitHub** | Claude Code `WebSearch` (site:github.com) + xAI `web_search` | Free + $0.005/call |
| **Hacker News** | Claude Code `WebSearch` (site:news.ycombinator.com) + xAI `web_search` | Free + $0.005/call |
| **Tech Blogs** | Claude Code `WebSearch` (site-specific) | Free |

Results from multiple sources are **merged and deduplicated** for comprehensive coverage.

## Prerequisites

### Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| uv | Python package manager (handles dependencies) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

### API Keys

| Service | Purpose | Required | Get Key |
|---------|---------|----------|---------|
| xAI | X/Twitter search + supplemental web/GitHub/HN search | Recommended | https://console.x.ai |

**Note:** The skill works without xAI key (web-only mode via Claude Code), but X/Twitter data and broader coverage require xAI.

### Keychain Setup (One-Time, for xAI)

```bash
# 1. Create a dedicated keychain
security create-keychain -p 'YourPassword' ~/Library/Keychains/claude-keys.keychain-db

# 2. Add keychain to search list
security list-keychains -s ~/Library/Keychains/claude-keys.keychain-db ~/Library/Keychains/login.keychain-db /Library/Keychains/System.keychain

# 3. Store your xAI API key
echo -n "Enter xAI API key: " && read -s key && security add-generic-password -s "xai-api" -a "$USER" -w "$key" ~/Library/Keychains/claude-keys.keychain-db && unset key && echo
```

Before using: `security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db`

## Workflow Overview

| Step | Action | Purpose |
|------|--------|---------|
| 0 | Detect xAI key | Determine Full vs Web-Only mode |
| 1 | Parse query | Extract TOPIC, FRAMEWORK, DEPTH |
| 2 | Round 1: Broad search | Discover entities, themes, initial findings |
| 3 | Gap analysis | Identify missing perspectives, unverified claims |
| 4 | Round 2: Targeted follow-up | Fill gaps, verify claims, deepen coverage |
| 5 | Round 3: Verification | (deep only) Primary source verification |
| 6 | Synthesis | Structure findings into framework template |
| 7 | Expert mode | Answer follow-ups from cached results |

## Step 0: Detect xAI Key

**MANDATORY — run before every research session.**

```bash
security find-generic-password -s "xai-api" -w ~/Library/Keychains/claude-keys.keychain-db 2>/dev/null && echo "XAI_AVAILABLE=true" || echo "XAI_AVAILABLE=false"
```

- **XAI_AVAILABLE=true**: Use **Full mode** — Claude WebSearch AND xAI scripts in parallel.
- **XAI_AVAILABLE=false**: Use **Web-Only mode** — Claude WebSearch only. Append note suggesting xAI setup.

This step is NOT optional. Always check before starting research.

## Step 1: Parse Query

Extract from user input:

### 1a. TOPIC

The subject being researched. Strip framework indicators and depth modifiers.

### 1b. FRAMEWORK

Detect output framework from query patterns:

| Framework | Detection Patterns | Example |
|-----------|-------------------|---------|
| COMPARISON | "X vs Y", "compare X and Y", "X or Y", "which is better" | "React vs Vue for enterprise apps" |
| LANDSCAPE | "landscape", "ecosystem", "market", "what's out there", "overview of" | "AI agent frameworks landscape" |
| DEEP_DIVE | "deep dive", "how does X work", "explain", "tell me about", "what is" | "Deep dive into WebAssembly" |
| DECISION | "should I/we", "evaluate", "which should we use", "recommend" | "Should we use Kafka or RabbitMQ?" |

**Explicit override**: User can force a framework with `[comparison]`, `[landscape]`, `[deep-dive]`, or `[decision]` anywhere in query.

**Default**: If no framework detected, use DEEP_DIVE.

### 1c. DEPTH

| Depth | Trigger | Rounds | Target Sources |
|-------|---------|--------|---------------|
| quick | "quick", "brief", "overview" | 1 | 8-12 |
| default | (none) | 2 | 20-30 |
| deep | "deep", "comprehensive", "thorough" | 3 | 50-70 |

## Step 2: Round 1 — Broad Search

### Query Generation

Generate 4-6 queries covering different angles of the TOPIC:

1. **Direct query**: `"{TOPIC}"` — the topic as stated
2. **Temporal query**: `"{TOPIC} 2026"` or `"{TOPIC} latest"`
3. **Reddit query**: `site:reddit.com "{TOPIC}"`
4. **GitHub query**: `site:github.com "{TOPIC}"`
5. **HN query**: `site:news.ycombinator.com "{TOPIC}"`
6. **Framework-specific query**:
   - COMPARISON: `"{Alt A} vs {Alt B}"`
   - LANDSCAPE: `"{TOPIC} ecosystem" OR "{TOPIC} landscape"`
   - DEEP_DIVE: `"how {TOPIC} works" OR "{TOPIC} explained"`
   - DECISION: `"{TOPIC}" experience OR recommendation`

### Parallel Execution

Run searches simultaneously:

**Claude Code (free):**
- `WebSearch`: direct query
- `WebSearch`: temporal query
- `WebSearch`: Reddit-targeted query
- `WebSearch`: GitHub-targeted query
- `WebSearch`: HN-targeted query

**xAI scripts (if available, run as background Bash tasks):**
```bash
uv run scripts/xai_search.py web "{TOPIC}" --json &
uv run scripts/xai_search.py reddit "{TOPIC}" --json &
uv run scripts/xai_search.py x "{TOPIC}" --json &
uv run scripts/xai_search.py github "{TOPIC}" --json &
uv run scripts/xai_search.py hn "{TOPIC}" --json &
```

### Merge and Deduplicate

```
MERGED_WEB = dedupe(claude_web + xai_web)
MERGED_REDDIT = dedupe(claude_reddit + xai_reddit)
MERGED_GITHUB = dedupe(claude_github + xai_github)
MERGED_HN = dedupe(claude_hn + xai_hn)
X_RESULTS = xai_x_results  (no Claude equivalent)
```

Deduplication by URL, keeping the entry with more metadata.

### Round 1 Internal Notes

Record (internally, NOT in output):

```
KEY_ENTITIES: [specific tools, companies, people discovered]
THEMES: [recurring themes across sources]
GAPS: [what's missing — feed into Step 3]
CONTRADICTIONS: [conflicting claims]
LEADS: [URLs worth deep-reading via WebFetch in Round 2]
```

## Step 3: Gap Analysis

After Round 1, run gap analysis. See `references/iterative-research.md` for full checklist.

### Gap Categories

| Gap | Check | Action |
|-----|-------|--------|
| Missing perspective | Have developer, operator, and business views? | Target missing perspective |
| Unverified claims | Any claims from only 1 source? | Seek corroboration |
| Shallow coverage | Any entity mentioned but unexplained? | Deep-search that entity |
| Stale data | Key facts > 12 months old? | Search for recent updates |
| Missing source type | Missing Reddit / GitHub / HN / X / blogs? | Target that platform |

### Plan Round 2

Select top 4-6 gaps. Generate targeted queries for each. See `references/search-patterns.md` for multi-round refinement patterns.

**Skip to Step 6** if depth is `quick` (single round only).

## Step 4: Round 2 — Targeted Follow-Up

### Query Rules

1. **Never repeat Round 1 queries**
2. **Entity-specific queries** — target names/tools discovered in Round 1
3. **Source-type specific** — target platforms underrepresented in Round 1
4. **Framework-adapted** — see targeting table in `references/iterative-research.md`

### Execution

Same parallel pattern as Round 1, but with targeted queries.

**Additionally**, use `WebFetch` for high-value URLs discovered in Round 1:
- Official documentation pages
- Benchmark result pages
- Engineering blog posts
- Comparison articles with methodology

Maximum 4-6 WebFetch calls in Round 2.

### Confidence Update

After Round 2, re-assess all claims:

| Before | New Evidence | After |
|--------|-------------|-------|
| [LOW] | Second source found | [MEDIUM] |
| [MEDIUM] | Third source found | [HIGH] |
| Any | Contradicted | Note conflict, present both sides |

**Skip to Step 6** if depth is `default`.

## Step 5: Round 3 — Verification (Deep Only)

Round 3 is for **verification only**. No new discovery.

### Budget

Maximum 6-10 WebFetch lookups targeting:

| Target | Purpose | Max Calls |
|--------|---------|-----------|
| Primary sources for key claims | Verify accuracy | 3-4 |
| Independent benchmark sites | Validate performance claims | 1-2 |
| Both sides of contradictions | Resolve conflicts | 1-2 |
| Official sites for versions/dates | Confirm recency | 1-2 |

### Rules

1. **Verify, don't discover** — no new topic exploration
2. **Target highest-impact claims** — those that would change the recommendation
3. **Check primary sources** — go to the original, not summaries
4. **Update confidence** — upgrade or downgrade based on findings
5. **Trust primary over secondary** — if primary contradicts secondary, note it

## Step 6: Synthesis

### Framework Selection

Load `references/output-frameworks.md` and select the template matching the detected FRAMEWORK.

### Filling the Template

1. **Header block** — Framework type, topic, depth, source count, date
2. **Core content** — Fill framework sections with research findings
3. **Confidence indicators** — Mark each claim: `[HIGH]`, `[MEDIUM]`, or `[LOW]`
4. **Community perspective** — Synthesize Reddit/X/HN/GitHub sentiment
5. **Statistics footer** — Source counts and engagement metrics
6. **Sources section** — Organized by platform with URLs and metrics

### Engagement-Weighted Synthesis

Weight sources by signal strength. See `references/iterative-research.md` for full weighting table.

| Signal | Threshold | Weight |
|--------|-----------|--------|
| Reddit upvotes | 100+ | High |
| X engagement | 50+ likes | High |
| GitHub stars | 1000+ | High |
| HN points | 100+ | High |
| Multi-platform agreement | 3+ sources | High |
| Dual-engine match | Claude + xAI | High |
| Recent (< 7 days) | Any | Medium |
| Single source only | Any | Low |

### Statistics Footer Format

```
Research Statistics
├─ Reddit: {n} threads │ {upvotes} upvotes
├─ X: {n} posts │ {likes} likes │ {reposts} reposts
├─ GitHub: {n} repos │ {stars} total stars
├─ HN: {n} threads │ {points} total points
├─ Web: {n} pages │ {domains}
├─ Merged: {n} from Claude + {n} from xAI
└─ Top voices: r/{sub1} │ @{handle1} │ {blog1}
```

**Web-Only Mode footer:**
```
Research Statistics
├─ Reddit: {n} threads (via Claude WebSearch)
├─ GitHub: {n} repos (via Claude WebSearch)
├─ HN: {n} threads (via Claude WebSearch)
├─ Web: {n} pages
└─ Top sources: {site1}, {site2}

Add X/Twitter + broader coverage: Set up xAI API key (see Prerequisites)
```

## Step 7: Expert Mode

After delivering research, enter Expert Mode:

- Answer follow-ups from cached results
- No new searches unless explicitly requested
- Cross-reference between sources

**New search triggers** (exit Expert Mode):
- "Search again for..."
- "Find more about..."
- "Update the research..."
- "Look deeper into..."

## Operational Modes

| Mode | Sources | When |
|------|---------|------|
| **Full** | Claude WebSearch + xAI (web + X + Reddit + GitHub + HN) | Step 0 returns XAI_AVAILABLE=true |
| **Web-Only** | Claude WebSearch only | Step 0 returns XAI_AVAILABLE=false |

Mode is determined by Step 0 — never skip it or assume Web-Only without checking.

## Depth Control

| Depth | Rounds | Sources | xAI Calls (Full) | Use Case |
|-------|--------|---------|-------------------|----------|
| quick | 1 | 8-12 | 5 | Fast overview, time-sensitive |
| default | 2 | 20-30 | 10 | Balanced research |
| deep | 3 | 50-70 | 15 + 6-10 WebFetch | Comprehensive analysis, important decisions |

## Cost Awareness

| Action | Cost |
|--------|------|
| Claude Code WebSearch | Free (subscription) |
| xAI search call (any type) | $0.005/call |
| WebFetch (built-in) | Free |

**Estimated cost per research session:**

| Depth | Full Mode | Web-Only |
|-------|-----------|----------|
| quick | ~$0.025 (5 xAI calls) | Free |
| default | ~$0.05 (10 xAI calls) | Free |
| deep | ~$0.075 (15 xAI calls) | Free |

**Cost-Saving Strategy:**
- Claude WebSearch handles most needs (free)
- xAI adds X/Twitter (unique value) + broader coverage per platform
- WebFetch for deep-reading specific URLs (free)

## Critical Constraints

**DO:**
- Run Step 0 (xAI key detection) before every research session
- If xAI key exists: run Claude WebSearch AND xAI scripts in parallel (Full mode)
- If xAI key missing: use Claude WebSearch only (Web-Only mode)
- Run gap analysis between rounds — never skip it
- Merge and deduplicate results by URL
- Mark every claim with confidence: `[HIGH]`, `[MEDIUM]`, or `[LOW]`
- Ground synthesis in actual research, not pre-existing knowledge
- Cite specific sources with URLs
- Use `--json` flag when calling xAI scripts for programmatic parsing
- Load framework template from `references/output-frameworks.md`

**DON'T:**
- Skip Claude Code WebSearch (it's free)
- Run sequential searches when parallel is possible
- Display duplicate results from different search engines
- Quote more than 125 characters from any single source
- Repeat queries across rounds — each round targets gaps from previous
- Add Round 3 for quick or default depth — it's deep-only
- Discover new topics in Round 3 — verification only

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

**No X/Twitter results:** Requires valid xAI API key. Check at https://console.x.ai

**Script errors:** Ensure uv is installed: `which uv`. If missing: `curl -LsSf https://astral.sh/uv/install.sh | sh`

## References

- `references/output-frameworks.md` — Framework templates (comparison, landscape, deep-dive, decision)
- `references/search-patterns.md` — Search operators and multi-round query patterns
- `references/iterative-research.md` — Gap analysis, round procedures, cross-referencing methodology
