---
name: trends-research
description: "Research trending topics using xAI (Web + X/Twitter) and Reddit. Multi-source synthesis with engagement metrics, intent parsing, and prompt generation. Use for: trend analysis, topic research, social listening, market research, competitive intelligence, prompt discovery. Triggers: trending topics, what's trending, research trends, X trends, Twitter trends, Reddit discussions, social pulse, market trends, find prompts for."
---

# Trends Research

Research trending topics across Reddit, X/Twitter, and the web with engagement-weighted synthesis, intent parsing, and prompt generation.

## Prerequisites

### API Keys Required

| Service | Purpose | Get Key |
|---------|---------|---------|
| xAI | Web + X/Twitter + Reddit (via web search) | https://console.x.ai |

**Note:** Reddit content is accessed via xAI's Web Search - no separate Reddit API key needed.

### Keychain Setup (One-Time)

**Step 1: Create a dedicated keychain**

```bash
# Replace 'YourPassword' with your chosen keychain password
# Use single quotes if password contains special chars like @
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

### Verify Setup

```bash
security find-generic-password -s "xai-api" ~/Library/Keychains/claude-keys.keychain-db
```

### Before Using This Skill

```bash
security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db
```

## Operational Modes

| Mode | Sources | When Used |
|------|---------|-----------|
| **Full** | Reddit + X + Web | All API keys configured |
| **Partial** | X + Web | Only xAI key configured |
| **Web-Only** | Web search only | Fallback when APIs unavailable |

## Depth Control

Control research breadth with depth flags:

| Flag | Sources per Platform | Use Case |
|------|---------------------|----------|
| `--quick` | 8-12 | Fast overview |
| (default) | 20-30 | Balanced research |
| `--deep` | 50-70 | Comprehensive analysis |

```bash
python3 scripts/xai_search.py all "topic" --quick
python3 scripts/xai_search.py all "topic" --deep
```

## Intent Parsing

Extract three variables from user input:

1. **TOPIC** - The subject being researched
2. **TARGET_TOOL** - Optional destination tool (ask after research if unspecified)
3. **QUERY_TYPE** - Determines research approach

### Query Types

| Intent | Trigger Patterns | Example Query |
|--------|------------------|---------------|
| **PROMPTING** | "prompts for", "prompting", "how to prompt" | "Best prompts for Midjourney" |
| **RECOMMENDATIONS** | "best X", "top X", "recommend" | "Best Python libraries for ML" |
| **NEWS** | "latest", "what's happening", "updates" | "Latest OpenAI announcements" |
| **GENERAL** | Everything else | "What's happening in AI?" |

### Pattern Recognition

Recognize common query formats:

```
"[topic] for [tool]" → Extract both topic and target tool
"[topic] prompts for [tool]" → PROMPTING intent with target
"best [topic]" → RECOMMENDATIONS intent
"latest [topic]" → NEWS intent
```

### Intent Detection Workflow

1. Identify the intent type from trigger patterns
2. Extract the core TOPIC
3. Extract TARGET_TOOL if present (e.g., "for Claude", "for Midjourney")
4. If TARGET_TOOL not specified, ask after showing research results
5. Adjust search strategy based on intent

## Research Workflow

### Step 1: Parse Intent

```
Query: "Find the best prompts for using Claude for code review"
Intent: PROMPTING
Topic: code review prompts
Target: Claude
```

### Step 2: Multi-Source Search

Search across all available sources with intent-specific queries:

**Query Templates by Intent:**

| Intent | Search Queries |
|--------|---------------|
| **RECOMMENDATIONS** | `best {TOPIC} recommendations`, `most popular {TOPIC}`, `top {TOPIC} 2026` |
| **NEWS** | `{TOPIC} news 2026`, `{TOPIC} announcement`, `{TOPIC} update` |
| **PROMPTING** | `{TOPIC} prompts examples`, `{TOPIC} techniques tips`, `how to prompt {TOPIC}` |
| **GENERAL** | `{TOPIC} 2026`, `{TOPIC} discussion`, `{TOPIC} explained` |

**Reddit** (via web search):
- Search relevant subreddits (r/ClaudeAI, r/programming, etc.)
- Capture upvote counts and comment engagement
- Prioritize highly-upvoted threads

**X/Twitter**:
- Search posts and threads
- Capture likes, retweets, replies
- Find expert opinions and debates

**Web** (excludes reddit.com, x.com - already covered):
- News articles and blog posts
- Documentation and guides
- GitHub repositories and tutorials

### Step 3: Engagement-Weighted Synthesis

Weight sources by engagement signals:

| Signal | Weight | Rationale |
|--------|--------|-----------|
| Reddit upvotes (100+) | High | Community validated |
| X engagement (50+ likes) | High | Viral/popular |
| Multiple sources agree | High | Cross-platform consensus |
| Recent (< 7 days) | Medium | Fresh but unvalidated |
| Single source | Low | Needs verification |

### Step 4: Generate Output

Based on intent, produce appropriate output:

**For PROMPTING queries:**
- Extract actual prompts from discussions
- Format as copy-paste ready
- Include context on when to use each

**For RECOMMENDATIONS:**
- Create ranked list with pros/cons
- Include community sentiment
- Note controversial choices

**For NEWS:**
- Timeline of events
- Key developments
- Expert reactions

**For GENERAL:**
- Topic overview
- Major themes and debates
- Key resources

## Prompt Generation

After synthesizing research, generate tailored prompts in the format the community recommends:

### Output Formats

| Format | When to Use |
|--------|-------------|
| JSON/structured | API integrations, programmatic use |
| Natural language | Conversational AI, chatbots |
| Keyword lists | Image generation, search |
| System prompts | Agent configuration |

### Prompt Template

```markdown
## Generated Prompt

**For:** [Target tool/platform]
**Intent:** [What this prompt achieves]
**Source:** [Where this pattern was found]

---

[Copy-paste ready prompt here]

---

**Tips from community:**
- [Tip 1]
- [Tip 2]
```

## Expert Mode

After completing research, enter Expert Mode:

- Answer follow-up questions from cached research
- No new searches unless explicitly requested
- Provide deeper analysis on specific findings
- Cross-reference between sources

**Trigger phrases for new research:**
- "Search again for..."
- "Find more about..."
- "Update the research on..."

**Stay in Expert Mode for:**
- "Tell me more about [finding]"
- "Explain the [topic] point"
- "Compare [A] and [B] from the research"

## Search Capabilities

### Reddit Search (via Web Search)

Searches Reddit content through xAI's Web Search:
- Subreddit posts and discussions
- Top comments and threads
- Community recommendations

**Search pattern:** `site:reddit.com [topic]`

**Relevant subreddits by topic:**
- AI/ML: r/MachineLearning, r/artificial, r/ClaudeAI, r/ChatGPT
- Programming: r/programming, r/webdev, r/python
- Tech: r/technology, r/gadgets, r/startups

### X/Twitter Search

Searches X content:
- Posts and threads
- User mentions and hashtags
- Engagement metrics
- Trending topics

### Web Search

Searches general internet:
- News articles
- Blog posts
- Documentation
- Forums

## Output Format

Research results follow a structured sequence:

### 1. Summary Section

Varies by intent:
- **RECOMMENDATIONS**: Ranked list with mention counts and source attribution
- **PROMPTING**: Copy-paste prompts with community tips
- **NEWS**: Timeline of events with key developments
- **GENERAL**: 2-4 sentence synthesis plus identified patterns

### 2. Statistics Section

Display with emoji indicators:

**Full Mode (xAI key configured):**
```
✅ Research complete!
├─ 🟠 Reddit: {n} threads │ {upvotes} upvotes
├─ 🔵 X: {n} posts │ {likes} likes │ {reposts} reposts
├─ 🌐 Web: {n} pages │ {domains}
└─ Top voices: r/{sub1}, r/{sub2} │ @{handle1}, @{handle2}
```

**Web-Only Mode (no xAI key):**
```
✅ Research complete!
├─ 🌐 Web: {n} pages │ {domains}
└─ Top sources: {author1} on {site1}, {author2} on {site2}

🔑 Unlock Reddit & X data: Set up xAI API key in keychain
   Run: security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db
```

### 3. Resources List

Complete list of sources used:

```
📚 Resources:
├─ Reddit:
│  ├─ r/ClaudeAI: "Title of thread" (234 upvotes)
│  ├─ r/programming: "Another thread" (189 upvotes)
│  └─ ...
├─ X/Twitter:
│  ├─ @user1: "Post excerpt..." (89 likes)
│  ├─ @user2: "Another post..." (45 likes)
│  └─ ...
└─ Web:
   ├─ site.com: "Article title"
   ├─ blog.dev: "Another article"
   └─ ...
```

### 4. Invitation Section

After presenting research:
- Ask user for their creative vision or specific use case
- Request TARGET_TOOL if not specified
- Gather context for prompt generation

### 5. Prompt Generation

Only after user shares their vision:
- Write a single, tailored prompt
- Match the format research recommends (JSON, natural language, etc.)
- Include one-line explanation of applied research insight
- Provide 2-3 variations only if explicitly requested

### 6. Output Footer

After each generated prompt, display:

```
📚 Expert in: {TOPIC} for {TARGET_TOOL}
📊 Based on: {n} Reddit threads ({upvotes} upvotes) + {n} X posts ({likes} likes) + {n} web pages

Want another prompt? Just tell me what you're creating next.
```

**Web-Only footer:**
```
📚 Expert in: {TOPIC} for {TARGET_TOOL}
📊 Based on: {n} web pages from {domains}

Want another prompt? Just tell me what you're creating next.

🔑 Unlock Reddit & X data: Set up xAI API key in keychain
```

## Examples

### Prompt Discovery
```
"Find the best prompts for using Claude for code review"

Intent: PROMPTING
Sources: Reddit (r/ClaudeAI), X, Web
Output: Copy-paste prompts with community tips
```

### Tool Recommendations
```
"What are people recommending for Python web frameworks in 2025?"

Intent: RECOMMENDATIONS
Sources: Reddit (r/python, r/webdev), X, Web
Output: Ranked list with community sentiment
```

### News Research
```
"What's the latest on OpenAI's new model?"

Intent: NEWS
Sources: X (breaking news), Web (articles), Reddit (discussion)
Output: Timeline with key developments
```

### General Research
```
"What's happening in the AI agent space?"

Intent: GENERAL
Sources: All platforms
Output: Overview with major themes
```

## Running Searches

Use the bundled script to execute searches:

```bash
# Web search
python3 scripts/xai_search.py web "your search query"

# X/Twitter search
python3 scripts/xai_search.py x "your search query"

# Reddit search (via web search)
python3 scripts/xai_search.py reddit "your search query"

# All sources (Reddit + X + Web)
python3 scripts/xai_search.py all "your search query"
```

## Cost Awareness

**xAI API Pricing:**
- Web Search (includes Reddit): $5 per 1,000 calls ($0.005 each)
- X Search: $5 per 1,000 calls ($0.005 each)
- Plus token costs for Grok processing

**Cost-Saving Tips:**
- Use Expert Mode for follow-ups (no new searches)
- Be specific with queries to reduce iterations
- Combine related research in one session
- Use `site:reddit.com` to target Reddit specifically

## Keychain Management

### Update API Keys

```bash
# Delete old key
security delete-generic-password -s "xai-api" -a "$USER" ~/Library/Keychains/claude-keys.keychain-db

# Add new key
echo -n "Enter new xAI API key: " && read -s key && security add-generic-password -s "xai-api" -a "$USER" -w "$key" ~/Library/Keychains/claude-keys.keychain-db && unset key && echo
```

### Delete Keychain

```bash
security delete-keychain ~/Library/Keychains/claude-keys.keychain-db
```

### Lock Keychain

```bash
security lock-keychain ~/Library/Keychains/claude-keys.keychain-db
```

## Critical Constraints

**DO:**
- Ground synthesis in actual research content, not pre-existing knowledge
- Use exact user terminology in searches (don't substitute related terms)
- Ask about TARGET_TOOL after research if unspecified
- Wait for user's vision before writing prompts
- Cite specific Reddit threads, X posts, and web sources

**DON'T:**
- Display lengthy "Sources:" lists (considered noise)
- Conflate similar product names (e.g., "ClawdBot" vs "Claude Code")
- Quote more than 125 characters from any single source
- Generate multiple prompt variations unless explicitly requested
- Run new searches in Expert Mode unless user asks for different topic

## Troubleshooting

**"SecKeychainSearchCopyNext: item could not be found"**
- API key not stored. Run setup commands above.

**"SecKeychainUnlock: User interaction is not allowed"**
- Keychain locked. Run `security unlock-keychain`.

**xAI API errors**
- Verify key at https://console.x.ai
- Check account has credits/payment method

**Reddit results not appearing**
- Use explicit search: `site:reddit.com [topic]`
- Try specific subreddit: `site:reddit.com/r/python [topic]`

## References

For advanced search patterns, see `references/search-patterns.md`.
