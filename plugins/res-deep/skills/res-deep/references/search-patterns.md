# Search Patterns Reference

Advanced search patterns and operators for multi-source deep research.

## X Search Operators

### Basic Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `from:` | Posts from specific user | `from:elonmusk AI` |
| `to:` | Replies to specific user | `to:OpenAI feedback` |
| `@` | Mentions of user | `@anthropic claude` |
| `#` | Hashtag search | `#MachineLearning` |

### Content Filters

| Operator | Description | Example |
|----------|-------------|---------|
| `filter:links` | Posts with links | `AI news filter:links` |
| `filter:images` | Posts with images | `data viz filter:images` |
| `filter:videos` | Posts with videos | `tutorial filter:videos` |
| `filter:media` | Posts with any media | `product launch filter:media` |

### Engagement Filters

| Operator | Description | Example |
|----------|-------------|---------|
| `min_retweets:N` | Minimum retweets | `AI tools min_retweets:100` |
| `min_faves:N` | Minimum likes | `startup advice min_faves:500` |
| `min_replies:N` | Minimum replies | `tech debate min_replies:50` |

### Boolean Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `AND` | Both terms required | `Python AND machine learning` |
| `OR` | Either term | `GPT-4 OR Claude OR Gemini` |
| `-` | Exclude term | `AI news -crypto` |
| `""` | Exact phrase | `"large language model"` |

### Date Filters

| Operator | Description | Example |
|----------|-------------|---------|
| `since:` | Posts after date | `AI since:2025-01-01` |
| `until:` | Posts before date | `trends until:2025-01-15` |

## Web Search Patterns

### Site-Specific Searches

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:` | Specific domain | `site:github.com machine learning` |
| `-site:` | Exclude domain | `Python tutorial -site:w3schools.com` |

### Content Type

| Pattern | Description | Example |
|---------|-------------|---------|
| `filetype:` | Specific file type | `AI whitepaper filetype:pdf` |
| `intitle:` | Term in page title | `intitle:tutorial Python async` |
| `inurl:` | Term in URL | `inurl:blog AI trends` |

### Freshness

| Pattern | Description | Example |
|---------|-------------|---------|
| Recent news | Add current year or "latest" | `Claude API latest 2026` |
| Historical | Add specific date/year | `AI predictions 2025` |

## GitHub Search Patterns

### Repository Discovery

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:github.com {topic}` | General repo search | `site:github.com vector database` |
| `site:github.com awesome {topic}` | Curated awesome lists | `site:github.com awesome rust` |
| `site:github.com {topic} stars:>1000` | Popular repos (in query text) | `site:github.com "machine learning" stars` |
| `site:github.com {topic} language:{lang}` | Language-specific | `site:github.com orm language:go` |

### Code and Documentation Search

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:github.com {topic} README` | Documentation search | `site:github.com WASM README` |
| `site:github.com {topic} example` | Example code | `site:github.com gRPC example` |
| `site:github.com {topic} tutorial` | Tutorial repos | `site:github.com Kubernetes tutorial` |

### Release and Issue Tracking

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:github.com {repo} releases` | Release notes | `site:github.com "pytorch" releases` |
| `site:github.com {repo} issues` | Issue discussions | `site:github.com "deno" issues` |
| `site:github.com {topic} "breaking change"` | Breaking changes | `site:github.com "next.js" "breaking change"` |

### Filtering Archived Repos

Always exclude archived repositories from results. Archived repos are read-only, unmaintained, and should not be recommended.

- Add `-"archived"` or `-"This repository has been archived"` to web search queries when targeting GitHub
- When using `gh` CLI: `gh search repos {query} --archived=false`
- When evaluating results: skip any repo page showing "This repository has been archived by the owner"

### Activity Signals

When evaluating GitHub results, look for:
- **Not archived:** Repository is actively accepting contributions (archived = exclude)
- **Stars:** Community validation (1000+ = significant adoption)
- **Recent commits:** Active maintenance (commits in last 3 months)
- **Open issues:** Active community (but check ratio of open vs closed)
- **Contributors:** Healthy project (10+ contributors)
- **Forks:** Usage and extension by others

## Hacker News Search Patterns

### Direct Search

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:news.ycombinator.com {topic}` | General HN search | `site:news.ycombinator.com "vector database"` |
| `site:news.ycombinator.com "Show HN" {topic}` | Project launches | `site:news.ycombinator.com "Show HN" rust` |
| `site:news.ycombinator.com "Ask HN" {topic}` | Community questions | `site:news.ycombinator.com "Ask HN" programming language` |

### Thread Type Filters

| Type | What It Contains | When to Use |
|------|-----------------|-------------|
| "Show HN" | Project launches, demos | Finding new tools and projects |
| "Ask HN" | Community questions and advice | Getting diverse opinions |
| Regular submissions | Links to articles, papers | Finding signal-boosted content |
| "Tell HN" | Community announcements | Finding ecosystem changes |

### Quality Signals

- **100+ points:** Strong community interest
- **50+ comments:** Active discussion (read for nuance)
- **Front page:** Validated by community voting
- **Flagged/dead:** Controversial (may still have useful info in comments)

## Technical Blog Targeting

### High-Signal Engineering Blogs

| Domain | Known For | Search Pattern |
|--------|-----------|---------------|
| `blog.cloudflare.com` | Infrastructure, networking, performance | `site:blog.cloudflare.com {topic}` |
| `netflixtechblog.com` | Distributed systems, streaming, ML | `site:netflixtechblog.com {topic}` |
| `engineering.fb.com` | Large-scale systems, React, ML | `site:engineering.fb.com {topic}` |
| `aws.amazon.com/blogs` | Cloud architecture, services | `site:aws.amazon.com/blogs {topic}` |
| `cloud.google.com/blog` | Cloud, AI/ML, Kubernetes | `site:cloud.google.com/blog {topic}` |
| `eng.uber.com` | Microservices, data platforms | `site:eng.uber.com {topic}` |
| `engineering.atspotify.com` | Data pipelines, ML, platforms | `site:engineering.atspotify.com {topic}` |
| `discord.com/blog` | Real-time systems, scaling | `site:discord.com/blog {topic}` |
| `fly.io/blog` | Edge computing, deployment | `site:fly.io/blog {topic}` |
| `vercel.com/blog` | Frontend, edge, DX | `site:vercel.com/blog {topic}` |

### Aggregating Blog Search

```
{topic} site:blog.cloudflare.com OR site:netflixtechblog.com OR site:engineering.fb.com
```

## Multi-Round Query Refinement

### Round 1 → Round 2 Pattern (Broad → Entity-Specific)

Round 1 discovers key entities, names, and themes. Round 2 targets them.

**Round 1 query:** `"vector database comparison 2026"`
**Round 1 discovers:** Pinecone, Weaviate, Qdrant, Milvus, pgvector

**Round 2 queries (generated from Round 1 findings):**
- `"Pinecone vs Weaviate" production experience` (entity-specific comparison)
- `site:reddit.com "qdrant" OR "milvus" experience` (community feedback on discovered entities)
- `site:github.com "pgvector" stars` (GitHub activity for discovered tool)
- `"vector database" benchmark 2026` (verification of performance claims)

### Round 2 → Round 3 Pattern (Claims → Primary Source Verification)

Round 2 surfaces specific claims and data. Round 3 verifies them at the source.

**Round 2 discovers:** "Qdrant claims 10x faster than Milvus on ANN benchmarks"

**Round 3 queries (verification):**
- Direct WebFetch of the benchmark URL cited
- `site:ann-benchmarks.com` for independent benchmark data
- `"qdrant" "milvus" benchmark results` for third-party validation

### Framework-Adapted Targeting

| Framework | Round 2 Focus |
|-----------|---------------|
| COMPARISON | Equal depth per alternative — if Round 1 found more on Alt A than Alt B, target Alt B in Round 2 |
| LANDSCAPE | Fill empty categories — target categories with fewer than 2 players found |
| DECISION | Experience reports — `{option} "in production"`, `{option} "switched from"`, `{option} regret` |
| DEEP_DIVE | "How" and "Limitations" — `"how {topic} works"`, `{topic} limitations OR drawbacks` |

## Cost Optimization

### Reduce API Calls

1. **Be specific** — Narrow queries reduce iterations
2. **Use operators** — Filter upfront, not after
3. **Batch related queries** — Combine when possible

### Example: Inefficient vs Efficient

```bash
# Inefficient (multiple broad queries)
uv run xai_search.py x "AI"
uv run xai_search.py x "AI tools"
uv run xai_search.py x "AI tools 2026"

# Efficient (single targeted query)
uv run xai_search.py x "AI tools 2026 min_faves:100"
```

## Combining Search Types

### Comprehensive Research Flow

1. **Start with Web + Reddit** — Get broad coverage and community sentiment
2. **Add X/Twitter** — Real-time opinions and expert takes
3. **Add GitHub** — Assess actual adoption, code quality, maintenance
4. **Add HN** — Technical depth, contrarian views, historical context
5. **Cross-reference** — Compare social sentiment with code reality

### Query Adaptation by Source

The same topic needs different queries per source:

| Source | Query Style | Example for "AI code review" |
|--------|-------------|------------------------------|
| Web | Formal, article-oriented | `"AI code review tools" comparison 2026` |
| Reddit | Conversational, experience | `site:reddit.com "AI code review" experience recommend` |
| X | Concise, trending | `AI code review min_faves:50` |
| GitHub | Repository-focused | `site:github.com "AI code review" OR "AI PR review"` |
| HN | Technical, opinionated | `site:news.ycombinator.com "AI code review"` |

## Rate Limits

xAI API has rate limits. If you encounter rate limiting:

1. Add delays between requests
2. Reduce query frequency
3. Use more specific queries to get better results per call
