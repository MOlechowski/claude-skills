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
| `related:` | Sites Google considers similar — discovers competitors and alternatives you didn't know to search for | `related:pinecone.io` |
| `cache:` | Google's cached version of a page — bypasses paywalls and blocks without needing scrapling | `cache:example.com/paywalled-article` |

### Content Type

| Pattern | Description | Example |
|---------|-------------|---------|
| `filetype:` | Specific file type | `AI whitepaper filetype:pdf` |
| `intitle:` | One term must appear in page title | `intitle:benchmark vector database` |
| `allintitle:` | ALL terms must appear in page title — stricter than `intitle:`, filters tangential results | `allintitle:vector database benchmark 2026` |
| `inurl:` | One term must appear in URL | `inurl:blog AI trends` |
| `allinurl:` | ALL terms must appear in URL — targets official docs and primary sources by URL structure | `allinurl:api docs v2 reference` |

### Date Filtering

| Pattern | Description | Example |
|---------|-------------|---------|
| `after:YYYY-MM-DD` | Results published after date | `"AI agents" after:2025-06-01` |
| `before:YYYY-MM-DD` | Results published before date | `"GPT-4" before:2025-01-01` |
| Combined range | Exact time window — far more precise than appending year | `"vector database" after:2025-09-01 before:2026-03-01` |
| Year append | Quick freshness hint when exact dates aren't needed | `Claude API latest 2026` |

### Discovery Operators

| Pattern | Description | Example |
|---------|-------------|---------|
| `AROUND(N)` | Terms must appear within N words of each other — finds focused discussions, not pages that merely mention both terms | `"vector database" AROUND(3) "benchmark"` |
| `*` wildcard | Fill-in-the-blank — discovers unknown entities and alternatives | `"best * for machine learning"`, `"switched from Kafka to *"` |
| `$X..$Y` range | Numeric range filter — useful for financial research | `"funding $10..$50 million" AI startup` |
| `(X OR Y)` grouping | Boolean groups — multi-option queries in one search | `(React OR Vue OR Svelte) "state management" 2026` |

### Noise Reduction

Stack `-site:` to exclude SEO spam and low-signal domains from results:

```
{topic} -site:pinterest.com -site:quora.com -site:w3schools.com -site:geeksforgeeks.org
```

Common noise sources to exclude by research type:

| Research Type | Exclude |
|---------------|---------|
| Technical/programming | `-site:w3schools.com -site:geeksforgeeks.org -site:tutorialspoint.com` |
| Product/tool research | `-site:pinterest.com -site:quora.com -site:g2.com` |
| Financial research | `-site:pinterest.com -site:investopedia.com` (basic definitions, not analysis) |

### Operator Composition

Stack operators for precision targeting. Order doesn't matter.

| Combination | Purpose | Example |
|-------------|---------|---------|
| `site:` + `intitle:` | Focused topic on specific platform | `site:reddit.com intitle:"vs" "React" "Vue"` |
| `site:` + `after:` | Recent content from specific source | `site:news.ycombinator.com "AI agents" after:2025-10-01` |
| `allintitle:` + `after:` | Precision + freshness | `allintitle:qdrant milvus benchmark after:2025-06-01` |
| `related:` + `intitle:` | Competitor discovery + topic filter | Search `related:pinecone.io`, then `intitle:pricing` on discovered domains |
| `AROUND()` + `site:` | Proximity search on specific platform | `site:reddit.com "kubernetes" AROUND(5) "nightmare"` |

### When to Use Which

| Research Phase | Best Operators | Why |
|----------------|---------------|-----|
| Round 1 (broad) | `site:`, `""`, `OR`, year append | Cast wide net, discover entities |
| Round 2 (targeted) | `allintitle:`, `AROUND()`, `*`, `after:`/`before:`, `related:` | Fill gaps, find specific discussions |
| Round 3 (verify) | `allinurl:`, `cache:`, `allintitle:` + `after:` | Hit primary sources, bypass blocks |
| LANDSCAPE gaps | `related:` | Discover competitors Google knows about |
| Paywall bypass | `cache:` | Free fallback before scrapling |

## Google Scholar Patterns

### Academic Paper Discovery

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:scholar.google.com "{topic}"` | General academic search | `site:scholar.google.com "retrieval augmented generation"` |
| `site:arxiv.org "{topic}"` | Preprints and working papers | `site:arxiv.org "mixture of experts"` |
| `site:arxiv.org "{topic}" abs` | Abstract pages specifically | `site:arxiv.org "RLHF" abs` |
| `"{topic}" filetype:pdf site:*.edu` | University research papers | `"transformer architecture" filetype:pdf site:*.edu` |
| `"{topic}" filetype:pdf site:*.ac.uk` | UK academic papers | `"reinforcement learning" filetype:pdf site:*.ac.uk` |

### When to Use

- DEEP_DIVE on technical topics — find the original paper behind a technique
- Verification round — confirm claims with primary academic sources
- COMPARISON framework — find benchmark papers that tested alternatives head-to-head

### Quality Signals

- **Citation count:** 100+ = established work, 1000+ = landmark paper
- **Recent papers citing it:** Active research area if cited in last 12 months
- **Author affiliation:** Google Brain, DeepMind, Meta AI, university labs = high signal
- **Conference venue:** NeurIPS, ICML, ACL, CVPR = peer-reviewed quality

### Limitations

- Scholar results via WebSearch give titles/snippets only — use WebFetch on arxiv.org abstract pages for full content
- PDFs from university sites are often accessible via WebFetch; conference proceedings may be paywalled

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

## Substack Search Patterns

### Article Discovery

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:substack.com "{topic}"` | General Substack search | `site:substack.com "AI agents"` |
| `site:*.substack.com "{topic}"` | Include custom subdomain newsletters | `site:*.substack.com "machine learning"` |
| `site:substack.com "{author}"` | Author search | `site:substack.com "Alap Shah"` |
| `"{topic}" substack comments reaction` | Find discussions and reactions | `"AI crisis" substack comments` |

### Quality Signals

- **Subscriber count:** 10K+ = established newsletter
- **Likes/hearts:** 50+ = high engagement for the platform
- **Comment sections:** Active comments often contain expert counter-arguments
- **Cross-posting:** Articles shared on X/HN/Reddit = validated content

### Limitations

- Many Substacks are paywalled — WebFetch may only get preview content. If blocked, try scrapling fallback: `scrapling extract get "URL" /tmp/scrapling-fallback.md`
- `open.substack.com` URLs redirect to author subdomains — follow redirects

## Financial Media Search Patterns

### Site-Specific Searches

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:tradingview.com "{topic}"` | TradingView analysis and ideas | `site:tradingview.com "AI stocks"` |
| `site:seekingalpha.com "{topic}"` | Seeking Alpha analysis | `site:seekingalpha.com "AI disruption"` |
| `site:benzinga.com "{topic}"` | Benzinga news and analysis | `site:benzinga.com "AI jobs"` |
| `site:wallstreetoasis.com "{topic}"` | WSO forum threads | `site:wallstreetoasis.com "AI banking"` |
| `site:invezz.com "{topic}"` | Invezz market analysis | `site:invezz.com "AI market"` |

### Aggregating Financial Search

```
{topic} site:seekingalpha.com OR site:benzinga.com OR site:tradingview.com
```

### Quality Signals

- **Seeking Alpha:** Comment count, author track record, PRO-only articles tend to be higher quality
- **WSO:** Monkey points, replies from verified professionals, "Most Helpful" tags
- **TradingView:** Ideas with chart analysis and community votes
- **Benzinga:** Analyst ratings, earnings data references

### Limitations

- Seeking Alpha articles are often paywalled — WebFetch gets preview only. Try scrapling fallback: `scrapling extract get "URL" /tmp/scrapling-fallback.md`
- WSO returns 403 on WebFetch — try scrapling fallback: `scrapling extract get "URL" /tmp/scrapling-fallback.md`, then read `/tmp/scrapling-fallback.md`. Fall back to WebSearch snippets if scrapling also fails
- TradingView ideas are heavy on charts (not extractable via WebFetch or scrapling)

## LinkedIn Search Patterns

### Profile and Content Searches

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:linkedin.com/in/ "{name}"` | Person profile | `site:linkedin.com/in/ "Alap Shah"` |
| `site:linkedin.com/company/ "{org}"` | Company page | `site:linkedin.com/company/ "Anthropic"` |
| `site:linkedin.com/pulse/ "{topic}"` | LinkedIn articles | `site:linkedin.com/pulse/ "AI jobs"` |
| `site:linkedin.com/posts/ "{topic}"` | LinkedIn posts | `site:linkedin.com/posts/ "AI disruption"` |

### Quality Signals

- **Connections/followers:** 500+ connections = established professional
- **Article engagement:** Likes and comments on Pulse articles
- **Verified badges:** Company pages with verified status

### Limitations

- WebFetch to LinkedIn usually fails (requires JavaScript/authentication). Try scrapling fallback: `scrapling extract get "URL" /tmp/scrapling-fallback.md` -- scrapling handles JavaScript rendering
- If scrapling also fails, use WebSearch snippets only — do not attempt further deep-reading of LinkedIn URLs
- Profile data from search snippets is often sufficient for author background checks

## Crunchbase Search Patterns

### Entity Discovery

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:crunchbase.com/person/ "{name}"` | Person profile | `site:crunchbase.com/person/ "Sam Altman"` |
| `site:crunchbase.com/organization/ "{org}"` | Company profile | `site:crunchbase.com/organization/ "anthropic"` |
| `"{name}" crunchbase investments advisory` | Investment activity | `"Marc Andreessen" crunchbase investments` |

### Quality Signals

- **Funding rounds:** Series stage, amounts, investors
- **Board members:** Advisory and board roles reveal incentive structures
- **Acquisitions:** M&A activity shows strategic interests

### Limitations

- Crunchbase paywalls detailed data — WebSearch snippets give basics (funding, HQ, employee count)
- WebFetch may hit paywall for full profiles. Try scrapling fallback: `scrapling extract get "URL" /tmp/scrapling-fallback.md`

## YouTube Search Patterns

### Video Discovery

| Pattern | Description | Example |
|---------|-------------|---------|
| `site:youtube.com "{topic}"` | General video search | `site:youtube.com "AI job displacement"` |
| `site:youtube.com "{topic}" reaction OR review` | Reaction/review videos | `site:youtube.com "AI crisis" reaction` |
| `site:youtube.com "{topic}" explained` | Explainer videos | `site:youtube.com "METR benchmark" explained` |
| `site:youtube.com "{topic}" interview` | Interview clips | `site:youtube.com "AI safety" interview` |

### Quality Signals

- **View count:** 10K+ = notable reach
- **Like ratio:** High like-to-dislike = community approval
- **Comment count:** 100+ = active discussion
- **Channel subscribers:** 100K+ = established creator

### Limitations

- WebFetch cannot extract video content — only metadata, descriptions, and comments. Scrapling fallback has the same limitation for video content
- Use WebSearch snippets for video titles, view counts, and descriptions
- Transcripts are not available via standard web fetching

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
- Direct WebFetch of the benchmark URL cited (use scrapling fallback if blocked)
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
5. **Add Substack** — Long-form analysis, newsletter perspectives, counter-arguments
6. **Add Financial Media** — Market impact, professional investor views (for finance/economics topics)
7. **Add LinkedIn** — Author backgrounds, company profiles, professional credibility
8. **Add YouTube** — Video reactions, explainers, interviews
9. **Cross-reference** — Compare social sentiment with code reality and financial data

### Query Adaptation by Source

The same topic needs different queries per source:

| Source | Query Style | Example for "AI code review" |
|--------|-------------|------------------------------|
| Web | Formal, article-oriented | `"AI code review tools" comparison 2026` |
| Reddit | Conversational, experience | `site:reddit.com "AI code review" experience recommend` |
| X | Concise, trending | `AI code review min_faves:50` |
| GitHub | Repository-focused | `site:github.com "AI code review" OR "AI PR review"` |
| HN | Technical, opinionated | `site:news.ycombinator.com "AI code review"` |
| Substack | Long-form, analytical | `site:substack.com "AI code review"` |
| Financial | Market-impact oriented | `site:seekingalpha.com "AI code review" market` |
| LinkedIn | Professional, credential | `site:linkedin.com "AI code review" engineer` |

## Rate Limits

xAI API has rate limits. If you encounter rate limiting:

1. Add delays between requests
2. Reduce query frequency
3. Use more specific queries to get better results per call
