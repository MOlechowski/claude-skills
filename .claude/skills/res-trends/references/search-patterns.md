# Search Patterns Reference

Advanced search patterns and operators for Web and X searches.

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
| Recent news | Add "2025" or "latest" | `Claude API latest 2025` |
| Historical | Add specific date/year | `AI predictions 2024` |

## Effective Query Patterns

### Trend Discovery

```
# Find emerging discussions
"what do you think about [topic]" min_faves:100

# Find expert opinions
[topic] from:[known_expert] OR from:[another_expert]

# Find debates
[topic] OR "wrong about" min_replies:50
```

### Competitive Intelligence

```
# Brand mentions
[company_name] -from:[company_handle]

# Product feedback
[product_name] (love OR hate OR "wish it")

# Comparison discussions
[product] vs [competitor]
```

### Market Research

```
# Problem discovery
"I wish [product_category]" OR "why doesn't [category]"

# Buying signals
"looking for" [product_category] recommendations

# Feature requests
[product] "feature request" OR "please add"
```

### Industry Monitoring

```
# News aggregation
[industry] news site:techcrunch.com OR site:wired.com

# Funding news
[industry] (raised OR funding OR "series A")

# Regulatory updates
[industry] (regulation OR policy OR compliance)
```

## Combining Search Types

### Comprehensive Research Flow

1. **Start with X** - Get real-time sentiment and conversations
2. **Follow with Web** - Get in-depth articles and analysis
3. **Cross-reference** - Compare social sentiment with media coverage

### Example Research Session

```bash
# Step 1: Social pulse
python3 xai_search.py x "AI agents 2025"

# Step 2: Industry analysis
python3 xai_search.py web "AI agent market analysis 2025"

# Step 3: Combined view
python3 xai_search.py both "AI agent trends"
```

## Cost Optimization

### Reduce API Calls

1. **Be specific** - Narrow queries reduce iterations
2. **Use operators** - Filter upfront, not after
3. **Batch related queries** - Combine when possible

### Example: Inefficient vs Efficient

```bash
# Inefficient (multiple broad queries)
python3 xai_search.py x "AI"
python3 xai_search.py x "AI tools"
python3 xai_search.py x "AI tools 2025"

# Efficient (single targeted query)
python3 xai_search.py x "AI tools 2025 min_faves:100"
```

## Rate Limits

xAI API has rate limits. If you encounter rate limiting:

1. Add delays between requests
2. Reduce query frequency
3. Use more specific queries to get better results per call
