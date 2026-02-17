# Output Frameworks Reference

Templates for structured research output. Select framework based on query type.

## Framework Detection

| Framework | Trigger Patterns | Example Query |
|-----------|-----------------|---------------|
| COMPARISON | "X vs Y", "compare", "which is better" | "React vs Vue for enterprise" |
| LANDSCAPE | "landscape", "ecosystem", "market", "what's out there" | "AI agent frameworks landscape" |
| DEEP_DIVE | "deep dive", "how does X work", "explain", "tell me about" | "Deep dive into WebAssembly" |
| DECISION | "should I", "evaluate", "which should we", "recommend" | "Should we use Kafka or RabbitMQ?" |

User can override with explicit tag: `[comparison]`, `[landscape]`, `[deep-dive]`, `[decision]`.

## Common Elements

### Header Block

```markdown
---
Framework: {COMPARISON|LANDSCAPE|DEEP_DIVE|DECISION}
Topic: {TOPIC}
Depth: {quick|default|deep}
Sources: {N} across {M} platforms
Date: {YYYY-MM-DD}
---
```

### Confidence Indicators

Use inline after claims:

- `[HIGH]` — Corroborated by 3+ independent sources
- `[MEDIUM]` — Supported by 2 sources
- `[LOW]` — Single source only, treat as preliminary

### Statistics Footer

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

### Sources Section

```markdown
## Sources

### Reddit
- r/{subreddit}: "[Thread title](url)" ({upvotes} upvotes)

### X/Twitter
- @{handle}: "[Post excerpt...](url)" ({likes} likes)

### GitHub
- [{owner/repo}](url): "{description}" ({stars} stars)

### Hacker News
- "[Thread title](url)" ({points} points, {comments} comments)

### Web
- [{domain}](url): "{Article title}" ({date})
```

---

## COMPARISON Framework

Use when comparing 2-4 specific alternatives.

### Template

```markdown
# {Alternative A} vs {Alternative B} [vs {C}...]

## Quick Verdict

{1-2 sentence summary: who should use what}

## Comparison Matrix

| Criteria | {Alt A} | {Alt B} | {Alt C} |
|----------|---------|---------|---------|
| {Criterion 1} | {value} [CONFIDENCE] | {value} [CONFIDENCE] | {value} [CONFIDENCE] |
| {Criterion 2} | ... | ... | ... |
| ... | ... | ... | ... |

## Feature Matrix

| Feature | {Alt A} | {Alt B} | {Alt C} |
|---------|---------|---------|---------|
| {Feature 1} | Yes/No/Partial | ... | ... |
| {Feature 2} | ... | ... | ... |

## Detailed Analysis

### {Alternative A}

**Strengths:**
- {strength with evidence} [CONFIDENCE]

**Weaknesses:**
- {weakness with evidence} [CONFIDENCE]

**Community Sentiment:**
- Reddit: {summary of r/relevant discussions}
- X: {summary of expert opinions}
- HN: {summary of technical discussions}

### {Alternative B}
{Same structure}

## Verdict by Use Case

| Use Case | Recommendation | Why |
|----------|---------------|-----|
| {Use case 1} | {Alt X} | {reasoning} |
| {Use case 2} | {Alt Y} | {reasoning} |

## {Statistics Footer}
## {Sources Section}
```

---

## LANDSCAPE Framework

Use for mapping an ecosystem or market space.

### Template

```markdown
# {Topic} Landscape

## Overview

{2-3 sentence summary of the space}

## Category Map

### {Category 1}: {Brief description}

| Player | Type | Maturity | Key Differentiator |
|--------|------|----------|--------------------|
| {Player A} | {OSS/Commercial/Hybrid} | {Early/Growing/Mature} | {differentiator} |
| {Player B} | ... | ... | ... |

### {Category 2}: {Brief description}
{Same table structure}

## Market Dynamics

| Dimension | Current State | Trend | Evidence |
|-----------|--------------|-------|----------|
| Adoption | {state} | {Growing/Stable/Declining} | {evidence} [CONFIDENCE] |
| Investment | {state} | ... | ... |
| Consolidation | {state} | ... | ... |
| Open Source vs Commercial | {balance} | ... | ... |

## Key Developments Timeline

| Date | Event | Impact |
|------|-------|--------|
| {YYYY-MM} | {event} | {impact} [CONFIDENCE] |

## White Spaces and Gaps

- **Unserved need:** {description of gap} [CONFIDENCE]
- **Emerging opportunity:** {description} [CONFIDENCE]

## Community Perspective

**Reddit sentiment:** {summary}
**HN sentiment:** {summary}
**X discourse:** {summary}
**GitHub activity:** {summary — active projects, trending repos}

## {Statistics Footer}
## {Sources Section}
```

---

## DEEP_DIVE Framework

Use for comprehensive analysis of a single topic.

### Template

```markdown
# Deep Dive: {Topic}

## What It Is

{2-3 sentence definition accessible to someone unfamiliar}

## How It Works

{Technical explanation at appropriate depth}

### Architecture / Key Concepts

{Diagram description or concept breakdown}

## Current State

{Where the technology/topic stands today} [CONFIDENCE]

## Key Players

| Entity | Role | Notable For |
|--------|------|-------------|
| {Player A} | {Creator/Major user/Contributor} | {what they did} |

## Strengths

- {strength with evidence} [CONFIDENCE]

## Limitations

- {limitation with evidence} [CONFIDENCE]

## Community Perspective

**Developer experience (Reddit/HN):**
- {key themes from discussions}

**Industry opinion (X/Blogs):**
- {key themes from expert posts}

**Open source activity (GitHub):**
- {repo activity, contributor trends, issue patterns}

## Future Outlook

{Where this is heading based on evidence} [CONFIDENCE]

- **Near-term (6 months):** {prediction}
- **Medium-term (1-2 years):** {prediction}

## {Statistics Footer}
## {Sources Section}
```

---

## DECISION Framework

Use when helping make a specific choice with trade-off analysis.

### Template

```markdown
# Decision: {Question being decided}

## Options Summary

| Option | Summary | Effort | Risk | Cost |
|--------|---------|--------|------|------|
| {Option A} | {1-line summary} | {Low/Med/High} | {Low/Med/High} | {estimate} |
| {Option B} | ... | ... | ... | ... |

## Recommendation

**{Recommended option}** — {1-2 sentence reasoning}

Confidence: [HIGH|MEDIUM|LOW] based on {source count} sources

## Detailed Analysis

### Option A: {Name}

**Description:** {what this option entails}

**Pros:**
- {pro with evidence} [CONFIDENCE]

**Cons:**
- {con with evidence} [CONFIDENCE]

**Evidence:**
- {specific data point from research} — {source}

### Option B: {Name}
{Same structure}

## Risk Analysis

| Risk Factor | {Option A} | {Option B} |
|-------------|------------|------------|
| Blast radius if it fails | {assessment} | {assessment} |
| Rollback difficulty | {Easy/Medium/Hard} | ... |
| Lock-in / switching cost | {assessment} | ... |
| Security surface | {assessment} | ... |

## Community Experience

**What practitioners say (Reddit/HN):**
- {real experience reports}

**What experts say (X/Blogs):**
- {expert opinions}

**Open source signals (GitHub):**
- {adoption indicators — stars, forks, issues}

## Recommendation with Caveats

**Go with {Option X} if:** {conditions}
**Consider {Option Y} instead if:** {conditions}

**Caveats:**
- {important caveat or assumption}

## {Statistics Footer}
## {Sources Section}
```
