# Iterative Research Reference

Procedures for multi-round research, gap analysis, and cross-referencing.

## Research Rounds Overview

| Depth | Rounds | Purpose |
|-------|--------|---------|
| quick | 1 | Broad survey, surface-level findings |
| default | 2 | Broad survey + targeted follow-up |
| deep | 3 | Broad survey + targeted follow-up + primary source verification |

## Round 1: Broad Survey

### Query Generation

Generate 4-6 queries covering different angles:

1. **Direct query** — The topic as stated
2. **Temporal query** — Topic + current year or "latest"
3. **Reddit query** — `site:reddit.com` + topic
4. **GitHub query** — `site:github.com` + topic
5. **HN query** — `site:news.ycombinator.com` + topic
6. **Framework-specific query** — Adapted to detected framework (see below)

### Framework-Specific Round 1 Queries

| Framework | Additional Query Angle |
|-----------|----------------------|
| COMPARISON | `"{Alt A} vs {Alt B}"` |
| LANDSCAPE | `"{topic} ecosystem" OR "{topic} landscape"` |
| DEEP_DIVE | `"how {topic} works" OR "{topic} explained"` |
| DECISION | `"{topic}" experience OR recommendation` |

### Parallel Execution

Run simultaneously:
- Claude WebSearch for each query
- xAI `web` search (if available)
- xAI `reddit` search (if available)
- xAI `x` search (if available)
- xAI `github` search (if available)
- xAI `hn` search (if available)

### Round 1 Internal Notes

After Round 1, record (internally, not in output):

```
KEY_ENTITIES: [list of specific tools, companies, people discovered]
THEMES: [recurring themes across sources]
GAPS: [what's missing — see gap analysis below]
CONTRADICTIONS: [conflicting claims found]
LEADS: [specific URLs or sources worth deep-reading in Round 2]
```

## Gap Analysis (After Round 1)

### Gap Categories

Run this checklist after Round 1 to identify what's missing:

| Gap Category | Check | Action |
|-------------|-------|--------|
| **Missing perspective** | Do we have views from developers, operators, and business stakeholders? | Target missing perspective in Round 2 |
| **Unverified claims** | Any claims supported by only 1 source? | Seek corroboration in Round 2 |
| **Shallow coverage** | Any entity mentioned but not explained? | Deep-search that entity in Round 2 |
| **Stale data** | Are key facts from >12 months ago? | Search for recent updates |
| **Missing source type** | Missing Reddit? GitHub? HN? X? Blogs? | Target that source type in Round 2 |

### Source Count Assessment

For each key claim or entity:

| Sources | Confidence | Action |
|---------|-----------|--------|
| 3+ independent sources | [HIGH] | No follow-up needed |
| 2 sources | [MEDIUM] | Optional follow-up if claim is central |
| 1 source only | [LOW] | Must seek corroboration in Round 2 |
| 0 sources (assumption) | [UNVERIFIED] | Must find evidence or remove claim |

### Coverage Balance Assessment

Check all four dimensions have adequate coverage:

- [ ] **Technical depth** — How it works, architecture, performance data
- [ ] **Practical experience** — Real-world usage reports, migration stories, gotchas
- [ ] **Community sentiment** — What developers actually think (Reddit, HN, X)
- [ ] **Commercial aspects** — Pricing, licensing, vendor stability, support

### Recency Check

For each source:
- Sources < 3 months old: current
- Sources 3-12 months old: acceptable for stable topics
- Sources > 12 months old: flag for verification in Round 2

## Round 2: Targeted Follow-Up

### Query Generation Rules

1. **Never repeat Round 1 queries** — queries must target gaps, not re-cover ground
2. **Entity-specific queries** — Use names/tools discovered in Round 1
3. **Source-type-specific queries** — Target platforms that were underrepresented
4. **Framework-adapted queries** — See table below

### Framework-Adapted Round 2 Targeting

| Framework | Round 2 Priority |
|-----------|-----------------|
| COMPARISON | Equal depth per alternative. If Round 1 found 5 sources for Alt A and 2 for Alt B, Round 2 focuses on Alt B |
| LANDSCAPE | Fill empty categories. If Round 1 found players in 3/5 categories, Round 2 targets the 2 missing categories |
| DECISION | Experience reports: `{option} "in production"`, `{option} "switched from"`, `{option} regret` |
| DEEP_DIVE | Mechanisms and limitations: `"how {topic} works" internals`, `{topic} limitations OR drawbacks OR problems` |

### Round 2 Query Templates

Generate 4-6 queries from this pool:

1. **Entity deep-dive:** `"{entity_name}" review OR experience OR benchmark`
2. **Gap filling:** `"{topic}" {missing_perspective}` (e.g., "security", "performance", "cost")
3. **Contradiction resolution:** `"{claim_A}" OR "{claim_B}" {topic} benchmark`
4. **Source-type targeting:** `site:{underrepresented_platform} "{topic}"`
5. **Temporal update:** `"{entity}" latest OR update OR release 2026`
6. **Expert search:** `from:{discovered_expert} "{topic}"` (X only)

### WebFetch Targets

In Round 2, use WebFetch for high-value URLs found in Round 1:

- Official documentation pages
- Benchmark result pages
- Detailed blog posts from engineering teams
- Release notes or changelogs
- Comparison articles with methodology

Maximum 4-6 WebFetch calls in Round 2.

### Confidence Update

After Round 2, re-assess all confidence levels:

- Claims that gained a second source: upgrade [LOW] → [MEDIUM]
- Claims corroborated by 3+ sources: upgrade to [HIGH]
- Claims that contradicted: note the contradiction, present both sides
- Claims with no new evidence: keep at current level, note in output

## Round 3: Verification (Deep Only)

Round 3 is exclusively for verification. No new discovery.

### Verification Checklist

| Check | Method | Max Calls |
|-------|--------|-----------|
| Primary source verification | WebFetch the original source for key claims | 3-4 |
| Benchmark validation | WebFetch independent benchmark sites | 1-2 |
| Contradiction resolution | WebFetch both sides' primary sources | 1-2 |
| Recency confirmation | WebFetch official sites for latest versions/dates | 1-2 |

**Total Round 3 budget: 6-10 WebFetch lookups maximum.**

### Verification Rules

1. **Verify, don't discover** — Round 3 is not for finding new information
2. **Target highest-impact claims** — Verify claims that would change the recommendation
3. **Check primary sources** — Go to the original, not summaries
4. **Update confidence** — Upgrade or downgrade based on what you find
5. **Note contradictions** — If primary source contradicts secondary, trust primary

## Cross-Referencing Methodology

### Source Agreement Matrix

For each key claim, track which sources agree:

| Claim | Web | Reddit | X | GitHub | HN | Blogs | Agreement |
|-------|-----|--------|---|--------|-----|-------|-----------|
| {Claim 1} | Y | Y | - | Y | - | Y | 4/6 [HIGH] |
| {Claim 2} | Y | - | - | - | - | - | 1/6 [LOW] |
| {Claim 3} | Y | N | - | - | Y | - | CONFLICT |

### Contradiction Resolution Procedure

When sources disagree:

1. **Identify the specific disagreement** — What exactly do they say differently?
2. **Check source quality** — Primary source > secondary. Recent > old. Expert > casual.
3. **Check context** — Are they talking about the same version/context?
4. **Present both sides** — Don't hide contradictions, show them with context
5. **State which is more credible** — With reasoning

### Engagement-Weighted Synthesis

When synthesizing across sources, weight by engagement signals:

| Source Type | High-Signal Threshold | Weight |
|-------------|----------------------|--------|
| Reddit threads | 100+ upvotes | High — community validated |
| X posts | 50+ likes | High — viral/popular |
| GitHub repos | 1000+ stars | High — broad adoption |
| HN threads | 100+ points | High — technically validated |
| Multiple sources agree | 3+ platforms | High — cross-platform consensus |
| Found by both Claude + xAI | Dual-engine match | High — validated coverage |
| Recent (< 7 days) | Any | Medium — fresh but unvalidated |
| Engineering blog post | From known company | Medium — authoritative but single viewpoint |
| Single source only | Any | Low — needs verification |

### Synthesis Priority Order

When assembling the final output:

1. **Cross-platform consensus** — Claims supported across multiple source types go first
2. **High-engagement items** — Widely discussed or starred items
3. **Expert opinion** — Known practitioners with track record
4. **Unique insights** — Valuable perspective found in only one source (flag as [LOW])
5. **Recency** — Newer information gets slight priority, all else being equal
