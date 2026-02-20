---
name: res-web
description: "Research topics with web search. Use when: researching a topic or concept, finding current information, answering factual questions, comparing options or technologies. Triggers: research [topic], find out about, what are the best practices for, research the latest on."
---

# Web Research

Thorough web research: multiple searches, cross-referenced sources, structured summary.

## Workflow

1. Parse topic from request
2. Generate 3-5 search queries (different angles)
3. Execute searches in parallel
4. Evaluate and cross-reference sources
5. Synthesize findings
6. Output structured summary with citations

## Query Generation

Cover:
- Direct topic search
- "What is [topic]"
- "[topic] explained"
- "[topic] best practices" or "[topic] examples"
- "[topic] vs alternatives" (if applicable)

Run searches in parallel.

## Source Evaluation

Prioritize:
- Official documentation
- Reputable tech sites
- Recent content (check dates)
- Multiple sources confirming same info

Avoid:
- Outdated information
- Single-source claims
- Marketing content without substance

## Cross-Reference

For each key finding:
- Verify across 2+ sources
- Note conflicting information
- Identify consensus vs debate

## Output Format

```
## [Topic]

### Key Findings
- [Most important point]
- [Second key point]
- [Third key point]

### Details

[Synthesized information organized by subtopic]

#### [Subtopic 1]
[Details...]

#### [Subtopic 2]
[Details...]

### Sources
- [Source Title](url)
- [Source Title](url)
- [Source Title](url)
```

## Guidelines

- Thorough but concise
- Distinguish facts from opinions
- Note uncertain or debated information
- Include publication dates for time-sensitive topics
- Use current year in searches

## Edge Cases

**Niche topics:** Broaden search terms or search for related concepts.

**Conflicting sources:** Present both perspectives, note disagreement.

**No good sources:** Report scarce information, suggest alternatives.

**Time-sensitive topics:** Include recent date in searches, note potential staleness.
