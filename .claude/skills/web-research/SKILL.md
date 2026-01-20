---
name: web-research
description: "Research topics with web search. Use when: researching a topic or concept, finding current information, answering factual questions, comparing options or technologies. Triggers: research [topic], find out about, what are the best practices for, research the latest on."
---

# Web Research

Thorough web research on any topic. Multiple searches, cross-referenced sources, structured summary.

## Workflow

1. Parse topic from user request
2. Generate 3-5 search queries (different angles)
3. Execute searches in parallel
4. Evaluate and cross-reference sources
5. Synthesize findings
6. Output structured summary with citations

## Query Generation

Create queries that cover:
- Direct topic search
- "What is [topic]"
- "[topic] explained"
- "[topic] best practices" or "[topic] examples"
- "[topic] vs alternatives" (if applicable)

Run searches in parallel when possible.

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
- Verify across 2+ sources when possible
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

- Be thorough but concise
- Distinguish facts from opinions
- Note when information is uncertain or debated
- Include publication dates for time-sensitive topics
- Use current year context for searches (don't search for outdated info)

## Edge Cases

**Niche topics:** If few results, broaden search terms or search for related concepts.

**Conflicting sources:** Present both perspectives, note the disagreement.

**No good sources:** Report that reliable information is scarce, suggest alternative approaches.

**Time-sensitive topics:** Always include recent date in searches, note when info may be outdated.
