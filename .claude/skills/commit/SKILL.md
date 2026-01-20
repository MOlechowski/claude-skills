---
name: commit
description: Generate Conventional Commits messages. Use when: creating commits, writing commit messages, committing changes. Triggers: /commit, "commit this", "commit my changes", finishing code changes.
---

# Commit

Generate commit messages. Adapt to repo style.

## Format

```
type(scope): description

[optional body]

[optional footer]
```

## Workflow

1. Run `git diff --staged` to see changes
2. Run `git log --oneline -10` to check repo style
3. Detect language from recent commits
4. Detect footer patterns (Change-Id, tickets)
5. Pick commit type from changes
6. Infer scope from affected files
7. Write short description

## Language Detection

Check recent commits for language:
- Polish: Dodanie, Naprawa, Poprawa, Zmiana, Usunięcie
- English: Add, Fix, Update, Remove, Change

Match the dominant language in last 10 commits.

## Atomic Commits

One commit = one logical change.

**Trigger rule:** If changes need different types (feat + fix) → Split into separate commits.

Before staging, ask: Can this be described in one subject line without "and"?

Bad:
```
feat(ios): Add mTLS support and fix cache tests
```

Good (split into two):
```
feat(ios): Add mTLS certificate injection
fix(ios): Fix cache tests for lowercase headers
```

## Style Rules

- Imperative mood: "add" not "added"
- No period at end
- No em dashes (—) in prose
- Under 50 chars for subject
- Match repo language and conventions

Em dash (—) vs hyphen (-):
- Bad: "add auth — with token support"
- Good: "add auth with token support"

## Writing Style

Be laconic:
- Shortest possible subject
- No filler words
- No bullet points in body
- No verbose explanations
- Skip body unless essential

**Body is noise unless it adds value.**

Subject examples:
- Bad: "Add Error convenience extensions for NetworkError"
- Good: "Add Error NetworkError extensions"

Body examples:

Bad (bullets):
```
feat(ios): Add mTLS support

- Add certificate fields
- Extract PEM data
```

Good (subject only):
```
feat(ios): Add mTLS certificate injection
```

Good (prose body when needed):
```
refactor(auth): Extract token service

Separate token logic for unit testing.
```

## Body

**Prefer no body.** A good subject makes body unnecessary.

Decision tree:
1. Is subject self-explanatory? → Skip body
2. Multiple unrelated changes? → Split into separate commits
3. Need to explain "why"? → Add prose body (1-2 sentences)

If body is needed:
- Prose only, no bullet points
- Explain why, not what
- One sentence per logical change
- Keep it short

## Breaking Changes

Add exclamation mark after type or scope:

```
feat!: remove deprecated API
feat(api)!: change response format
```

Or use footer:

```
feat: update auth flow

BREAKING CHANGE: token format changed
```

## Footers

Detect from repo history:
- Change-Id (Gerrit): preserve if present
- Ticket IDs (JIRA): include if pattern found
- Signed-off-by: include if repo uses it

Do not add footers the repo doesn't use.

## Safety

- Check `git status` first
- Never commit secrets or credentials
- Verify staged files before commit

See `quick-reference.md` for type details.
