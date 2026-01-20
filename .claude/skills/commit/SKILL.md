---
name: commit
description: Generate Conventional Commits messages.
---

# Commit

Generate commit messages. Adapt to repo style.

Use this skill when:
- Creating a commit
- Writing commit messages
- Committing changes

Examples:
- "commit my changes"
- "create a commit"
- "commit this"

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

## Types

| Type | Use |
|------|-----|
| feat | New feature |
| fix | Bug fix |
| docs | Documentation |
| style | Formatting |
| refactor | Code restructure |
| perf | Performance |
| test | Tests |
| build | Build, deps |
| ci | CI config |
| chore | Maintenance |

## Style Rules

- Imperative mood: "add" not "added"
- No period at end
- No em dashes
- Under 50 chars for subject
- Match repo language and conventions

## Writing Style

Be laconic:
- Shortest possible subject
- No filler words
- No em dashes (use commas or separate sentences)
- No verbose explanations
- If subject is clear, skip body

Examples:
- Bad: "Add Error convenience extensions for NetworkError"
- Good: "Add Error NetworkError extensions"

- Bad body: "Add helpers to extract httpStatusCode, transportError"
- Good body: "Extract httpStatusCode from Error"

## Body

When to add:
- Simple (1-2 files, clear intent): subject only
- Complex (3+ files, non-obvious): add body

Body style:
- Explain why, not what
- One line per logical change
- No bullet points unless 3+ items

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
