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
3. Pick commit type from changes
4. Infer scope from affected files
5. Write short description

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

- Short sentences
- Active voice
- No filler words (just, really, very, basically)
- Natural tone, not robotic
- Lead with action or outcome

## Body

- Simple changes: subject only, no body
- Complex changes: add body to explain why

## Breaking Changes

Add `!` after type or scope:

```
feat!: remove deprecated API
feat(api)!: change response format
```

Or use footer:

```
feat: update auth flow

BREAKING CHANGE: token format changed
```

## Safety

- Check `git status` first
- Never commit secrets or credentials
- Verify staged files before commit

See `quick-reference.md` for type details.
