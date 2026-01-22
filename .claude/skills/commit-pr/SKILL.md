---
name: commit-pr
description: "Commit changes and create PR in one flow. Use when: committing and creating PR in one step, shipping a feature, pushing changes with PR. Triggers: /commit-pr, ship this, commit and PR, push and create PR."
---

# Commit & PR

Full commit-to-PR flow via skill composition.

## Workflow

```
1. Branch → 2. Commit → 3. Push → 4. PR → 5. Merge
```

## Steps

### 1. Create Feature Branch

If on main/master:

```bash
git checkout -b feat/scope-name
```

Branch naming:
- `feat/` for features
- `fix/` for fixes

Derive scope from commit message or affected files.

### 2. Commit

Use `/commit` skill for message generation and style rules.

```
Skill(skill="commit")
```

### 3. Push

```bash
git push -u origin $(git branch --show-current)
```

### 4. Create PR

Use `/pr-create` skill for PR creation.

```
Skill(skill="pr-create")
```

### 5. Merge

Use `/pr-manage` skill for merge and lifecycle.

```
Skill(skill="pr-manage")
```

Skip merge if user requests "create PR only" or "no merge".

## Safety

- Never commit secrets
- Create feature branch (not main)
- Verify changes before commit
