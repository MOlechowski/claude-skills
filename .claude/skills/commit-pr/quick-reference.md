# Commit & PR Quick Reference

## Full Flow

```bash
# 1. Stage changes
git add -A

# 2. Check what's staged
git diff --staged

# 3. Create branch (if on main)
git checkout -b feat/feature-name

# 4. Commit
git commit -m "feat(scope): add feature"

# 5. Push
git push -u origin feat/feature-name

# 6. Create PR
gh pr create --title "feat(scope): add feature" --body "## Summary
- Added feature

## Test plan
- [ ] Test it"
```

## Commit Types

| Type | Use |
|------|-----|
| feat | New feature |
| fix | Bug fix |
| docs | Documentation |
| refactor | Code restructure |
| test | Tests |
| chore | Maintenance |

## Branch Naming

```
feat/scope-description
fix/scope-description
docs/update-readme
```

## PR Body Template

```markdown
## Summary
- Change 1
- Change 2

## Test plan
- [ ] Manual test
- [ ] Unit tests pass
```
