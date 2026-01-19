# Commit Types Reference

## Types

**feat** - New feature visible to users

**fix** - Bug fix for users

**docs** - Documentation only changes

**style** - Formatting, whitespace, semicolons

**refactor** - Code change without feature or fix

**perf** - Performance improvement

**test** - Adding or fixing tests

**build** - Build system, dependencies

**ci** - CI configuration files

**chore** - Maintenance, tooling

## Scope Examples

```
feat(auth): add OAuth support
fix(api): handle null response
docs(readme): update install steps
refactor(utils): simplify date parsing
test(user): add signup tests
```

## Good Messages

```
feat: add dark mode toggle
fix: prevent duplicate submissions
docs: clarify env setup
refactor: extract validation logic
perf: cache database queries
```

## Bad Messages

```
fix: fixed bug          # past tense
feat: Add feature.      # capital, period
update stuff            # no type, vague
WIP                     # meaningless
```

## Commands

```bash
# Check what will be committed
git diff --staged

# Check repo style
git log --oneline -10

# Commit
git commit -m "type(scope): description"

# Commit with body
git commit -m "type: subject" -m "body text"
```
