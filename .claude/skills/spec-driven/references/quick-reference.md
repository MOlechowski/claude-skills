# Spec-Driven Quick Reference

## Finding Tasks

```bash
# All incomplete tasks
grep -rn "^\- \[ \]" $SPEC_REPO/specs/*/tasks.md

# Specs with incomplete tasks
find $SPEC_REPO/specs -name "tasks.md" -exec grep -l "^\- \[ \]" {} \;

# Count tasks per spec (sorted)
for f in $SPEC_REPO/specs/*/tasks.md; do
  count=$(grep -c "^\- \[ \]" "$f" 2>/dev/null || echo 0)
  [ "$count" -gt 0 ] && echo "$count $f"
done | sort -rn

# Tasks by priority
grep -n "^## P1" -A 100 $SPEC_REPO/specs/*/tasks.md | grep "^\- \[ \]"
```

## Spec Repository Structure

```
spec-repo/
+-- specs/
|   +-- 001-feature/
|   |   +-- README.md      # Specification
|   |   +-- tasks.md       # Tasks with checkboxes
|   +-- 002-feature/
|   |   +-- ...
+-- README.md
```

## Task Syntax

### Incomplete Task
```markdown
- [ ] Task description
```

### Completed Task (with PR link)
```markdown
- [x] Task description [PR #123](https://github.com/org/repo/pull/123)
```

### Blocked Task
```markdown
- [ ] Task description (blocked: needs infrastructure X)
```

### Priority Sections
```markdown
## P1 - Critical
- [ ] Must have task

## P2 - Important
- [ ] Should have task

## P3 - Nice to Have
- [ ] Could have task
```

## Workflow Commands

### 1. Check Open PRs
```bash
gh pr list --state open --json number,title,reviewDecision
```

### 2. Multi-Spec Setup (REQUIRED for 2+ specs)
```bash
# Create worktrees BEFORE implementation
git worktree add ../impl-014-feature -b 014-feature-name main
git worktree add ../impl-015-feature -b 015-feature-name main

# Work in each directory (no checkout needed)
cd ../impl-014-feature && # implement spec 014
cd ../impl-015-feature && # implement spec 015

# Cleanup after merge
git worktree remove ../impl-014-feature
git worktree remove ../impl-015-feature
```

### 3. Single Spec (branch workflow)
```bash
git checkout -b feat/spec-001-task-name main
```

### 4. After Implementation
```bash
git add -A
git commit -m "feat: implement task from spec-001"
git push -u origin feat/spec-001-task-name
gh pr create --title "feat: implement X from spec-001" --body "Implements task from specs/001-feature"
```

### 4. Update Spec Repo
```bash
cd $SPEC_REPO

# Edit tasks.md: change [ ] to [x] and add PR link

git add specs/001-feature/tasks.md
git commit -m "mark: complete task X [PR #123]"
git push origin main
```

## Parallel Work Setup

```bash
# Create worktrees (max 3)
git worktree add ../repo-task-1 -b feat/task-1
git worktree add ../repo-task-2 -b feat/task-2
git worktree add ../repo-task-3 -b feat/task-3

# List worktrees
git worktree list

# Remove when done
git worktree remove ../repo-task-1
```

## Handling Blockers

### E2E Test (needs credentials)
```go
//go:build e2e

func TestE2E(t *testing.T) {
    // Implementation
}
```

### Unit Test (needs mocks)
```go
// Add to .mockery.yaml, run: go generate ./...
type MyInterface interface {
    Method(ctx context.Context) error
}
```

## Commit Message Formats

### Implementation
```
feat: implement X from spec-NNN
fix: resolve issue in spec-NNN implementation
test: add tests for spec-NNN
```

### Spec Repo Updates
```
mark: complete task X [PR #123]
mark: update task status for spec-NNN
```

## Quick Checks

| Check | Command |
|-------|---------|
| Open PRs | `gh pr list --state open` |
| Incomplete tasks | `grep -r "^\- \[ \]" specs/*/tasks.md` |
| My branches | `git branch -a \| grep feat/` |
| Worktrees | `git worktree list` |
| CI status | `gh pr checks <PR>` |

## Post-Task Reflection

After tasks, use self-improvement skill:

```
Trigger questions:
- [ ] Figured out something undocumented?
- [ ] Found a workaround?
- [ ] Discovered a better pattern?
- [ ] Anything confusing?

If yes -> Update docs -> Commit: "docs: improve <file> - <description>"
```
