# Git Worktree Quick Reference

## Create Worktrees

```bash
# Add worktree for existing branch
git worktree add <path> <branch>
git worktree add ../feature feature-branch

# Add worktree with new branch
git worktree add -b <new-branch> <path> <start-point>
git worktree add -b feature ../feature main

# Add worktree tracking remote branch
git worktree add <path> <remote>/<branch>
git worktree add ../pr-review origin/feature

# Add detached HEAD worktree (specific commit/tag)
git worktree add --detach <path> <commit>
git worktree add --detach ../release v2.0.0

# Force add (overwrites existing directory)
git worktree add --force <path> <branch>
```

## List Worktrees

```bash
# List all worktrees
git worktree list

# Porcelain output (for scripting)
git worktree list --porcelain

# Example output:
# /home/user/project       abc1234 [main]
# /home/user/project-feat  def5678 [feature]
```

## Remove Worktrees

```bash
# Remove worktree (safe - checks for changes)
git worktree remove <worktree>
git worktree remove ../feature

# Force remove (even with uncommitted changes)
git worktree remove --force <worktree>

# Clean up stale worktree references
git worktree prune

# Dry run prune (see what would be removed)
git worktree prune --dry-run

# Prune with verbose output
git worktree prune -v
```

## Lock Worktrees

```bash
# Lock worktree (prevent removal/pruning)
git worktree lock <worktree>

# Lock with reason
git worktree lock --reason "message" <worktree>
git worktree lock --reason "On network drive" ../feature

# Unlock worktree
git worktree unlock <worktree>
```

## Move/Repair Worktrees

```bash
# Move worktree to new location
git worktree move <worktree> <new-path>
git worktree move ../old-path ../new-path

# Repair worktree references after manual move
git worktree repair <path>
```

## Common Flags

| Flag | Description |
|------|-------------|
| `-b <branch>` | Create new branch |
| `-B <branch>` | Create or reset branch |
| `--detach` | Detached HEAD (no branch) |
| `--force` | Override safety checks |
| `--lock` | Lock worktree after creation |
| `--reason` | Specify lock reason |
| `--porcelain` | Machine-readable output |
| `-v, --verbose` | Verbose output |
| `--dry-run` | Show what would happen |

## One-Liners

```bash
# Create worktree, work, then cleanup
git worktree add ../temp-test test-branch && \
  (cd ../temp-test && npm test) ; \
  git worktree remove ../temp-test

# List worktree paths only
git worktree list --porcelain | grep "^worktree" | cut -d' ' -f2

# Remove all worktrees except main
git worktree list --porcelain | grep "^worktree" | cut -d' ' -f2 | \
  grep -v "$(git rev-parse --show-toplevel)" | \
  xargs -I {} git worktree remove {}

# Check if branch is checked out somewhere
git worktree list | grep "feature-branch"

# Create worktree and open in VS Code
git worktree add ../feature feature-branch && code ../feature
```

## Bare Repository Setup

```bash
# Clone as bare
git clone --bare <url> repo.git

# Fix fetch config for bare repo
cd repo.git
git config remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"

# Add worktrees from bare repo
git worktree add ../main main
git worktree add ../develop develop
git worktree add -b feature ../feature main
```

## Common Errors

| Error | Solution |
|-------|----------|
| `'<branch>' is already checked out` | Branch in another worktree. Use different branch or remove other worktree |
| `<path> already exists` | Path exists. Use `--force` or choose different path |
| `not a valid object name` | Branch/git-commit doesn't exist. Fetch first: `git fetch origin` |
| `fatal: <path> is locked` | Worktree is locked. Use `git worktree unlock <path>` |
