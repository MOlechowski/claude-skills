---
name: git-worktree
description: "Work on multiple branches simultaneously. Use when: working on multiple branches, reviewing PRs without stashing, parallel builds/tests, bare repo workflows. Triggers: /git-worktree, work on two branches, create worktree, set up bare repo."
---

# Git Worktree

Multiple working directories linked to one repository. Check out multiple branches simultaneously without stashing.

**Benefits:** Parallel features, PR reviews without disruption, concurrent builds/tests, persistent dev servers.

## Core Concepts

### Main Worktree vs Linked Worktrees
- **Main worktree**: The original clone directory (contains `.git` folder)
- **Linked worktrees**: Additional checkouts that reference the main `.git`

### Shared State
All worktrees share:
- Commit history and objects
- Remote configurations
- Refs (branches, tags)
- Git configuration

Each worktree has separate:
- Working directory files
- Index (staging area)
- HEAD (current branch/commit)

## Common Patterns

### Pattern 1: Create Worktree for Existing Branch

```bash
# Create worktree for an existing branch
git worktree add ../project-feature feature-branch

# Create worktree tracking a remote branch
git worktree add ../project-pr-123 origin/pr-123
```

### Pattern 2: Create Worktree with New Branch

```bash
# Create new branch and worktree together
git worktree add -b new-feature ../project-new-feature main

# Create from specific commit
git worktree add -b hotfix ../project-hotfix v1.2.3
```

### Pattern 3: Detached HEAD Worktree

```bash
# Checkout specific commit without branch
git worktree add --detach ../project-test abc123

# Useful for testing specific commits or tags
git worktree add --detach ../project-release v2.0.0
```

### Pattern 4: List and Manage Worktrees

```bash
# List all worktrees
git worktree list

# List with more details
git worktree list --porcelain

# Remove a worktree (clean way)
git worktree remove ../project-feature

# Force remove if there are changes
git worktree remove --force ../project-feature

# Clean up stale worktree references
git worktree prune
```

### Pattern 5: Lock/Unlock Worktrees

```bash
# Prevent accidental removal (e.g., on network drive)
git worktree lock ../project-feature

# Add reason for lock
git worktree lock --reason "Long-running experiment" ../project-feature

# Unlock when done
git worktree unlock ../project-feature
```

## Directory Organization Strategies

### Strategy 1: Sibling Directories (Simple)

```
~/projects/
├── myproject/           # main worktree (main branch)
├── myproject-feature/   # feature branch
├── myproject-hotfix/    # hotfix branch
└── myproject-pr-42/     # PR review
```

**Pros:** Simple, independent worktrees
**Cons:** Clutters project directory

### Strategy 2: Subdirectory Organization

```
~/projects/myproject/
├── main/               # main worktree
└── worktrees/
    ├── feature/        # feature branch
    ├── hotfix/         # hotfix branch
    └── pr-42/          # PR review
```

**Pros:** Clean organization, related dirs together
**Cons:** Deeper paths

### Strategy 3: Bare Repository (Recommended for Power Users)

```
~/projects/
├── myproject.git/      # bare repo (no working files)
└── myproject/
    ├── main/           # main branch worktree
    ├── develop/        # develop branch worktree
    └── feature-x/      # feature branch worktree
```

**Pros:** No "special" main worktree, clean separation
**Cons:** More complex initial setup

## Bare Repository Setup (Advanced)

Bare repos treat all worktrees equally - no "main" directory is special.

### Initial Setup

```bash
# Clone as bare repository
git clone --bare git@github.com:user/repo.git repo.git

# Or convert existing repo to bare
cd existing-repo
git clone --bare . ../repo.git

# Configure remote fetch (important for bare repos)
cd repo.git
git config remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"
```

### Adding Worktrees from Bare Repo

```bash
cd repo.git

# Add main branch worktree
git worktree add ../repo/main main

# Add other worktrees
git worktree add ../repo/develop develop
git worktree add -b feature-x ../repo/feature-x main
```

### Fetching Updates

```bash
# Fetch from bare repo directory
cd repo.git
git fetch origin

# Then update individual worktrees as needed
cd ../repo/main
git merge origin/main
```

## Best Practices

1. **Naming Convention**: Use descriptive names (`project-feature-auth` not `project-1`)

2. **Clean Up**: Remove worktrees when done
   ```bash
   git worktree remove ../project-feature
   ```

3. **Lock Long-Running Worktrees**: Prevent accidental removal:
   ```bash
   git worktree lock --reason "Active development" ../project-feature
   ```

4. **Use Bare Repos for Teams**: Avoids "main worktree" confusion

5. **Separate Dependencies**: Each worktree needs own `node_modules`, `.venv`, etc.

6. **Regular Pruning**: Clean stale references periodically:
   ```bash
   git worktree prune
   ```

## Quick Reference

See `quick-reference.md` for command reference.

## Workflow Examples

See `examples.md` for real-world workflow examples.
