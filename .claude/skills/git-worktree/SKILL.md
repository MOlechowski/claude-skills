---
name: git-worktree
description: Work on multiple branches simultaneously.
---

# Git Worktree Skill

Use this skill when:
- Working on multiple branches at the same time without stashing
- Reviewing PRs or code while keeping current work intact
- Running builds or tests on different branches in parallel
- Setting up isolated development environments per branch
- Managing bare repo + worktree workflows

Examples:
- "How do I work on two branches at once?"
- "Create a worktree for reviewing a PR"
- "Set up git worktrees for parallel development"
- "Set up a bare repo with worktrees"
- "Manage worktrees in a monorepo"

You are an expert in git worktrees for managing multiple working directories linked to a single repository.

## What are Git Worktrees?

Git worktrees allow you to check out multiple branches simultaneously in separate directories, all sharing the same `.git` repository. This eliminates the need to stash, commit, or lose work when switching contexts.

**Key Benefits:**
- Work on multiple features/branches simultaneously
- Review PRs without disrupting current work
- Run parallel builds/tests on different branches
- Keep long-running processes (dev servers) running while working elsewhere

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

**Pros:** Simple, each worktree is independent
**Cons:** Can clutter project directory

### Strategy 2: Subdirectory Organization

```
~/projects/myproject/
├── main/               # main worktree
└── worktrees/
    ├── feature/        # feature branch
    ├── hotfix/         # hotfix branch
    └── pr-42/          # PR review
```

**Pros:** Clean organization, all related dirs together
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

**Pros:** No "special" main worktree, clean separation, easier to reason about
**Cons:** Slightly more complex initial setup

## Bare Repository Setup (Advanced)

The bare repo approach treats all worktrees equally - there's no "main" directory that's different from others.

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

## Monorepo Workflows

### Selective Package Worktrees

In monorepos, you might want worktrees focused on specific packages:

```bash
# Main worktree has full monorepo
~/monorepo/main/

# Feature worktree - work happens in specific package
~/monorepo/feature-auth/
# Focus on: packages/auth/, packages/shared/
```

### Dependency Management Considerations

**Node.js (npm/yarn/pnpm):**

```bash
# Option 1: Separate node_modules per worktree
cd ../project-feature
npm install  # Creates its own node_modules

# Option 2: Shared node_modules with pnpm (recommended for monorepos)
# pnpm's content-addressable store shares packages efficiently

# Option 3: Symlink common dependencies (advanced)
ln -s ../main/node_modules ./node_modules  # Use with caution
```

**Python:**

```bash
# Separate virtual environments per worktree (recommended)
cd ../project-feature
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### CI/CD with Worktrees

Worktrees can speed up CI by enabling parallel branch testing:

```bash
# CI script example
git worktree add /tmp/test-branch-a branch-a
git worktree add /tmp/test-branch-b branch-b

# Run tests in parallel
(cd /tmp/test-branch-a && npm test) &
(cd /tmp/test-branch-b && npm test) &
wait

# Cleanup
git worktree remove /tmp/test-branch-a
git worktree remove /tmp/test-branch-b
```

## IDE Integration

### VS Code

```bash
# Open worktree in new window
code ../project-feature

# Or use VS Code workspaces to manage multiple worktrees
# Create .code-workspace file referencing multiple folders
```

### JetBrains IDEs

Each worktree can be opened as a separate project. The IDE will recognize it shares the same Git repository.

### Vim/Neovim

Worktrees work seamlessly. Just `cd` to the worktree directory and edit normally.

## Troubleshooting

### "fatal: '<branch>' is already checked out"

A branch can only be checked out in one worktree at a time.

```bash
# Find where the branch is checked out
git worktree list

# Solutions:
# 1. Use a different branch
git worktree add -b feature-v2 ../new-worktree main

# 2. Remove the other worktree first
git worktree remove ../other-worktree
```

### Stale Worktree References

If you manually delete a worktree directory:

```bash
# Clean up the reference
git worktree prune

# Verify
git worktree list
```

### Worktree on Different Filesystem/Network Drive

```bash
# Lock to prevent accidental pruning
git worktree lock --reason "On network drive" /mnt/network/worktree

# Unlock when back on local filesystem
git worktree unlock /mnt/network/worktree
```

### Submodules in Worktrees

```bash
# After creating worktree, initialize submodules
cd ../project-feature
git submodule update --init --recursive
```

## Best Practices

1. **Naming Convention**: Use descriptive names that indicate purpose
   - `project-feature-auth` not `project-1`
   - `project-pr-123-review` for PR reviews

2. **Clean Up**: Remove worktrees when done
   ```bash
   git worktree remove ../project-feature
   ```

3. **Lock Long-Running Worktrees**: Prevent accidental removal
   ```bash
   git worktree lock --reason "Active development" ../project-feature
   ```

4. **Use Bare Repos for Teams**: When multiple people work with worktrees, bare repos avoid "main worktree" confusion

5. **Separate Dependencies**: Each worktree should have its own `node_modules`, `.venv`, etc. to avoid conflicts

6. **Regular Pruning**: Clean up stale references periodically
   ```bash
   git worktree prune
   ```

## Quick Reference

For a concise command reference, see `quick-reference.md` in this skill directory.

## Workflow Examples

For detailed real-world workflow examples, see `examples.md` in this skill directory.
