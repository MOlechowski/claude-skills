# Git Worktree Workflow Examples

Real-world scenarios for effective git worktree usage.

## Example 1: Feature Development While Reviewing PR

Working on a feature when teammate asks for PR review.

```bash
# Current state: working in main repo on feature-auth
~/projects/myapp$ git status
On branch feature-auth
Changes not staged for commit:
  modified:   src/auth/login.ts

# Create worktree for PR review (don't lose your work!)
~/projects/myapp$ git fetch origin
~/projects/myapp$ git worktree add ../myapp-pr-42 origin/feature-payments

# Review the PR in new worktree
~/projects$ cd myapp-pr-42
~/projects/myapp-pr-42$ npm install
~/projects/myapp-pr-42$ npm test
~/projects/myapp-pr-42$ code .  # Open in VS Code to review

# ... review complete, leave comments on PR ...

# Clean up
~/projects/myapp-pr-42$ cd ../myapp
~/projects/myapp$ git worktree remove ../myapp-pr-42

# Continue your feature work (unchanged!)
~/projects/myapp$ git status
On branch feature-auth
Changes not staged for commit:
  modified:   src/auth/login.ts
```

## Example 2: Hotfix While Feature in Progress

Production bug - fix without losing feature work.

```bash
# Working on feature branch
~/projects/api$ git branch
* feature-new-dashboard
  main

# Create hotfix worktree from main
~/projects/api$ git worktree add -b hotfix-login ../api-hotfix main

# Switch to hotfix
~/projects$ cd api-hotfix

# Fix the bug
~/projects/api-hotfix$ vim src/auth.ts
~/projects/api-hotfix$ npm test
~/projects/api-hotfix$ git add -A
~/projects/api-hotfix$ git commit -m "fix: resolve login timeout issue"
~/projects/api-hotfix$ git push origin hotfix-login

# Create PR, get it merged to main...

# Clean up hotfix worktree
~/projects/api-hotfix$ cd ../api
~/projects/api$ git worktree remove ../api-hotfix

# Update your feature branch with the fix
~/projects/api$ git fetch origin
~/projects/api$ git rebase origin/main
```

## Example 3: Parallel Test Runs

Run tests on multiple branches simultaneously.

```bash
#!/bin/bash
# parallel-tests.sh

REPO_DIR=$(pwd)
BRANCHES=("main" "develop" "feature-x")
WORKTREE_BASE="/tmp/parallel-test"

# Create worktrees
for branch in "${BRANCHES[@]}"; do
    echo "Creating worktree for $branch..."
    git worktree add "$WORKTREE_BASE/$branch" "$branch"
    (cd "$WORKTREE_BASE/$branch" && npm ci) &
done
wait

# Run tests in parallel
for branch in "${BRANCHES[@]}"; do
    echo "Testing $branch..."
    (cd "$WORKTREE_BASE/$branch" && npm test > "test-$branch.log" 2>&1) &
done
wait

# Report results
for branch in "${BRANCHES[@]}"; do
    echo "=== Results for $branch ==="
    tail -20 "$WORKTREE_BASE/$branch/test-$branch.log"
done

# Cleanup
for branch in "${BRANCHES[@]}"; do
    git worktree remove "$WORKTREE_BASE/$branch"
done
```

## Example 4: Bare Repository Setup (Team Workflow)

Bare repo setup for clean worktree management.

```bash
# Initial setup (one time)
~/projects$ git clone --bare git@github.com:company/product.git product.git

# Configure fetch (important for bare repos!)
~/projects$ cd product.git
~/projects/product.git$ git config remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"

# Create directory structure
~/projects$ mkdir product

# Add main worktree
~/projects/product.git$ git worktree add ../product/main main

# Add develop worktree
~/projects/product.git$ git worktree add ../product/develop develop

# Result:
# ~/projects/
# ├── product.git/         # bare repo
# └── product/
#     ├── main/            # main branch
#     └── develop/         # develop branch

# Daily workflow - add feature worktree
~/projects/product.git$ git fetch origin
~/projects/product.git$ git worktree add -b feature-xyz ../product/feature-xyz develop

# Work on feature
~/projects$ cd product/feature-xyz
~/projects/product/feature-xyz$ npm install
~/projects/product/feature-xyz$ code .

# When done, clean up
~/projects/product.git$ git worktree remove ../product/feature-xyz
```

## Example 5: Comparing Implementations

Compare two approaches to solving a problem.

```bash
# Create branch for approach A
~/projects/app$ git worktree add -b approach-a ../app-approach-a main

# Create branch for approach B
~/projects/app$ git worktree add -b approach-b ../app-approach-b main

# Implement approach A
~/projects$ cd app-approach-a
~/projects/app-approach-a$ # ... implement using Strategy pattern ...
~/projects/app-approach-a$ npm run benchmark > benchmark-a.txt

# Implement approach B
~/projects$ cd ../app-approach-b
~/projects/app-approach-b$ # ... implement using Factory pattern ...
~/projects/app-approach-b$ npm run benchmark > benchmark-b.txt

# Compare
~/projects$ diff app-approach-a/benchmark-a.txt app-approach-b/benchmark-b.txt

# Keep the winner, remove the other
~/projects/app$ git worktree remove ../app-approach-b
# Continue with approach-a...
```

## Example 6: Monorepo Package Development

Multiple packages simultaneously in a monorepo.

```bash
# Monorepo structure:
# ~/monorepo/
# ├── packages/
# │   ├── core/
# │   ├── ui/
# │   └── api/
# └── apps/
#     └── web/

# Main development on core package
~/monorepo$ git checkout feature-core-refactor

# Need to simultaneously update UI package to test integration
~/monorepo$ git worktree add -b feature-ui-updates ../monorepo-ui main

# Install dependencies in new worktree
~/monorepo$ cd ../monorepo-ui
~/monorepo-ui$ pnpm install

# Link local core changes (if using pnpm/yarn workspaces)
# Both worktrees can reference shared packages

# Run UI development server
~/monorepo-ui$ pnpm --filter @company/ui dev

# Meanwhile, in original worktree, run core tests
~/monorepo$ pnpm --filter @company/core test:watch

# When integration is verified, merge changes
~/monorepo$ git worktree remove ../monorepo-ui
```

## Example 7: Long-Running Dev Server

Dev server running while working on other branches.

```bash
# Start dev server in dedicated worktree
~/projects/web$ git worktree add --lock ../web-devserver main
~/projects/web$ cd ../web-devserver
~/projects/web-devserver$ npm install
~/projects/web-devserver$ npm run dev &

# Server running at http://localhost:3000

# Now work on feature in main worktree
~/projects$ cd web
~/projects/web$ git checkout feature-new-page
~/projects/web$ # ... develop feature ...

# Test against running dev server (different branch!)
# Browser: http://localhost:3000 shows main branch
# Your editor shows feature-new-page branch

# When done with long session
~/projects/web$ git worktree unlock ../web-devserver
~/projects/web$ git worktree remove ../web-devserver
```

## Example 8: Release Branch Management

Release management while development continues.

```bash
# Create release worktree
~/projects/app$ git worktree add -b release/v2.0 ../app-release main

# Development continues in main worktree
~/projects/app$ git checkout develop
~/projects/app$ # ... continue feature development ...

# Release work in separate worktree
~/projects$ cd app-release
~/projects/app-release$ # Apply release-specific changes
~/projects/app-release$ npm version 2.0.0
~/projects/app-release$ git add package.json
~/projects/app-release$ git commit -m "chore: bump version to 2.0.0"

# Run release validation
~/projects/app-release$ npm run test:e2e
~/projects/app-release$ npm run build

# Tag and push release
~/projects/app-release$ git tag v2.0.0
~/projects/app-release$ git push origin release/v2.0 --tags

# Merge back to main
~/projects/app-release$ git checkout main
~/projects/app-release$ git merge release/v2.0
~/projects/app-release$ git push origin main

# Clean up
~/projects/app$ git worktree remove ../app-release
```

## Example 9: CI/CD Optimization

Parallel branch validation in CI.

```yaml
# .github/workflows/parallel-branches.yml
name: Parallel Branch Validation

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  validate-branches:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        branch: [main, develop, staging]
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup worktree for ${{ matrix.branch }}
        run: |
          git worktree add /tmp/branch-${{ matrix.branch }} ${{ matrix.branch }}

      - name: Install and test
        working-directory: /tmp/branch-${{ matrix.branch }}
        run: |
          npm ci
          npm test
          npm run build

      - name: Cleanup
        if: always()
        run: git worktree remove /tmp/branch-${{ matrix.branch }} --force
```

## Example 10: Investigation/Debugging

Reproduce and debug issue on specific commit.

```bash
# Bug reported in production (running v1.5.2)
~/projects/app$ git worktree add --detach ../app-debug v1.5.2

# Set up debug environment
~/projects$ cd app-debug
~/projects/app-debug$ npm install
~/projects/app-debug$ export DEBUG=*
~/projects/app-debug$ npm run dev

# Reproduce and investigate the bug
# ... debugging ...

# Found the issue! Now create a fix
~/projects/app$ git worktree add -b bugfix/issue-123 ../app-fix v1.5.2

# Implement fix
~/projects$ cd app-fix
~/projects/app-fix$ # ... fix the bug ...
~/projects/app-fix$ git commit -am "fix: resolve issue #123"
~/projects/app-fix$ git push origin bugfix/issue-123

# Clean up
~/projects/app$ git worktree remove ../app-debug
~/projects/app$ git worktree remove ../app-fix
```

## Tips from Examples

1. **`npm install` in new worktrees** - they don't share `node_modules`
2. **Use `--lock`** for long-running worktrees
3. **Descriptive names** - `app-pr-42`, `app-hotfix`, not `app-2`
4. **Clean up promptly** - Remove worktrees when done
5. **Fetch before creating** - `git fetch origin` for latest refs
6. **Bare repos for teams** - cleaner mental model
7. **One worktree per task**
