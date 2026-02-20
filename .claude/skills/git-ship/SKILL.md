---
name: git-ship
description: "Commit, create PR, and merge with CI skipped. Disables GitHub Actions workflows via API before push, re-enables after merge. Use when: shipping trivial changes (renames, typos, config), bypassing CI for safe changes, fast-tracking PRs. Triggers: /git-ship, commit and merge skip ci, ship without ci, fast merge."
---

# Commit PR CI Merge

Full commit-to-merge flow with CI bypassed via GitHub Actions API.

## Workflow

```
1. Detect repo → 2. Disable workflows → 3. Branch → 4. Commit → 5. Push → 6. PR → 7. Merge → 8. Re-enable workflows → 9. Cleanup
```

## Steps

### 1. Detect Repository

Extract owner and repo from git remote:

```bash
gh repo view --json owner,name --jq '[.owner.login, .name] | @tsv'
```

Store as `OWNER` and `REPO` for all subsequent gh api calls.

### 2. List and Disable Workflows

Get all active workflows:

```bash
gh api repos/{OWNER}/{REPO}/actions/workflows --jq '.workflows[] | select(.state=="active") | [.id, .name] | @tsv'
```

Disable each PR-triggered workflow:

```bash
gh api repos/{OWNER}/{REPO}/actions/workflows/{ID}/disable -X PUT
```

Track disabled workflow IDs for re-enabling later. Only disable workflows that trigger on `pull_request` or `push` events. If unsure, disable all active workflows.

### 3. Create Feature Branch

If on main/master, create a branch. Use `/commit` skill conventions for branch naming:

```bash
git checkout -b chore/short-description
```

### 4. Commit

Use `/commit` skill for message generation.

```
Skill(skill="commit")
```

### 5. Push

```bash
git push -u origin $(git branch --show-current)
```

### 6. Create PR

Use `/pr-create` skill for PR creation. Add a note in the PR body that CI was skipped.

```
Skill(skill="pr-create")
```

### 7. Merge via API

First attempt: merge using the GitHub API with `--admin` flag:

```bash
gh pr merge {PR_NUMBER} --squash --admin
```

If merge fails with **review requirement error** (HTTP 405 or "approving review is required"):

1. Save current review protection settings:

```bash
gh api repos/{OWNER}/{REPO}/branches/main/protection/required_pull_request_reviews --jq '{dismiss_stale_reviews, require_code_owner_reviews, require_last_push_approval, required_approving_review_count}'
```

2. Temporarily remove review requirement:

```bash
gh api repos/{OWNER}/{REPO}/branches/main/protection/required_pull_request_reviews -X DELETE
```

3. Merge:

```bash
gh pr merge {PR_NUMBER} --squash --admin
```

4. Restore review protection using saved settings (use `--input -` with JSON to preserve boolean types):

```bash
gh api repos/{OWNER}/{REPO}/branches/main/protection/required_pull_request_reviews -X PATCH --input - <<'EOF'
{saved settings JSON}
EOF
```

**CRITICAL:** Always restore branch protection, even if the merge fails. Use the saved settings from step 1 to restore the exact original configuration.

### 8. Re-enable Workflows

Re-enable all previously disabled workflows:

```bash
gh api repos/{OWNER}/{REPO}/actions/workflows/{ID}/enable -X PUT
```

### 9. Local Cleanup

```bash
git checkout main && git pull && git branch -d {BRANCH_NAME}
```

## Safety

- Never skip CI for code changes that affect behavior
- Always re-enable workflows, even if merge fails
- Track disabled workflow IDs to ensure none are left disabled
- Appropriate for: renames, typos, config changes, documentation
- Not appropriate for: feature code, security changes, dependency updates
