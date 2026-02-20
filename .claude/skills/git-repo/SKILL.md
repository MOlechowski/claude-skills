---
name: git-repo
description: "Create GitHub repositories via OpenTofu in the github-infrastructure repo. Clones repo to tmp, generates repository module (main.tf, outputs.tf, versions.tf), updates root main.tf and outputs.tf, runs fmt+validate, pushes and creates PR. Use when: (1) creating a new GitHub repo, (2) adding a repository to the org, (3) provisioning a new project/spec/infra/template repo. Triggers: new repo, create repository, add repo, github repository, provision repo."
---

# GitHub Repository Creation

Create new GitHub repositories by adding OpenTofu modules to the `github-infrastructure` repo.

## Workflow

### 1. Gather Parameters

Collect from the user:

| Parameter | Required | Default | Notes |
|-----------|----------|---------|-------|
| `name` | Yes | - | kebab-case, e.g. `my-new-repo` |
| `description` | Yes | - | One-line description |
| `visibility` | No | `private` | `private` or `public` |
| `is_template` | No | `false` | `true` for template repos |
| `default_branch` | No | `main` | Branch to protect (`main` or `master`) |
| `extra_branches` | No | `[]` | Additional branches to protect |
| `status_checks` | No | `["Claude Code Review", "CodeRabbit", "Lint"]` | CI checks to require |
| `category` | No | infer | `Projects`, `Specs`, `Infrastructure`, or `Templates` |

**Category inference:** name ends with `-spec` → Specs; ends with `-template` → Templates; contains `infrastructure`, `ci-`, `org-` → Infrastructure; else → Projects.

### 2. Clone to Temp Directory

```bash
WORK_DIR=$(mktemp -d)
git clone --depth 1 git@github.com:OlechowskiMichal/github-infrastructure.git "$WORK_DIR/github-infrastructure"
cd "$WORK_DIR/github-infrastructure"
git checkout -b feat/add-<repo-name>
```

All subsequent file operations happen inside `$WORK_DIR/github-infrastructure`.

### 3. Create Module Files

Create `tofu/repositories/<repo-name>/` with three files. Use the exact templates from [references/templates.md](references/templates.md).

### 4. Update Root Module

**`tofu/main.tf`** — Add under the correct category comment (`# Projects`, `# Specs`, `# Infrastructure`, `# Templates`):

```hcl
module "<module_name>" {
  source = "./repositories/<repo-name>"
}
```

Module name: replace hyphens and dots with underscores, strip leading dots.

**`tofu/outputs.tf`** — Add to both `repositories` and `branch_protections` outputs under the same category:

```hcl
# In repositories:
"<repo-name>" = module.<module_name>.repository

# In branch_protections:
"<repo-name>" = module.<module_name>.branch_protection
```

### 5. Commit, Push, and Create PR

```bash
cd "$WORK_DIR/github-infrastructure"
tofu -chdir=tofu fmt -recursive
git add tofu/
git commit -m "feat: add <repo-name> repository"
git push -u origin feat/add-<repo-name>
gh pr create --title "feat: add <repo-name> repository" --body "Add OpenTofu module for <repo-name>"
```

### 6. Clean Up

```bash
rm -rf "$WORK_DIR"
```

Report the PR URL to the user.

## OPA Policy Requirements

CI will reject violations. These are mandatory:

- `vulnerability_alerts = true`
- `delete_branch_on_merge = true`
- `allow_merge_commit = false`
- `allow_squash_merge = true`
- `has_wiki = false`
- `has_projects = false`
- `has_issues = true`
- Branch protection with `required_status_checks` and `required_pull_request_reviews`
- `allows_force_pushes = false`, `allows_deletions = false`
- At least 1 approving review
- `github_branch_protection.extra` block always present (even with `for_each = toset([])`)
- `lifecycle { prevent_destroy = true }` on repository resource
- `archive_on_destroy = true`
