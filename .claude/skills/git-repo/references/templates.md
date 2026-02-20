# Repository Module Templates

Copy these templates exactly, replacing only the placeholder values.

## main.tf

```hcl
resource "github_repository" "this" {
  name        = "<REPO_NAME>"
  description = "<DESCRIPTION>"
  visibility  = "<VISIBILITY>"

  has_issues   = true
  has_projects = false
  has_wiki     = false
  is_template  = <IS_TEMPLATE>
  auto_init    = true

  allow_merge_commit     = false
  allow_squash_merge     = true
  allow_rebase_merge     = false
  delete_branch_on_merge = true
  vulnerability_alerts   = true
  archive_on_destroy     = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "github_branch_protection" "default" {
  repository_id = github_repository.this.node_id
  pattern       = "<DEFAULT_BRANCH>"

  enforce_admins                  = true
  require_signed_commits          = false
  required_linear_history         = false
  require_conversation_resolution = false
  lock_branch                     = false
  allows_deletions                = false
  allows_force_pushes             = false

  required_status_checks {
    strict   = true
    contexts = [<STATUS_CHECKS>]
  }

  required_pull_request_reviews {
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = false
    required_approving_review_count = 1
    restrict_dismissals             = false
  }
}

resource "github_branch_protection" "extra" {
  for_each = toset([<EXTRA_BRANCHES>])

  repository_id = github_repository.this.node_id
  pattern       = each.value

  enforce_admins                  = true
  require_signed_commits          = false
  required_linear_history         = false
  require_conversation_resolution = false
  lock_branch                     = false
  allows_deletions                = false
  allows_force_pushes             = false

  required_status_checks {
    strict   = true
    contexts = [<STATUS_CHECKS>]
  }

  required_pull_request_reviews {
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = false
    required_approving_review_count = 1
    restrict_dismissals             = false
  }
}
```

### Placeholder Values

| Placeholder | Example | Notes |
|-------------|---------|-------|
| `<REPO_NAME>` | `my-new-repo` | Exact repo name |
| `<DESCRIPTION>` | `CLI tool for managing widgets` | One-line description |
| `<VISIBILITY>` | `private` | `private` or `public` |
| `<IS_TEMPLATE>` | `false` | `true` or `false` (no quotes) |
| `<DEFAULT_BRANCH>` | `main` | Usually `main`, sometimes `master` |
| `<STATUS_CHECKS>` | `"Claude Code Review", "CodeRabbit", "Lint"` | Comma-separated quoted strings, or empty |
| `<EXTRA_BRANCHES>` | `"main"` | Comma-separated quoted strings, or empty for none |

### Common Status Check Patterns

- Standard project: `"Claude Code Review", "CodeRabbit", "Lint"`
- Spec repos: `"Lint"`
- Infrastructure repos: `"Lint", "Plan Infrastructure Changes"`
- Minimal (no CI yet): `` (empty)
- Single reviewer: `"CodeRabbit"`

## outputs.tf

```hcl
output "repository" {
  description = "Repository attributes"
  value = {
    name          = github_repository.this.name
    full_name     = github_repository.this.full_name
    html_url      = github_repository.this.html_url
    ssh_clone_url = github_repository.this.ssh_clone_url
    visibility    = github_repository.this.visibility
    node_id       = github_repository.this.node_id
  }
}

output "branch_protection" {
  description = "Branch protection IDs"
  value = merge(
    { (github_branch_protection.default.pattern) = github_branch_protection.default.id },
    { for k, v in github_branch_protection.extra : k => v.id }
  )
}
```

This file is identical for every module. Copy as-is.

## versions.tf

```hcl
terraform {
  required_providers {
    github = {
      source = "integrations/github"
    }
  }
}
```

This file is identical for every module. Copy as-is.
