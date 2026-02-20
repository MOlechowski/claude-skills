# Configuration Reference

## Commands

```bash
backlog config              # interactive wizard
backlog config list         # view all current values
backlog config get <key>    # get specific value
backlog config set <key> <value>  # set value
```

## All Configuration Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `projectName` | string | directory name | Project identifier |
| `statuses` | string[] | `[To Do, In Progress, Done]` | Board column names |
| `labels` | string[] | `[]` | Available label values |
| `defaultStatus` | string | `To Do` | Initial status for new tasks |
| `defaultAssignee` | string[] | `[]` | Pre-fill assignee on new tasks |
| `definition_of_done` | string[] | (not set) | Default DoD checklist items for new tasks |
| `dateFormat` | string | `yyyy-mm-dd hh:mm` | DateTime display format |
| `includeDatetimeInDates` | boolean | `true` | Add time to new dates |
| `defaultEditor` | string | platform default | Editor for 'E' key (e.g., `code --wait`, `vim`) |
| `defaultPort` | number | `6420` | Web UI port |
| `autoOpenBrowser` | boolean | `true` | Auto-open browser on `backlog browser` |
| `remoteOperations` | boolean | `true` | Enable git fetch (set `false` for offline) |
| `autoCommit` | boolean | `false` | Auto-commit task changes to git |
| `bypassGitHooks` | boolean | `false` | Skip pre-commit hooks on auto-commit (`--no-verify`) |
| `zeroPaddedIds` | number | (disabled) | Zero-pad IDs (e.g., `3` produces `001`, `002`) |
| `checkActiveBranches` | boolean | `true` | Detect task state across active git branches |
| `activeBranchDays` | number | `30` | Days before a branch is considered inactive |
| `onStatusChange` | string | (disabled) | Shell command on status change |
| `prefixes.task` | string | `task` | ID prefix for tasks |

## Status Change Callbacks

Global callback in `config.yml`:
```yaml
onStatusChange: 'if [ "$NEW_STATUS" = "In Progress" ]; then notify-send "Task started"; fi'
```

Per-task override in task frontmatter:
```yaml
onStatusChange: 'custom-command-for-this-task'
```

Available variables: `$TASK_ID`, `$OLD_STATUS`, `$NEW_STATUS`, `$TASK_TITLE`.

## Config File Location

- Project config: `backlog/config.yml`
- User config: `~/.backlog/user` (global defaults)

## Custom Statuses Example

```yaml
statuses:
  - Backlog
  - Design
  - Development
  - QA
  - Done
defaultStatus: Backlog
```

## Definition of Done Defaults

```yaml
definition_of_done:
  - Tests pass
  - Documentation updated
  - Code reviewed
```

New tasks automatically get these DoD items. Override per-task with `--no-dod-defaults`.
