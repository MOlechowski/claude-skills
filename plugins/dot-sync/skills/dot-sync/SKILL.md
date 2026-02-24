---
name: dot-sync
description: "Bidirectional sync between a dot-claude config repo and live ~/.claude/. Diffs settings, hooks, plugins, and CLAUDE.md — explains changes semantically and lets you choose direction per file. Use when: syncing claude config, config drift detection, pulling config changes, pushing config to repo. Triggers: dot-sync, sync config, sync claude, config drift, sync hooks, sync settings."
---

# dot-sync

Bidirectional sync between a `dot-claude` Git repository and the live `~/.claude/` configuration directory.

## Purpose

Claude Code configuration evolves in two places: the live `~/.claude/` directory (when you enable plugins, tweak hooks, edit settings) and a version-controlled `dot-claude` repo (for tracking and sharing config). This skill detects drift between them and lets you reconcile interactively.

## Workflow

When invoked, execute these steps in order:

### 1. Locate the dot-claude repo

Find the repo path using this priority:

1. **Environment variable**: Check `DOT_CLAUDE_REPO` — use if set
2. **Git remote detection**: Search for a local clone whose remote URL contains `dot-claude`
   ```bash
   # Scan common parent directories for the repo
   for parent in ~/Projects ~/Projects/ai-agents ~/repos ~/code; do
     find "$parent" -maxdepth 3 -name ".git" -type d 2>/dev/null | while read gitdir; do
       repo_dir=$(dirname "$gitdir")
       if git -C "$repo_dir" remote -v 2>/dev/null | grep -q "dot-claude"; then
         echo "$repo_dir"
       fi
     done
   done
   ```
3. If not found, ask the user for the path

Cache the resolved path for the session.

### 2. Diff all managed files

Compare each file pair between the repo and live config. Report status for each.

#### Files in scope

| Category | Repo path | Live path | Diff method |
|----------|-----------|-----------|-------------|
| Settings | `settings.json` | `~/.claude/settings.json` | Semantic JSON diff |
| Instructions | `CLAUDE.md` | `~/.claude/CLAUDE.md` | Text diff |
| Status line | `statusline-command.sh` | `~/.claude/statusline-command.sh` | Text diff |
| Marketplaces | `plugins/known_marketplaces.json` | `~/.claude/plugins/known_marketplaces.json` | Semantic JSON diff |
| Installed plugins | `plugins/installed_plugins.json` | `~/.claude/plugins/installed_plugins.json` | Semantic JSON diff |
| Hook scripts | `hooks/*.py` | `~/.claude/hooks/*.py` | Per-file text diff |
| Session memory hooks | `hooks/session-memory/*.sh` | `~/.claude/hooks/session-memory/*.sh` | Per-file text diff |

#### Excluded paths (never sync)

- `~/.claude/cache/`
- `~/.claude/telemetry/`
- `~/.claude/todos/`
- `~/.claude/teams/`
- `~/.claude/memory/`
- `~/.claude/projects/`
- `~/.claude/sessions/`
- `~/.claude/session-memory/`
- `~/.claude/plugins/marketplaces/` (managed by plugin system)
- `~/.claude/plugins/cache/` (managed by plugin system)

### 3. Present differences

For each file with differences, present:

1. **Status**: `modified`, `repo-only` (exists in repo but not live), `live-only` (exists live but not in repo)
2. **Diff**: Show the actual changes concisely
3. **Semantic explanation**: Describe what changed in human terms

#### Semantic diff rules

- **settings.json**: Call out added/removed hooks, changed plugin enable states, new env vars, statusline changes. Compare JSON keys, not raw text
- **installed_plugins.json**: List plugins added/removed/version-changed. Show install dates
- **known_marketplaces.json**: List added/removed marketplaces
- **Hook scripts**: Describe what the hook does and what changed functionally
- **CLAUDE.md**: Summarize added/removed sections or rules

#### Direction recommendation

For each diff, recommend a direction:

- If the live side has **additions** (new plugins, new hooks) → recommend `live → repo` (capture the new config)
- If the repo side has **additions** → recommend `repo → live` (deploy the tracked config)
- If both sides changed the same file → recommend `merge` and present both versions
- If only timestamps/formatting differ → recommend `skip`

### 4. Apply changes

For each diff, ask the user to choose:

- **repo → live**: Copy from repo to `~/.claude/`
- **live → repo**: Copy from `~/.claude/` to repo
- **skip**: Leave as-is
- **merge**: For conflicts — show both versions, let user pick sections

Apply all chosen changes.

### 5. Post-sync

After applying changes:

1. **Summary**: Show what was synced in each direction
2. **Repo commits**: If any `live → repo` changes were applied, offer to:
   - Stage the changed files
   - Create a commit with a descriptive message (e.g., `chore: sync live config — add 2 new plugins, update hooks`)
   - Optionally push to remote
3. **Reload hint**: If any `repo → live` changes were applied, suggest running `dev-reload` to pick up the changes without restarting Claude Code

## Output format

```
dot-sync: comparing repo vs live ~/.claude/

  settings.json          ✓ in sync
  CLAUDE.md              ⚠ modified (repo has 3 new lines in ## Testing section)
  statusline-command.sh  ✓ in sync
  plugins/installed.json ⚠ live-only changes (2 new plugins: foo, bar)
  hooks/pre_tool_use.py  ⚠ modified (live adds new blocked command pattern)
  hooks/stop.py          ✓ in sync
  ...

3 files differ. Resolve each:

[1/3] CLAUDE.md — repo has additions in ## Testing
  Recommend: repo → live
  Choose: [repo→live] / live→repo / skip

[2/3] plugins/installed_plugins.json — live has 2 new plugins
  Recommend: live → repo
  Choose: repo→live / [live→repo] / skip

[3/3] hooks/pre_tool_use.py — live adds "docker" to blocked commands
  Recommend: live → repo
  Choose: repo→live / [live→repo] / skip

Applied: 2 live→repo, 1 repo→live
Commit repo changes? (Y/n)
```
