---
name: dev-reload
description: "Reload Claude Code configuration without full restart. SIGHUP-based reload for CLAUDE.md, hooks, skills, commands, agents, MCP servers. Includes shell wrapper setup and reload command. Use when: config changed mid-session, CLAUDE.md updated, skills added/removed, hooks modified, need to reload without losing context. Triggers: reload config, reload claude, restart claude, config changed, reload settings, dev-reload."
---

# Claude Code Config Reload

Reload all Claude Code configuration mid-session without losing context. Uses SIGHUP signal to trigger a graceful restart with session continuation.

## What Reloads Live (No Action Needed)

| Config | File |
|--------|------|
| General settings | `settings.json` (user/project/local) |
| `/config` changes | Interactive UI |

## What Requires Reload

| Config | File |
|--------|------|
| Instructions | `CLAUDE.md`, `.claude/CLAUDE.md` |
| Hooks | `settings.json` hook section (cached at startup) |
| Slash commands | `.claude/commands/*.md` |
| Skills | `.claude/skills/` |
| Agent definitions | `.claude/agents/` |
| MCP servers | MCP config |

`/clear` does NOT re-read any of these — it only clears conversation context.

## Reload Mechanism

Send SIGHUP to Claude's parent process. Claude exits with code 129 (128 + signal 1). A shell wrapper detects this exit code and restarts Claude with `-c` to continue the session.

### Setup

Two components required. See `references/setup.md` for full instructions.

**1. Reload command** — `.claude/commands/reload.md`:

```markdown
# Reload Claude Code (restart Claude)
!`kill -HUP $PPID`
```

The `!` prefix executes immediately without LLM processing (~1 second, deterministic).

**2. Shell wrapper** — add to `.zshrc` / `.bashrc`:

```bash
function claude-reload() {
  local continue_flag=""
  local restart_msg=""
  local rc
  while true; do
    claude $continue_flag "$@" $restart_msg
    rc=$?
    [ $rc -eq 129 ] || return $rc
    echo "Reloading Claude Code..."
    sleep 0.5
    continue_flag="-c"
    restart_msg="restarted"
  done
}
```

Start sessions with `claude-reload` instead of `claude`. Add flags as needed (e.g., `claude-reload --dangerously-skip-permissions`).

### Usage

From within a Claude session started via the wrapper:

- **User**: Type `/reload` in the prompt
- **Claude**: Run `kill -HUP $PPID` via Bash tool

Both trigger the same mechanism: SIGHUP → exit 129 → wrapper restarts with `-c`.

## When to Suggest Reload

After modifying any file in the "Requires Reload" table above, inform the user:

> Configuration changed. Run `/reload` or restart Claude to pick up the changes.

## Limitations

- Context is summarized on restart (not fully preserved)
- Requires the shell wrapper — without it, SIGHUP terminates Claude permanently
- The `-c` flag continues the session but loads a compressed context summary
- Context compaction bug: long sessions may lose CLAUDE.md instructions entirely (known issue, no fix as of Feb 2026)
