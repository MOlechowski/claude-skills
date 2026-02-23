# Setup Guide

## 1. Create the Reload Command

Create `.claude/commands/reload.md` in your project or globally at `~/.claude/commands/reload.md`:

```markdown
# Reload Claude Code (restart Claude)
!`kill -HUP $PPID`
```

The `!` prefix is critical — it bypasses LLM processing and executes immediately. Without it, Claude may add commentary, request confirmation, or refuse to run the command.

## 2. Add Shell Wrapper

Add to `~/.zshrc` or `~/.bashrc`:

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

Then reload your shell:

```bash
source ~/.zshrc  # or source ~/.bashrc
```

### How It Works

1. `kill -HUP $PPID` sends SIGHUP (signal 1) to Claude's parent process
2. Claude terminates with exit code 129 (128 + 1, shell convention for signal termination)
3. The wrapper loop detects exit code 129
4. Restarts Claude with `-c` flag (continue previous session)
5. Passes `"restarted"` as a message so Claude resumes work without waiting for input
6. All config files (CLAUDE.md, hooks, skills, commands, agents) are re-read on startup

### Wrapper Customization

Add your preferred flags directly:

```bash
function claude-reload() {
  local continue_flag=""
  local restart_msg=""
  local rc
  while true; do
    claude --dangerously-skip-permissions $continue_flag "$@" $restart_msg
    rc=$?
    [ $rc -eq 129 ] || return $rc
    echo "Reloading Claude Code..."
    sleep 0.5
    continue_flag="-c"
    restart_msg="restarted"
  done
}
```

Or create an alias:

```bash
alias cl='claude-reload'
alias clp='claude-reload --dangerously-skip-permissions'
```

## 3. Verify

1. Start a session: `claude-reload`
2. Type `/reload` in the prompt
3. Claude should exit and restart with "Reloading Claude Code..." message
4. Session continues with config re-read

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| Claude terminates, doesn't restart | Not using the wrapper | Start with `claude-reload`, not `claude` |
| `/reload` not found | Command file missing | Create `.claude/commands/reload.md` |
| Claude asks for confirmation | Missing `!` prefix | Ensure command starts with `!` |
| Context feels different after reload | Session compressed | Expected — `-c` loads summarized context |

## Attribution

SIGHUP reload approach by [Anthony Panozzo](https://www.panozzaj.com/blog/2026/02/07/building-a-reload-command-for-claude-code/).
