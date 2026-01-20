---
name: tmux
description: "Terminal multiplexer session management. Use for: (1) running commands in persistent sessions, (2) automating interactive CLI workflows, (3) capturing output from long-running processes, (4) managing background tasks. Triggers: run in tmux, create session, send keys, capture output, interactive script automation."
---

# Tmux Skill

## Core Capabilities

1. **Session Management** - Create, attach, detach sessions
2. **Command Execution** - Run commands with proper escaping/timing
3. **Output Capture** - Retrieve pane output
4. **Interactive Automation** - Send keys for interactive CLIs
5. **Background Processing** - Persistent long-running processes

## Common Patterns

### Pattern 1: Run Command and Capture Output

```bash
# Create session, run command, capture output, kill session
tmux new-session -d -s session-name 'command to run'
sleep 1  # Wait for command to complete
tmux capture-pane -t session-name -p
tmux kill-session -t session-name
```

### Pattern 2: Interactive Script Automation

```bash
# Start session with script
tmux new-session -d -s session-name './script.sh'

# Send inputs (with proper timing)
sleep 1
tmux send-keys -t session-name 'first-input' Enter
sleep 0.5
tmux send-keys -t session-name 'second-input' Enter

# Capture result
sleep 1
tmux capture-pane -t session-name -p
tmux kill-session -t session-name
```

### Pattern 3: Long-Running Background Process

```bash
# Start persistent session
tmux new-session -d -s background-job 'long-running-command'

# Check if still running
tmux has-session -t background-job 2>/dev/null && echo "Running"

# Capture partial output
tmux capture-pane -t background-job -p -S -100  # Last 100 lines

# Stop when done
tmux kill-session -t background-job
```

### Pattern 4: Multiple Commands in Sequence

```bash
# Create session
tmux new-session -d -s multi-cmd

# Run commands sequentially
tmux send-keys -t multi-cmd 'cd /some/directory' Enter
sleep 0.5
tmux send-keys -t multi-cmd 'export VAR=value' Enter
sleep 0.5
tmux send-keys -t multi-cmd './run-script.sh' Enter

# Wait and capture
sleep 2
tmux capture-pane -t multi-cmd -p
tmux kill-session -t multi-cmd
```

## Key Commands

### Session Control
- `tmux new-session -d -s NAME 'CMD'` - Create detached session
- `tmux has-session -t NAME` - Check if session exists
- `tmux kill-session -t NAME` - Terminate session
- `tmux list-sessions` - Show all sessions

### Command Execution
- `tmux send-keys -t NAME 'text' Enter` - Send text + Enter
- `tmux send-keys -t NAME 'text'` - Send text without Enter
- `tmux send-keys -t NAME C-c` - Send Ctrl+C (interrupt)
- `tmux send-keys -t NAME C-d` - Send Ctrl+D (EOF)

### Output Capture
- `tmux capture-pane -t NAME -p` - Print entire pane
- `tmux capture-pane -t NAME -p -S -N` - Last N lines
- `tmux capture-pane -t NAME -p -S START -E END` - Line range

## Critical Guidelines

### Timing and Synchronization
Add sleep delays between tmux commands:
- After `new-session`: 0.5-1s for shell init
- After `send-keys`: 0.3-0.5s before next command
- Before `capture-pane`: Wait for command completion
- Interactive prompts: 1-2s for prompt to appear

### Escaping and Quoting
- Single quotes in `send-keys`: Use `'\''` or double quotes
- Double quotes in `send-keys`: Use `\"` or single quotes
- Special chars: `$`, `!`, backticks need care in double quotes
- Example: `tmux send-keys -t session "echo 'It'\''s working'" Enter`

### Session Name Best Practices
- Descriptive names: `install-deps`, `test-runner`, not `temp`
- Include context: `user-auth-test`, `build-frontend`
- Check conflicts: `tmux has-session` first
- Clean up: Kill sessions when done

### Error Handling
```bash
# Check if session exists before operations
if tmux has-session -t my-session 2>/dev/null; then
    tmux kill-session -t my-session
fi

# Create with error check
tmux new-session -d -s my-session 'command' || {
    echo "Failed to create session"
    exit 1
}
```

## Common Use Cases

### 1. Install Scripts with Prompts
```bash
# Script asks for confirmation (y/n)
tmux new-session -d -s installer './install.sh'
sleep 1
# Answer first prompt
tmux send-keys -t installer 'y' Enter
sleep 0.5
# Answer second prompt
tmux send-keys -t installer 'y' Enter
# Wait for completion
sleep 2
tmux capture-pane -t installer -p
tmux kill-session -t installer
```

### 2. Interactive CLI Testing
```bash
# Test CLI with user input
tmux new-session -d -s cli-test 'mycli interactive'
sleep 1
tmux send-keys -t cli-test 'test-user' Enter  # Username
sleep 0.5
tmux send-keys -t cli-test 'password123' Enter  # Password
sleep 1
output=$(tmux capture-pane -t cli-test -p)
tmux kill-session -t cli-test
echo "$output"
```

### 3. Monitoring Long Commands
```bash
# Start long-running command
tmux new-session -d -s monitor 'npm install && npm test'

# Check progress periodically
while tmux has-session -t monitor 2>/dev/null; do
    echo "Still running..."
    tmux capture-pane -t monitor -p | tail -5
    sleep 5
done

echo "Complete!"
```

### 4. Parallel Tasks
```bash
# Run multiple commands in separate sessions
tmux new-session -d -s task1 'pytest tests/unit'
tmux new-session -d -s task2 'npm run lint'
tmux new-session -d -s task3 'go test ./...'

# Wait for all to complete
for task in task1 task2 task3; do
    while tmux has-session -t $task 2>/dev/null; do
        sleep 1
    done
done
```

## Advanced Techniques

### Pane Management
```bash
# Create session with multiple panes
tmux new-session -d -s multi-pane
tmux split-window -h -t multi-pane  # Horizontal split
tmux split-window -v -t multi-pane  # Vertical split

# Target specific panes
tmux send-keys -t multi-pane.0 'command1' Enter
tmux send-keys -t multi-pane.1 'command2' Enter
tmux send-keys -t multi-pane.2 'command3' Enter
```

### Environment Variables
```bash
# Set environment before command
tmux new-session -d -s with-env \
    "export DEBUG=1 && export VERBOSE=true && ./script.sh"
```

### Capturing to File
```bash
# Save output to file
tmux capture-pane -t session-name -p > output.txt

# Append to log
tmux capture-pane -t session-name -p >> session.log
```

## Troubleshooting

### Session Already Exists
```bash
# Force recreate
tmux kill-session -t my-session 2>/dev/null || true
tmux new-session -d -s my-session 'command'
```

### Command Not in Output
- Increase sleep before capture-pane
- Check if command completed
- Verify session exists: `tmux has-session -t NAME`

### Special Characters Not Working
- Use single quotes: `tmux send-keys -t s 'echo $VAR'`
- Escape: `'\''` for single quote in single-quoted string
- Double quotes: `tmux send-keys -t s "echo \"quoted\""`

### Blank Output
- Session may have exited; check with `tmux has-session`
- Command may need more time; increase sleep
- Capture earlier: `capture-pane -S -50`

## Best Practices

1. Kill sessions after use
2. Use descriptive session names
3. Add timing delays between commands
4. Check session existence before operations
5. Capture output before killing
6. Handle errors
7. Test timing interactively first
8. Document timing rationale

Tmux automation requires careful timing and error handling.
