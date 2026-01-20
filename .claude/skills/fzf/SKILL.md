---
name: fzf
description: Interactive fuzzy finder for files, history, and lists. Use for: (1) interactive file/directory selection, (2) command history search with preview, (3) building selection menus in scripts, (4) filtering large lists or command outputs. Triggers: fuzzy search, interactive selector, pick from list, file finder with preview.
---

# fzf Expertise Skill

You are an expert in `fzf`, a general-purpose command-line fuzzy finder that provides an interactive interface for filtering and selecting items from any list.

## Core Capabilities

1. **Fuzzy Matching**: Smart approximate string matching with ranking
2. **Interactive Interface**: Real-time filtering as you type
3. **Multi-Selection**: Select multiple items with Tab
4. **Preview Window**: Show context for items (file contents, git diff, etc.)
5. **Key Bindings**: Customizable keyboard shortcuts for actions
6. **Integration**: Works with any command that outputs lines

## fzf Overview

**What it does:**
- Takes list of items as input (from stdin or command)
- Provides interactive fuzzy search interface
- Returns selected item(s) to stdout
- Supports custom key bindings and actions
- Shows preview of selected items
- Multi-selection with Tab key

**Why use fzf:**
- **Fast**: Written in Go, handles millions of lines
- **Flexible**: Works with any line-oriented data
- **Composable**: Pipes in/out of other commands
- **Customizable**: Rich options for UI and behavior
- **Universal**: Linux, macOS, Windows

**When to use fzf:**
- Interactive file/directory selection
- Command history search
- Git branch/commit selection
- Process selection for kill/debugging
- Custom picker interfaces
- Filtering large datasets

## Basic Usage

### Simple Selection
```bash
# Select from list
echo -e "apple\nbanana\ncherry" | fzf

# Select file in current directory
find . -type f | fzf

# Use selected value
file=$(find . -type f | fzf)
vim "$file"
```

### Default Key Bindings
```
Ctrl-J / Down    Move cursor down
Ctrl-K / Up      Move cursor up
Enter            Select item and exit
Ctrl-C / Esc     Exit without selection
Tab              Mark multiple items
Shift-Tab        Unmark items
Ctrl-A           Select all
Ctrl-D           Deselect all
Ctrl-U           Clear query
```

## Search Syntax

### Fuzzy Matching
```bash
# Fuzzy match (default)
fzf  # Type "abc" matches "a_b_c", "a123b456c", etc.

# Exact match (prefix with ')
fzf  # Type "'exact" matches "exact" only

# Prefix match (suffix with ^)
fzf  # Type "^start" matches lines starting with "start"

# Suffix match (prefix with $)
fzf  # Type "end$" matches lines ending with "end"

# Negation (prefix with !)
fzf  # Type "!exclude" matches lines not containing "exclude"
```

### Combining Patterns
```bash
# AND (space-separated)
# Type "foo bar" matches lines with both "foo" AND "bar"

# OR (pipe-separated)
# Type "foo | bar" matches lines with "foo" OR "bar"
```

## Options and Customization

### Display Options
```bash
# Multi-select
fzf --multi

# Reverse layout (prompt at top)
fzf --reverse

# Partial height
fzf --height 40%

# Border
fzf --border

# Prompt text
fzf --prompt "Select file> "

# Header
fzf --header "Choose an option"
```

### Search Behavior
```bash
# Case-sensitive
fzf --case-sensitive

# Exact match by default
fzf --exact

# Disable sort
fzf --no-sort

# Custom delimiter
fzf --delimiter=: --with-nth=2  # Only search 2nd field
```

### Preview Window
```bash
# Show preview
fzf --preview 'cat {}'

# Preview window size
fzf --preview 'cat {}' --preview-window=right:50%

# Preview window position
fzf --preview 'cat {}' --preview-window=up:40%

# Hide preview by default (toggle with Ctrl-/)
fzf --preview 'cat {}' --preview-window=hidden

# Custom preview with bat
fzf --preview 'bat --color=always --style=numbers {}'
```

## Key Bindings

### Built-in Actions
```bash
# Execute command on selection
fzf --bind 'enter:execute(vim {})'

# Reload list
fzf --bind 'ctrl-r:reload(find . -type f)'

# Toggle preview
fzf --bind 'ctrl-/:toggle-preview'

# Select all
fzf --bind 'ctrl-a:select-all'
```

### Custom Actions
```bash
# Multiple bindings
fzf --bind 'ctrl-e:execute(echo {} >> selected.txt)' \
    --bind 'ctrl-d:execute(rm {})'

# Chain actions
fzf --bind 'enter:execute(vim {})+abort'
```

## Integration Patterns

### File Navigation
```bash
# Interactive file opener
vim $(fzf)

# Change directory
cd $(find . -type d | fzf)

# With preview
find . -type f | fzf --preview 'bat --color=always {}'

# Open multiple files
vim $(fzf --multi)
```

### Git Integration
```bash
# Checkout branch
git checkout $(git branch | fzf | sed 's/^[* ]*//')

# Show commit
git log --oneline | fzf --preview 'git show {1}'

# Add files interactively
git add $(git status -s | fzf --multi | awk '{print $2}')

# Interactive git diff
git diff --name-only | fzf --preview 'git diff --color=always {}'
```

### Process Management
```bash
# Kill process
ps aux | fzf | awk '{print $2}' | xargs kill

# With preview showing process details
ps aux | fzf --header-lines=1 --preview 'pstree -p {2}'
```

### Command History
```bash
# Manual history search
history | fzf --tac | sed 's/^[[:space:]]*[0-9]*[[:space:]]*//'

# Execute selected command
eval "$(history | fzf --tac | sed 's/^[[:space:]]*[0-9]*[[:space:]]*//')"
```

## Shell Integration

### Bash/Zsh Keybindings
After running `fzf` installer:

```bash
# Ctrl-T: Paste selected files/directories
# Ctrl-R: Command history
# Alt-C: Change directory
```

### Custom Functions

**Interactive Git Branch Checkout:**
```bash
fco() {
  local branches branch
  branches=$(git branch -vv) &&
  branch=$(echo "$branches" | fzf +m) &&
  git checkout $(echo "$branch" | awk '{print $1}' | sed "s/.* //")
}
```

**Interactive File Editor:**
```bash
fe() {
  local file
  file=$(fd --type f | fzf --preview 'bat --color=always {}') &&
  ${EDITOR:-vim} "$file"
}
```

**Kill Process:**
```bash
fkill() {
  local pid
  pid=$(ps aux | fzf --header-lines=1 | awk '{print $2}') &&
  kill -9 "$pid"
}
```

**Tmux Session Selector:**
```bash
ftm() {
  local session
  session=$(tmux list-sessions -F '#{session_name}' | fzf) &&
  tmux attach-session -t "$session"
}
```

## Advanced Features

### Custom Preview
```bash
# File preview with syntax highlighting
fzf --preview 'bat --style=numbers --color=always {} | head -500'

# Directory preview
fzf --preview '[[ -d {} ]] && tree -C {} || bat --color=always {}'

# Git log preview
git log --oneline | fzf --preview 'git show --color=always --stat {1}'

# JSON preview
find . -name "*.json" | fzf --preview 'jq -C . {}'
```

### Dynamic Reloading
```bash
# Reload based on input
fzf --bind 'ctrl-r:reload(rg --files)' \
    --bind 'ctrl-g:reload(git ls-files)'

# Live grep
fzf --disabled --bind "change:reload:rg --column --line-number --no-heading --color=always {q}"
```

## Scripting with fzf

### Menu Builder
```bash
#!/bin/bash
option=$(cat << EOF | fzf --prompt="Select action> "
Build project
Run tests
Deploy to staging
View logs
EOF
)

case "$option" in
  "Build project") make build ;;
  "Run tests") npm test ;;
  "Deploy to staging") ./deploy.sh staging ;;
  "View logs") tail -f logs/app.log ;;
esac
```

### Multi-Step Wizard
```bash
#!/bin/bash
# Step 1: Select environment
ENV=$(echo -e "development\nstaging\nproduction" | \
  fzf --prompt="Environment> " --height=40%)

# Step 2: Select service
SERVICE=$(echo -e "api\nweb\nworker" | \
  fzf --prompt="Service> " --height=40%)

# Step 3: Confirm
CONFIRM=$(echo -e "Yes\nNo" | \
  fzf --prompt="Deploy $SERVICE to $ENV? " --height=40%)

if [[ "$CONFIRM" == "Yes" ]]; then
  ./deploy.sh "$SERVICE" "$ENV"
fi
```

## Best Practices

### DO
- Use `--reverse` for better ergonomics
- Add `--preview` for context
- Bind useful actions to keys
- Quote variables: `"$file"`
- Use `--multi` for batch operations
- Provide `--header` for instructions

### DON'T
- Process unsanitized user input directly
- Forget to handle empty selection
- Use without quoting variables
- Ignore exit codes
- Overload with too many bindings

## Environment Variables

```bash
# Default command for Ctrl-T
export FZF_DEFAULT_COMMAND='fd --type f'

# Default options
export FZF_DEFAULT_OPTS='--height 40% --layout=reverse --border'

# Ctrl-T command and options
export FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"
export FZF_CTRL_T_OPTS="--preview 'bat --color=always --line-range :500 {}'"

# Alt-C command and options
export FZF_ALT_C_COMMAND='fd --type d'
export FZF_ALT_C_OPTS="--preview 'tree -C {} | head -100'"
```

## Troubleshooting

### Common Issues
```bash
# No results shown
# Check if input is piped correctly
echo "test" | fzf  # Should work

# Preview not working
# Check preview command
fzf --preview 'echo {}' <<< "test"

# Key binding not working
# Re-run installer
$(brew --prefix)/opt/fzf/install
```

## Additional Resources

For detailed examples and reference, see `examples.md` and `quick-reference.md`.

- Official Repository: https://github.com/junegunn/fzf
- Wiki Examples: https://github.com/junegunn/fzf/wiki/examples

When providing fzf guidance, emphasize interactive workflows, suggest useful key bindings, recommend preview windows for context, and show integration patterns with other tools.
