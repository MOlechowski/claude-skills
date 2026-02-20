---
name: cli-fzf
description: "Interactive fuzzy finder for files, history, and lists. Use for: (1) interactive file/directory selection, (2) command history search with preview, (3) building selection menus in scripts, (4) filtering large lists or command outputs. Triggers: fuzzy search, interactive selector, pick from list, file finder with preview."
---

# cli-fzf Skill

## Basic Usage

### Selection
```bash
# Select from list
echo -e "apple\nbanana\ncherry" | fzf

# Select file
find . -type f | fzf

# Use selected value
file=$(find . -type f | fzf)
vim "$file"
```

### Keybindings
```
Ctrl-J / Down    Cursor down
Ctrl-K / Up      Cursor up
Enter            Select and exit
Ctrl-C / Esc     Exit
Tab              Mark item
Shift-Tab        Unmark
Ctrl-A           Select all
Ctrl-D           Deselect all
Ctrl-U           Clear query
```

## Search Syntax

### Fuzzy Matching
```bash
# Fuzzy match (default): "abc" matches "a_b_c"
# Exact match: "'exact" matches only "exact"
# Prefix match: "^start" matches lines starting with "start"
# Suffix match: "end$" matches lines ending with "end"
# Negation: "!exclude" excludes lines containing "exclude"
```

### Combining Patterns
```bash
# AND (space): "foo bar" matches lines with both
# OR (pipe): "foo | bar" matches lines with either
```

## Options

### Display
```bash
fzf --multi               # Multi-select
fzf --reverse             # Prompt at top
fzf --height 40%          # Partial height
fzf --border              # Border
fzf --prompt "Select> "   # Prompt text
fzf --header "Options"    # Header
```

### Search Behavior
```bash
fzf --case-sensitive      # Case-sensitive
fzf --exact               # Exact match by default
fzf --no-sort             # Disable sort
fzf --delimiter=: --with-nth=2  # Search 2nd field only
```

### Preview Window
```bash
fzf --preview 'cat {}'
fzf --preview 'cat {}' --preview-window=right:50%
fzf --preview 'cat {}' --preview-window=up:40%
fzf --preview 'cat {}' --preview-window=hidden  # toggle with Ctrl-/
fzf --preview 'bat --color=always --style=numbers {}'
```

## Key Bindings

### Built-in Actions
```bash
fzf --bind 'enter:execute(vim {})'     # Execute on selection
fzf --bind 'ctrl-r:reload(find . -type f)'  # Reload list
fzf --bind 'ctrl-/:toggle-preview'     # Toggle preview
fzf --bind 'ctrl-a:select-all'         # Select all
```

### Custom Actions
```bash
fzf --bind 'ctrl-e:execute(echo {} >> selected.txt)' \
    --bind 'ctrl-d:execute(rm {})'

# Chain actions
fzf --bind 'enter:execute(vim {})+abort'
```

## Integration Patterns

### File Navigation
```bash
vim $(fzf)                                    # File opener
cd $(find . -type d | fzf)                    # Change directory
find . -type f | fzf --preview 'bat --color=always {}'  # With preview
vim $(fzf --multi)                            # Multiple files
```

### Git Integration
```bash
git checkout $(git branch | fzf | sed 's/^[* ]*//')  # Checkout branch
git log --oneline | fzf --preview 'git show {1}'     # Show commit
git add $(git status -s | fzf --multi | awk '{print $2}')  # Add files
git diff --name-only | fzf --preview 'git diff --color=always {}'  # Diff
```

### Process Management
```bash
ps aux | fzf | awk '{print $2}' | xargs kill  # Kill process
ps aux | fzf --header-lines=1 --preview 'pstree -p {2}'  # With preview
```

### Command History
```bash
history | fzf --tac | sed 's/^[[:space:]]*[0-9]*[[:space:]]*//'  # Search
eval "$(history | fzf --tac | sed 's/^[[:space:]]*[0-9]*[[:space:]]*//')"  # Execute
```

## Shell Integration

After `cli-fzf` installer:
```bash
# Ctrl-T: Paste selected files
# Ctrl-R: Command history
# Alt-C: Change directory
```

### Custom Functions

```bash
# Git branch checkout
fco() {
  local branches branch
  branches=$(git branch -vv) &&
  branch=$(echo "$branches" | fzf +m) &&
  git checkout $(echo "$branch" | awk '{print $1}' | sed "s/.* //")
}

# File editor
fe() {
  local file
  file=$(fd --type f | fzf --preview 'bat --color=always {}') &&
  ${EDITOR:-vim} "$file"
}

# Kill process
fkill() {
  local pid
  pid=$(ps aux | fzf --header-lines=1 | awk '{print $2}') &&
  kill -9 "$pid"
}

# Tmux session selector
ftm() {
  local session
  session=$(tmux list-sessions -F '#{session_name}' | fzf) &&
  tmux attach-session -t "$session"
}
```

## Advanced Features

### Custom Preview
```bash
# File with syntax highlighting
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
fzf --bind 'ctrl-r:reload(rg --files)' \
    --bind 'ctrl-g:reload(git ls-files)'

# Live grep
fzf --disabled --bind "change:reload:rg --column --line-number --no-heading --color=always {q}"
```

## Scripting

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
ENV=$(echo -e "development\nstaging\nproduction" | \
  fzf --prompt="Environment> " --height=40%)

SERVICE=$(echo -e "api\nweb\nworker" | \
  fzf --prompt="Service> " --height=40%)

CONFIRM=$(echo -e "Yes\nNo" | \
  fzf --prompt="Deploy $SERVICE to $ENV? " --height=40%)

if [[ "$CONFIRM" == "Yes" ]]; then
  ./deploy.sh "$SERVICE" "$ENV"
fi
```

## Environment Variables

```bash
export FZF_DEFAULT_COMMAND='fd --type f'
export FZF_DEFAULT_OPTS='--height 40% --layout=reverse --border'
export FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"
export FZF_CTRL_T_OPTS="--preview 'bat --color=always --line-range :500 {}'"
export FZF_ALT_C_COMMAND='fd --type d'
export FZF_ALT_C_OPTS="--preview 'tree -C {} | head -100'"
```

## Additional Resources

See `examples.md` and `quick-reference.md`.
