---
name: fzf
description: |
  Expert guidance for fzf, a blazingly fast command-line fuzzy finder that enables interactive filtering and selection of lists, files, command history, processes, and any line-oriented data.

  Use this skill when:
  - Interactively searching through files, directories, or command history
  - Building interactive selection menus for shell scripts
  - Filtering large lists or command outputs
  - Creating powerful keyboard-driven workflows
  - Integrating fuzzy search into custom tools and aliases

  Examples:
  - "Create interactive file selector for editing"
  - "Search command history with preview"
  - "Build git branch selector with fuzzy search"
  - "Filter running processes and kill selected"
  - "Create custom fuzzy file finder with preview"
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

## Installation

```bash
# macOS (Homebrew)
brew install fzf
# Install key bindings and fuzzy completion
$(brew --prefix)/opt/fzf/install

# Linux (apt)
sudo apt install fzf

# Linux (git)
git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
~/.fzf/install

# Verify installation
fzf --version
```

## Basic Usage

### Simple Selection
```bash
# Select from list
echo -e "apple\nbanana\ncherry" | fzf

# Select file in current directory
find . -type f | fzf

# Select from command output
ls | fzf

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
Ctrl-W           Delete word
```

## Search Syntax

### Fuzzy Matching
```bash
# Fuzzy match (default)
fzf  # Type "abc" → matches "a_b_c", "a123b456c", etc.

# Exact match (prefix with ')
fzf  # Type "'exact" → matches "exact" only

# Prefix match (suffix with ^)
fzf  # Type "^start" → matches lines starting with "start"

# Suffix match (prefix with $)
fzf  # Type "end$" → matches lines ending with "end"

# Negation (prefix with !)
fzf  # Type "!exclude" → matches lines not containing "exclude"
```

### Combining Patterns
```bash
# AND (space-separated)
# Type "foo bar" → matches lines with both "foo" AND "bar"

# OR (pipe-separated)
# Type "foo | bar" → matches lines with "foo" OR "bar"

# Complex combinations
# Type "^start end$ !exclude" → lines starting with "start", ending with "end", not containing "exclude"
```

## Options and Customization

### Display Options
```bash
# Multi-select
fzf --multi

# Reverse layout (prompt at top)
fzf --reverse

# Full screen height
fzf --height 100%

# Partial height
fzf --height 40%

# Border
fzf --border

# Prompt text
fzf --prompt "Select file> "

# Header
fzf --header "Choose an option"

# Info style
fzf --info=inline  # Show info inline
fzf --info=hidden  # Hide info
```

### Search Behavior
```bash
# Case-sensitive
fzf --case-sensitive

# Exact match by default
fzf --exact

# Enable multi-line matching
fzf --multi-line

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

# Scroll preview
fzf --preview 'cat {}' --bind 'ctrl-d:preview-page-down,ctrl-u:preview-page-up'

# Custom preview command
fzf --preview 'bat --color=always --style=numbers {}'

# Preview for different file types
fzf --preview '[[ -f {} ]] && bat --color=always {} || tree -C {}'
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

# Toggle selection
fzf --bind 'ctrl-t:toggle'

# Select all
fzf --bind 'ctrl-a:select-all'

# Deselect all
fzf --bind 'ctrl-d:deselect-all'

# Execute command and reload
fzf --bind 'ctrl-r:reload(git branch | cut -c 3-)'

# Print query
fzf --bind 'ctrl-e:print-query'
```

### Custom Actions
```bash
# Multiple bindings
fzf --bind 'ctrl-e:execute(echo {} >> selected.txt)' \
    --bind 'ctrl-d:execute(rm {})'

# Chain actions
fzf --bind 'enter:execute(vim {})+abort'

# Conditional execution
fzf --bind 'enter:execute-silent([ -d {} ] && ls {} || cat {})'
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

# Better file finder with bat preview
fd --type f | fzf --preview 'bat --color=always --style=numbers --line-range=:500 {}'
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

# Search commits
git log --oneline | fzf --preview 'git show --color=always {1}'

# Delete merged branches
git branch --merged | fzf --multi | xargs -I {} git branch -d {}
```

### Process Management
```bash
# Kill process
ps aux | fzf | awk '{print $2}' | xargs kill

# With preview showing process details
ps aux | fzf --preview 'ps -f -p {2}' | awk '{print $2}' | xargs kill -9

# Interactive htop-style selector
ps aux | fzf --header-lines=1 --preview 'pstree -p {2}'
```

### Command History
```bash
# Search command history (Ctrl-R)
# Already bound if you ran fzf installer

# Manual history search
history | fzf --tac | sed 's/^[[:space:]]*[0-9]*[[:space:]]*//'

# Execute selected command
eval "$(history | fzf --tac | sed 's/^[[:space:]]*[0-9]*[[:space:]]*//')"
```

### Environment Variables
```bash
# Select and export env var
export VAR=$(env | fzf | cut -d= -f1)

# Browse environment
env | fzf --preview 'echo {}'
```

## Shell Integration

### Bash/Zsh Keybindings
After running `fzf` installer:

```bash
# Ctrl-T: Paste selected files/directories
# Usage: vim <Ctrl-T>

# Ctrl-R: Command history
# Usage: <Ctrl-R> to search history

# Alt-C: Change directory
# Usage: <Alt-C> to fuzzy cd
```

### Custom Functions

**Interactive Git Branch Checkout:**
```bash
# ~/.bashrc or ~/.zshrc
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

**Interactive Docker Container:**
```bash
fdc() {
  local container
  container=$(docker ps | fzf --header-lines=1 | awk '{print $1}') &&
  docker exec -it "$container" /bin/bash
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

# Image preview (with chafa or catimg)
fzf --preview 'chafa {}'

# JSON preview
find . -name "*.json" | fzf --preview 'jq -C . {}'
```

### Dynamic Reloading
```bash
# Reload based on input
fzf --bind 'ctrl-r:reload(rg --files)' \
    --bind 'ctrl-g:reload(git ls-files)'

# Search with ripgrep reload
rg --files | fzf --bind "change:reload:rg --files | rg {q}"

# Live grep
fzf --disabled --bind "change:reload:rg --column --line-number --no-heading --color=always {q}"
```

### Custom Color Scheme
```bash
# Dark theme
fzf --color=dark \
    --color=fg:#d0d0d0,bg:#1a1a1a,hl:#5f87af \
    --color=fg+:#ffffff,bg+:#262626,hl+:#5fd7ff

# Light theme
fzf --color=light \
    --color=fg:#3c3836,bg:#fbf1c7,hl:#9d0006

# Nord theme
fzf --color=bg+:#3b4252,bg:#2e3440,spinner:#81a1c1,hl:#616e88 \
    --color=fg:#d8dee9,header:#616e88,info:#81a1c1,pointer:#81a1c1 \
    --color=marker:#81a1c1,fg+:#d8dee9,prompt:#81a1c1,hl+:#81a1c1
```

### Headers and Layout
```bash
# Multi-line header
fzf --header=$'First line\nSecond line\nThird line'

# Header from file
fzf --header="$(cat header.txt)"

# Layout options
fzf --layout=reverse  # Prompt at top
fzf --layout=default  # Prompt at bottom
fzf --layout=reverse-list  # Reverse list order

# Padding
fzf --padding=1,2,3,4  # top, right, bottom, left
```

## Scripting with fzf

### Menu Builder
```bash
#!/bin/bash
option=$(cat << EOF | fzf --prompt="Select action> "
Build project
Run tests
Deploy to staging
Deploy to production
View logs
EOF
)

case "$option" in
  "Build project") make build ;;
  "Run tests") npm test ;;
  "Deploy to staging") ./deploy.sh staging ;;
  "Deploy to production") ./deploy.sh production ;;
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
  echo "Deploying $SERVICE to $ENV..."
  ./deploy.sh "$SERVICE" "$ENV"
fi
```

### File Browser
```bash
#!/bin/bash
while true; do
  file=$(find . -type f -o -type d | \
    fzf --preview='[[ -d {} ]] && ls -la {} || bat --color=always {}' \
    --preview-window=right:60% \
    --bind 'ctrl-/:toggle-preview' \
    --header 'Enter: Open | Ctrl-C: Exit')

  [[ -z "$file" ]] && break

  if [[ -d "$file" ]]; then
    cd "$file"
  else
    ${EDITOR:-vim} "$file"
  fi
done
```

## Performance Tips

### Large Lists
```bash
# Stream large lists
find / -type f 2>/dev/null | fzf

# Limit initial results
fzf --height 40% --reverse

# Use fast file finder
fd --type f | fzf  # Faster than find

# Parallel processing
fd | fzf --preview 'bat --color=always {}'
```

### Fast Preview
```bash
# Limit preview lines
fzf --preview 'head -100 {}'

# Use faster preview tool
fzf --preview 'bat --color=always --line-range :500 {}'

# Conditional preview
fzf --preview '[[ $(wc -l < {}) -lt 1000 ]] && bat {} || echo "File too large"'
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
- Skip preview for complex selections

### Tips
- Install shell integrations for Ctrl-R, Ctrl-T, Alt-C
- Set `FZF_DEFAULT_OPTS` for global config
- Use `FZF_DEFAULT_COMMAND` for custom file listing
- Combine with `bat`, `fd`, `rg` for better UX
- Create aliases for common patterns
- Use `--bind` for workflow-specific actions

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

# Ctrl-R options
export FZF_CTRL_R_OPTS="--preview 'echo {}' --preview-window down:3:wrap"
```

## Troubleshooting

### Common Issues
```bash
# No results shown
# → Check if input is piped correctly
echo "test" | fzf  # Should work

# Preview not working
# → Check preview command
fzf --preview 'echo {}' <<< "test"

# Key binding not working
# → Re-run installer
$(brew --prefix)/opt/fzf/install

# Colors not showing
# → Check terminal supports colors
export TERM=xterm-256color
```

## Additional Resources

- Official Repository: https://github.com/junegunn/fzf
- Wiki Examples: https://github.com/junegunn/fzf/wiki
- Advanced Examples: https://github.com/junegunn/fzf/wiki/examples
- Color Schemes: https://github.com/junegunn/fzf/wiki/Color-schemes

When providing fzf guidance, emphasize interactive workflows, suggest useful key bindings, recommend preview windows for context, and show integration patterns with other tools.
