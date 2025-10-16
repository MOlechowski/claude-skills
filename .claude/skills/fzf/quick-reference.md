# fzf Quick Reference

## Basic Command
```bash
fzf [OPTIONS]
command | fzf [OPTIONS]
```

## Essential Flags

| Flag | Description |
|------|-------------|
| `-m` / `--multi` | Enable multi-select with Tab |
| `--reverse` | Prompt at top, list below |
| `--height <height>` | Height of fzf window (e.g., 40%, 100%) |
| `--border` | Draw border around window |
| `--preview <cmd>` | Preview command (use `{}` for item) |
| `--preview-window <opts>` | Preview window options |
| `--prompt <string>` | Custom prompt string |
| `--header <string>` | Header line |

## Default Keybindings

| Key | Action |
|-----|--------|
| `Ctrl-J` / `Down` | Move cursor down |
| `Ctrl-K` / `Up` | Move cursor up |
| `Enter` | Select and exit |
| `Ctrl-C` / `Esc` | Exit without selection |
| `Tab` | Toggle selection (multi mode) |
| `Shift-Tab` | Deselect (multi mode) |
| `Ctrl-A` | Select all |
| `Ctrl-D` | Deselect all |
| `Ctrl-U` | Clear query |
| `Ctrl-W` | Delete word backward |

## Search Syntax

| Pattern | Description | Example |
|---------|-------------|---------|
| `term` | Fuzzy match | `abc` matches `a_b_c` |
| `'term` | Exact match | `'exact` matches only `exact` |
| `^term` | Prefix match | `^start` matches lines starting with `start` |
| `term$` | Suffix match | `end$` matches lines ending with `end` |
| `!term` | Negation | `!exclude` excludes lines with `exclude` |
| `term1 term2` | AND (both) | `foo bar` matches lines with both |
| `term1 \| term2` | OR (either) | `foo \| bar` matches lines with either |

## Preview Window Options

```bash
# Position and size
--preview-window=right:50%     # Right side, 50% width
--preview-window=up:40%        # Top, 40% height
--preview-window=down:3        # Bottom, 3 lines
--preview-window=left:50%      # Left side, 50% width

# Visibility
--preview-window=hidden        # Hidden by default
--preview-window=nohidden      # Visible by default

# Border
--preview-window=border        # With border
--preview-window=noborder      # Without border

# Scroll
--preview-window=follow        # Auto-scroll to match
--preview-window=nofollow      # No auto-scroll

# Wrap
--preview-window=wrap          # Wrap long lines
--preview-window=nowrap        # Don't wrap

# Combined
--preview-window=right:50%:border:wrap
```

## Key Binding Actions

| Action | Description |
|--------|-------------|
| `execute(<cmd>)` | Execute command |
| `execute-silent(<cmd>)` | Execute without output |
| `reload(<cmd>)` | Reload list |
| `toggle-preview` | Show/hide preview |
| `preview-up/down` | Scroll preview |
| `preview-page-up/down` | Page scroll preview |
| `toggle` | Toggle selection |
| `select-all` | Select all items |
| `deselect-all` | Deselect all |
| `print-query` | Print query string |
| `abort` | Exit fzf |

## Custom Bindings

```bash
# Single binding
fzf --bind 'ctrl-d:execute(rm {})'

# Multiple bindings
fzf --bind 'ctrl-e:execute(echo {})' \
    --bind 'ctrl-d:execute(rm {})'

# Chain actions
fzf --bind 'enter:execute(vim {})+abort'

# Reload
fzf --bind 'ctrl-r:reload(find . -type f)'

# Toggle preview
fzf --bind 'ctrl-/:toggle-preview'

# Preview scroll
fzf --bind 'ctrl-u:preview-page-up' \
    --bind 'ctrl-d:preview-page-down'
```

## Shell Integration (after installer)

| Key | Action |
|-----|--------|
| `Ctrl-T` | Paste selected files/directories |
| `Ctrl-R` | Search command history |
| `Alt-C` | Change directory |

## Environment Variables

```bash
# Default command (file listing)
export FZF_DEFAULT_COMMAND='fd --type f'

# Default options
export FZF_DEFAULT_OPTS='--height 40% --reverse --border'

# Ctrl-T options
export FZF_CTRL_T_OPTS="--preview 'bat --color=always {}'"

# Alt-C options
export FZF_ALT_C_OPTS="--preview 'tree -C {}'"

# Ctrl-R options
export FZF_CTRL_R_OPTS="--preview 'echo {}' --preview-window down:3:wrap"
```

## Quick Patterns

```bash
# Basic selection
echo -e "option1\noption2\noption3" | fzf

# File selection
find . -type f | fzf

# With preview
find . -type f | fzf --preview 'cat {}'

# Multi-select
find . -type f | fzf --multi

# Open file in editor
vim $(fzf)

# Change directory
cd $(find . -type d | fzf)

# Git branch checkout
git checkout $(git branch | fzf | sed 's/^[* ]*//')

# Kill process
ps aux | fzf | awk '{print $2}' | xargs kill

# Search and edit
rg --files | fzf --preview 'bat --color=always {}' | xargs vim

# Docker container exec
docker exec -it $(docker ps | fzf --header-lines=1 | awk '{print $1}') /bin/bash

# Environment variable
export VAR=$(env | fzf | cut -d= -f1)

# Command history
history | fzf --tac

# Kubernetes pod
kubectl exec -it $(kubectl get pods | fzf --header-lines=1 | awk '{print $1}') -- /bin/bash

# Homebrew package
brew install $(brew search | fzf)
```

## Common Options Combos

```bash
# File browser with preview
fd --type f | fzf \
  --preview 'bat --color=always --style=numbers {}' \
  --preview-window=right:60% \
  --height=100% \
  --reverse \
  --border

# Interactive git log
git log --oneline | fzf \
  --preview 'git show --color=always {1}' \
  --preview-window=right:60% \
  --bind 'ctrl-/:toggle-preview'

# Multi-select with preview
find . -type f | fzf \
  --multi \
  --preview 'head -100 {}' \
  --bind 'ctrl-a:select-all' \
  --bind 'ctrl-d:deselect-all'

# Custom menu
cat << EOF | fzf --prompt="Action> " --height=40%
Build
Test
Deploy
Rollback
EOF

# Directory browser
fd --type d | fzf \
  --preview 'tree -C -L 2 {}' \
  --bind 'enter:execute(cd {})+abort'
```

## Preview Commands

```bash
# File content
--preview 'cat {}'
--preview 'bat --color=always {}'
--preview 'head -100 {}'

# Directory listing
--preview 'ls -la {}'
--preview 'tree -C {}'
--preview 'exa --tree --level=2 {}'

# Git
--preview 'git log -p {}'
--preview 'git show --color=always {1}'
--preview 'git diff --color=always {}'

# JSON
--preview 'jq -C . {}'

# YAML
--preview 'bat --color=always --language yaml {}'

# Image (with chafa)
--preview 'chafa {}'

# PDF (with pdftotext)
--preview 'pdftotext {} - | head -100'

# Markdown (with glow)
--preview 'glow -s dark {}'

# Code with syntax highlighting
--preview 'bat --color=always --style=numbers {}'

# Conditional preview
--preview '[[ -d {} ]] && tree {} || bat {}'
```

## Layout Options

```bash
# Reverse (prompt at top)
fzf --reverse

# Height
fzf --height 40%        # 40% of terminal height
fzf --height 100%       # Full screen
fzf --height 20         # 20 lines

# Border
fzf --border            # With border
fzf --border=rounded    # Rounded corners
fzf --border=sharp      # Sharp corners

# Info style
fzf --info=inline       # Inline info
fzf --info=hidden       # Hide info

# Padding
fzf --padding=1         # 1 space padding
fzf --padding=1,2,3,4   # Custom padding (top, right, bottom, left)

# Margin
fzf --margin=1,2,3,4    # Custom margin
```

## Useful Aliases

```bash
# File finder with preview
alias ff='fd --type f | fzf --preview "bat --color=always {}"'

# Directory changer
alias fcd='cd $(fd --type d | fzf)'

# Git branch checkout
alias fco='git checkout $(git branch | fzf | sed "s/^[* ]*//")'

# Kill process
alias fkill='ps aux | fzf --header-lines=1 | awk "{print \$2}" | xargs kill -9'

# Docker container shell
alias fdocker='docker exec -it $(docker ps | fzf --header-lines=1 | awk "{print \$1}") /bin/bash'

# Vim with fuzzy file find
alias fv='vim $(fzf)'

# History search and execute
alias fh='eval $(history | fzf --tac | sed "s/^[[:space:]]*[0-9]*[[:space:]]*//")'
```

## Debugging

```bash
# Check if fzf is installed
command -v fzf

# Show version
fzf --version

# Test basic functionality
echo -e "test1\ntest2\ntest3" | fzf

# Test preview
echo "test" | fzf --preview 'echo {}'

# Verbose mode (for bindings)
fzf --bind 'ctrl-t:execute(echo {})+abort' --verbose
```
