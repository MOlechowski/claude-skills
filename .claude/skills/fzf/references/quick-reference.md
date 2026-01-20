# fzf Quick Reference

## Basic Command
```bash
fzf [OPTIONS]
command | fzf [OPTIONS]
```

## Essential Flags

| Flag | Description |
|------|-------------|
| `-m` / `--multi` | Enable multi-select |
| `--reverse` | Prompt at top |
| `--height <height>` | Window height (40%, 100%) |
| `--border` | Draw border |
| `--preview <cmd>` | Preview command (`{}` = item) |
| `--preview-window <opts>` | Preview options |
| `--prompt <string>` | Custom prompt |
| `--header <string>` | Header line |

## Default Keybindings

| Key | Action |
|-----|--------|
| `Ctrl-J` / `Down` | Cursor down |
| `Ctrl-K` / `Up` | Cursor up |
| `Enter` | Select and exit |
| `Ctrl-C` / `Esc` | Exit |
| `Tab` | Toggle selection |
| `Shift-Tab` | Deselect |
| `Ctrl-A` | Select all |
| `Ctrl-D` | Deselect all |
| `Ctrl-U` | Clear query |
| `Ctrl-W` | Delete word |

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
# Position/size
--preview-window=right:50%
--preview-window=up:40%
--preview-window=down:3
--preview-window=left:50%

# Visibility
--preview-window=hidden
--preview-window=nohidden

# Border/scroll/wrap
--preview-window=border
--preview-window=follow
--preview-window=wrap

# Combined
--preview-window=right:50%:border:wrap
```

## Key Binding Actions

| Action | Description |
|--------|-------------|
| `execute(<cmd>)` | Execute command |
| `execute-silent(<cmd>)` | Execute silently |
| `reload(<cmd>)` | Reload list |
| `toggle-preview` | Show/hide preview |
| `preview-up/down` | Scroll preview |
| `preview-page-up/down` | Page scroll |
| `toggle` | Toggle selection |
| `select-all` | Select all |
| `deselect-all` | Deselect all |
| `print-query` | Print query |
| `abort` | Exit |

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

## Shell Integration

| Key | Action |
|-----|--------|
| `Ctrl-T` | Paste files |
| `Ctrl-R` | Search history |
| `Alt-C` | Change directory |

## Environment Variables

```bash
export FZF_DEFAULT_COMMAND='fd --type f'
export FZF_DEFAULT_OPTS='--height 40% --reverse --border'
export FZF_CTRL_T_OPTS="--preview 'bat --color=always {}'"
export FZF_ALT_C_OPTS="--preview 'tree -C {}'"
export FZF_CTRL_R_OPTS="--preview 'echo {}' --preview-window down:3:wrap"
```

## Quick Patterns

```bash
echo -e "option1\noption2\noption3" | fzf
find . -type f | fzf
find . -type f | fzf --preview 'cat {}'
find . -type f | fzf --multi
vim $(fzf)
cd $(find . -type d | fzf)
git checkout $(git branch | fzf | sed 's/^[* ]*//')
ps aux | fzf | awk '{print $2}' | xargs kill
rg --files | fzf --preview 'bat --color=always {}' | xargs vim
docker exec -it $(docker ps | fzf --header-lines=1 | awk '{print $1}') /bin/bash
export VAR=$(env | fzf | cut -d= -f1)
history | fzf --tac
kubectl exec -it $(kubectl get pods | fzf --header-lines=1 | awk '{print $1}') -- /bin/bash
brew install $(brew search | fzf)
```

## Common Combos

```bash
# File browser
fd --type f | fzf \
  --preview 'bat --color=always --style=numbers {}' \
  --preview-window=right:60% \
  --height=100% --reverse --border

# Git log
git log --oneline | fzf \
  --preview 'git show --color=always {1}' \
  --preview-window=right:60% \
  --bind 'ctrl-/:toggle-preview'

# Multi-select
find . -type f | fzf --multi \
  --preview 'head -100 {}' \
  --bind 'ctrl-a:select-all' \
  --bind 'ctrl-d:deselect-all'

# Menu
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
# Files
--preview 'cat {}'
--preview 'bat --color=always {}'
--preview 'head -100 {}'

# Directories
--preview 'ls -la {}'
--preview 'tree -C {}'

# Git
--preview 'git log -p {}'
--preview 'git show --color=always {1}'
--preview 'git diff --color=always {}'

# Formats
--preview 'jq -C . {}'     # JSON
--preview 'glow -s dark {}'  # Markdown
--preview 'chafa {}'         # Image

# Conditional
--preview '[[ -d {} ]] && tree {} || bat {}'
```

## Layout Options

```bash
fzf --reverse           # Prompt at top
fzf --height 40%        # Partial height
fzf --height 100%       # Full screen
fzf --border            # With border
fzf --border=rounded    # Rounded
fzf --info=inline       # Inline info
fzf --padding=1         # 1 space padding
fzf --margin=1,2,3,4    # Custom margin
```

## Aliases

```bash
alias ff='fd --type f | fzf --preview "bat --color=always {}"'
alias fcd='cd $(fd --type d | fzf)'
alias fco='git checkout $(git branch | fzf | sed "s/^[* ]*//")'
alias fkill='ps aux | fzf --header-lines=1 | awk "{print \$2}" | xargs kill -9'
alias fdocker='docker exec -it $(docker ps | fzf --header-lines=1 | awk "{print \$1}") /bin/bash'
alias fv='vim $(fzf)'
alias fh='eval $(history | fzf --tac | sed "s/^[[:space:]]*[0-9]*[[:space:]]*//")'
```

## Debugging

```bash
command -v fzf                     # Check installed
fzf --version                       # Version
echo -e "test1\ntest2" | fzf        # Basic test
echo "test" | fzf --preview 'echo {}' # Test preview
```
