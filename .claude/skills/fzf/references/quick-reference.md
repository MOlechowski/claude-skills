# fzf Quick Reference

## Basic Command
```bash
fzf [OPTIONS]
command | fzf [OPTIONS]
```

## Flags

| Flag | Description |
|------|-------------|
| `-m` / `--multi` | Multi-select |
| `--reverse` | Prompt at top |
| `--height <height>` | Window height (40%, 100%) |
| `--border` | Draw border |
| `--preview <cmd>` | Preview command (`{}` = item) |
| `--preview-window <opts>` | Preview options |
| `--prompt <string>` | Custom prompt |
| `--header <string>` | Header line |

## Keybindings

| Key | Action |
|-----|--------|
| `Ctrl-J` / `Down` | Cursor down |
| `Ctrl-K` / `Up` | Cursor up |
| `Enter` | Select and exit |
| `Ctrl-C` / `Esc` | Exit |
| `Tab` | Toggle selection |
| `Ctrl-A` | Select all |
| `Ctrl-D` | Deselect all |
| `Ctrl-U` | Clear query |

## Search Syntax

| Pattern | Description |
|---------|-------------|
| `term` | Fuzzy match |
| `'term` | Exact match |
| `^term` | Prefix match |
| `term$` | Suffix match |
| `!term` | Negation |
| `term1 term2` | AND (both) |
| `term1 \| term2` | OR (either) |

## Preview Window

```bash
--preview-window=right:50%
--preview-window=up:40%
--preview-window=hidden
--preview-window=right:50%:border:wrap
```

## Key Binding Actions

| Action | Description |
|--------|-------------|
| `execute(<cmd>)` | Execute command |
| `reload(<cmd>)` | Reload list |
| `toggle-preview` | Show/hide preview |
| `select-all` | Select all |
| `abort` | Exit |

## Custom Bindings

```bash
fzf --bind 'ctrl-d:execute(rm {})'
fzf --bind 'enter:execute(vim {})+abort'
fzf --bind 'ctrl-r:reload(find . -type f)'
fzf --bind 'ctrl-/:toggle-preview'
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
```

## Quick Patterns

```bash
vim $(fzf)
cd $(find . -type d | fzf)
git checkout $(git branch | fzf | sed 's/^[* ]*//')
ps aux | fzf | awk '{print $2}' | xargs kill
docker exec -it $(docker ps | fzf --header-lines=1 | awk '{print $1}') /bin/bash
history | fzf --tac
```

## Common Combos

```bash
# File browser
fd --type f | fzf --preview 'bat --color=always {}' \
  --preview-window=right:60% --height=100% --reverse --border

# Git log
git log --oneline | fzf --preview 'git show --color=always {1}' \
  --preview-window=right:60% --bind 'ctrl-/:toggle-preview'

# Multi-select
find . -type f | fzf --multi --preview 'head -100 {}' \
  --bind 'ctrl-a:select-all'

# Menu
cat << EOF | fzf --prompt="Action> " --height=40%
Build
Test
Deploy
EOF
```

## Preview Commands

```bash
--preview 'cat {}'
--preview 'bat --color=always {}'
--preview 'tree -C {}'
--preview 'git show --color=always {1}'
--preview 'jq -C . {}'
--preview '[[ -d {} ]] && tree {} || bat {}'
```

## Aliases

```bash
alias ff='fd --type f | fzf --preview "bat --color=always {}"'
alias fcd='cd $(fd --type d | fzf)'
alias fco='git checkout $(git branch | fzf | sed "s/^[* ]*//")'
alias fkill='ps aux | fzf --header-lines=1 | awk "{print \$2}" | xargs kill -9'
alias fv='vim $(fzf)'
```

## Debugging

```bash
command -v fzf              # Check installed
fzf --version               # Version
echo -e "test1\ntest2" | fzf  # Basic test
```
