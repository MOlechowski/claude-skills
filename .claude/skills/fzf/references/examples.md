# fzf Examples - Real-World Usage Patterns

## Development Workflows

### File Navigation
```bash
# Interactive file editor with preview
fe() {
  local file
  file=$(fd --type f --hidden --exclude .git | \
    fzf --preview 'bat --color=always --style=numbers --line-range=:500 {}' \
        --preview-window=right:60% \
        --height=100% \
        --reverse \
        --bind 'ctrl-/:toggle-preview') &&
  ${EDITOR:-vim} "$file"
}

# Open file in split pane
fs() {
  local file
  file=$(fzf --preview 'bat --color=always {}') &&
  tmux split-window -h "${EDITOR:-vim} $file"
}

# Multi-file editor
fv() {
  local files
  files=$(fd --type f | \
    fzf --multi \
        --preview 'bat --color=always {}' \
        --bind 'ctrl-a:select-all') &&
  ${EDITOR:-vim} $(echo "$files" | tr '\n' ' ')
}

# Recent files
recent() {
  local file
  file=$(fd --type f --changed-within 7d | \
    fzf --preview 'bat --color=always {}' \
        --header 'Files modified in last 7 days') &&
  ${EDITOR:-vim} "$file"
}
```

### Directory Navigation
```bash
# Smart cd with preview
fcd() {
  local dir
  dir=$(fd --type d --hidden --exclude .git | \
    fzf --preview 'tree -C -L 2 {}' \
        --preview-window=right:50% \
        --header 'Select directory') &&
  cd "$dir" || return
}

# Jump to project directory
proj() {
  local project
  project=$(fd --max-depth 2 --type d . ~/Projects | \
    fzf --preview 'ls -la {}' \
        --preview-window=up:40%) &&
  cd "$project" || return
}

# Bookmarked directories
bd() {
  local bookmarks="$HOME/.local/share/fzf/bookmarks"
  local dir
  dir=$(cat "$bookmarks" 2>/dev/null | \
    fzf --header 'Bookmarked directories') &&
  cd "$dir" || return
}

# Add bookmark
badd() {
  local bookmarks="$HOME/.local/share/fzf/bookmarks"
  mkdir -p "$(dirname "$bookmarks")"
  pwd >> "$bookmarks"
  echo "Added: $(pwd)"
}
```

## Git Workflows

### Branch Management
```bash
# Interactive branch checkout with preview
fco() {
  local branches branch
  branches=$(git branch -vv) &&
  branch=$(echo "$branches" | \
    fzf --preview 'git log --oneline --color=always $(echo {} | awk "{print \$1}")' \
        --preview-window=right:60% \
        --header 'Checkout branch' \
        --bind 'ctrl-/:toggle-preview') &&
  git checkout $(echo "$branch" | awk '{print $1}' | sed 's/.* //')
}

# Create new branch from selected branch
fcb() {
  local base_branch new_branch
  base_branch=$(git branch | \
    fzf --header 'Select base branch' | \
    sed 's/^[* ]* //') &&
  read -p "New branch name: " new_branch &&
  git checkout -b "$new_branch" "$base_branch"
}

# Delete merged branches
fbd() {
  local branches
  branches=$(git branch --merged | grep -v '^\*' | grep -v 'main\|master' | \
    fzf --multi \
        --header 'Select branches to delete' \
        --preview 'git log --oneline {}') &&
  echo "$branches" | xargs -I {} git branch -d {}
}

# Compare branches
fcmp() {
  local branch1 branch2
  branch1=$(git branch | fzf --header 'Select first branch') &&
  branch2=$(git branch | fzf --header 'Select second branch') &&
  git diff "${branch1// /}...${branch2// /}"
}
```

### Commit Operations
```bash
# Interactive commit browser
fshow() {
  git log --graph --color=always --format="%C(auto)%h%d %s %C(black)%C(bold)%cr" "$@" | \
    fzf --ansi --no-sort --reverse --tiebreak=index \
        --preview 'f() { set -- $(echo -- "$@" | grep -o "[a-f0-9]\{7\}"); [ $# -eq 0 ] || git show --color=always $1; }; f {}' \
        --bind 'ctrl-/:toggle-preview' \
        --bind 'enter:execute(echo {} | grep -o "[a-f0-9]\{7\}" | head -1 | xargs git show)+abort' \
        --header 'Enter: show commit | Ctrl-/: toggle preview'
}

# Cherry-pick commits
fcp() {
  local commits
  commits=$(git log --oneline --color=always | \
    fzf --ansi --multi \
        --preview 'git show --color=always {1}' \
        --header 'Select commits to cherry-pick') &&
  echo "$commits" | cut -d' ' -f1 | xargs git cherry-pick
}

# Revert commits
frev() {
  local commit
  commit=$(git log --oneline --color=always | \
    fzf --ansi \
        --preview 'git show --color=always {1}' \
        --header 'Select commit to revert') &&
  git revert $(echo "$commit" | awk '{print $1}')
}

# Interactive rebase
freb() {
  local base
  base=$(git log --oneline --color=always | \
    fzf --ansi \
        --preview 'git show --color=always {1}' \
        --header 'Select base commit') &&
  git rebase -i $(echo "$base" | awk '{print $1}')^
}
```

### File Operations
```bash
# Interactive git add
fga() {
  local files
  files=$(git status -s | \
    fzf --multi \
        --preview 'git diff --color=always {2}' \
        --preview-window=right:60% \
        --header 'Select files to stage' \
        --bind 'ctrl-/:toggle-preview') &&
  echo "$files" | awk '{print $2}' | xargs git add
}

# Interactive git restore
fgr() {
  local files
  files=$(git status -s | \
    fzf --multi \
        --preview 'git diff --color=always {2}' \
        --header 'Select files to restore') &&
  echo "$files" | awk '{print $2}' | xargs git restore
}

# Show file history
fgh() {
  local file
  file=$(git ls-files | fzf --header 'Select file') &&
  git log --follow --oneline --color=always "$file" | \
    fzf --ansi \
        --preview "git show --color=always {1}:$file" \
        --bind 'enter:execute(git show {1}:'"$file"' | less)+abort'
}

# Interactive git diff
fgd() {
  git diff --name-only | \
    fzf --multi \
        --preview 'git diff --color=always {}' \
        --preview-window=right:60% \
        --bind 'ctrl-/:toggle-preview'
}
```

## System Administration

### Process Management
```bash
# Interactive process killer with details
fkill() {
  local pid
  pid=$(ps aux | sed 1d | \
    fzf --multi \
        --header-lines=0 \
        --preview 'echo {} | awk "{print \$2}" | xargs ps -f -p' \
        --preview-window=down:40% \
        --bind 'ctrl-r:reload(ps aux | sed 1d)' | \
    awk '{print $2}')

  if [ -n "$pid" ]; then
    echo "$pid" | xargs kill -9
    echo "Killed processes: $pid"
  fi
}

# Monitor process
fmon() {
  local pid
  pid=$(ps aux | fzf --header-lines=1 | awk '{print $2}') &&
  watch -n 1 "ps -f -p $pid"
}

# Process tree explorer
fptree() {
  ps aux | \
    fzf --header-lines=1 \
        --preview 'pstree -p {2}' \
        --preview-window=right:60%
}
```

### Docker Management
```bash
# Interactive container shell
fdocker() {
  local container
  container=$(docker ps --format '{{.ID}} - {{.Names}} - {{.Image}}' | \
    fzf --header 'Select container' \
        --preview 'docker logs --tail=100 {1}' \
        --preview-window=down:40%) &&
  docker exec -it $(echo "$container" | awk '{print $1}') /bin/bash
}

# View container logs
fdlog() {
  local container
  container=$(docker ps --format '{{.ID}} - {{.Names}}' | \
    fzf --header 'Select container') &&
  docker logs -f $(echo "$container" | awk '{print $1}')
}

# Stop containers
fdstop() {
  local containers
  containers=$(docker ps --format '{{.ID}} - {{.Names}}' | \
    fzf --multi \
        --header 'Select containers to stop') &&
  echo "$containers" | awk '{print $1}' | xargs docker stop
}

# Remove images
fdrmi() {
  local images
  images=$(docker images --format '{{.ID}} - {{.Repository}}:{{.Tag}}' | \
    fzf --multi \
        --header 'Select images to remove') &&
  echo "$images" | awk '{print $1}' | xargs docker rmi
}

# Docker compose services
fdcup() {
  local service
  service=$(docker-compose config --services | \
    fzf --multi \
        --header 'Select services to start') &&
  echo "$service" | xargs docker-compose up -d
}
```

### Kubernetes
```bash
# Pod selector
fpod() {
  local pod
  pod=$(kubectl get pods --all-namespaces -o wide | \
    fzf --header-lines=1 \
        --preview 'kubectl describe pod {2} -n {1}' \
        --preview-window=right:60%) &&
  echo "$pod" | awk '{print "-n", $1, $2}'
}

# Exec into pod
fkexec() {
  local pod namespace
  pod=$(kubectl get pods --all-namespaces -o wide | \
    fzf --header-lines=1 \
        --header 'Select pod for exec') &&
  namespace=$(echo "$pod" | awk '{print $1}') &&
  pod=$(echo "$pod" | awk '{print $2}') &&
  kubectl exec -it -n "$namespace" "$pod" -- /bin/bash
}

# View pod logs
fklogs() {
  local pod namespace
  pod=$(kubectl get pods --all-namespaces | \
    fzf --header-lines=1) &&
  namespace=$(echo "$pod" | awk '{print $1}') &&
  pod=$(echo "$pod" | awk '{print $2}') &&
  kubectl logs -f -n "$namespace" "$pod"
}

# Delete pods
fkdel() {
  local pods
  pods=$(kubectl get pods --all-namespaces | \
    fzf --multi --header-lines=1 \
        --header 'Select pods to delete') &&
  echo "$pods" | while read line; do
    namespace=$(echo "$line" | awk '{print $1}')
    pod=$(echo "$line" | awk '{print $2}')
    kubectl delete pod -n "$namespace" "$pod"
  done
}
```

## Configuration and Package Management

### Environment Management
```bash
# Environment variable browser
fenv() {
  local var
  var=$(env | sort | \
    fzf --preview 'echo {}' \
        --preview-window=down:3 \
        --header 'Environment variables') &&
  echo "$var"
}

# SSH config selector
fssh() {
  local host
  host=$(grep "^Host " ~/.ssh/config | awk '{print $2}' | \
    fzf --preview 'grep -A 10 "^Host {}" ~/.ssh/config' \
        --header 'Select SSH host') &&
  ssh "$host"
}

# Tmux session manager
ftmux() {
  local session
  session=$(tmux list-sessions -F '#{session_name}' 2>/dev/null | \
    fzf --header 'Select tmux session' \
        --preview 'tmux capture-pane -pt {}') &&
  tmux attach-session -t "$session"
}
```

### Package Management
```bash
# Homebrew search and install
fbrew() {
  local package
  package=$(brew search | \
    fzf --preview 'brew info {}' \
        --preview-window=right:60% \
        --header 'Select package to install') &&
  brew install "$package"
}

# NPM package search
fnpm() {
  local package
  package=$(npm search --json . 2>/dev/null | jq -r '.[].name' | \
    fzf --preview 'npm info {}' \
        --header 'Select package to install') &&
  npm install "$package"
}

# Pip package search
fpip() {
  local package
  package=$(pip list | tail -n +3 | awk '{print $1}' | \
    fzf --preview 'pip show {}' \
        --header 'Installed packages') &&
  pip show "$package"
}
```

## Custom Tools and Scripts

### Interactive Menu System
```bash
# Main menu
main_menu() {
  local choice
  choice=$(cat << EOF | fzf --prompt="Action> " --height=50% --reverse --border
Development
Docker
Kubernetes
Packages
System
Git
Exit
EOF
  )

  case "$choice" in
    "Development") dev_menu ;;
    "Docker") docker_menu ;;
    "Kubernetes") k8s_menu ;;
    "Packages") package_menu ;;
    "System") system_menu ;;
    "Git") git_menu ;;
    *) return ;;
  esac
}

# Dev submenu
dev_menu() {
  local action
  action=$(cat << EOF | fzf --prompt="Dev> " --height=40%
Start dev server
Run tests
Build project
Lint code
Format code
Back
EOF
  )

  case "$action" in
    "Start dev server") npm run dev ;;
    "Run tests") npm test ;;
    "Build project") npm run build ;;
    "Lint code") npm run lint ;;
    "Format code") npm run format ;;
    "Back") main_menu ;;
  esac
}
```

### File Operations
```bash
# Bulk rename with preview
frename() {
  local files
  files=$(fd --type f | \
    fzf --multi \
        --preview 'bat --color=always {}' \
        --header 'Select files to rename')

  if [ -z "$files" ]; then
    return
  fi

  echo "$files" | while read file; do
    local newname
    echo "Current: $file"
    read -p "New name: " newname
    if [ -n "$newname" ]; then
      mv "$file" "$newname"
      echo "Renamed: $file -> $newname"
    fi
  done
}

# Interactive file mover
fmv() {
  local files dest
  files=$(fd --type f | \
    fzf --multi \
        --header 'Select files to move')

  if [ -z "$files" ]; then
    return
  fi

  dest=$(fd --type d | \
    fzf --header 'Select destination directory')

  if [ -n "$dest" ]; then
    echo "$files" | xargs -I {} mv {} "$dest"
    echo "Moved files to $dest"
  fi
}

# Duplicate finder
fdup() {
  fd --type f --exec md5sum {} \; | \
    sort | \
    awk '{print $1}' | \
    uniq -d | \
    while read hash; do
      fd --type f --exec md5sum {} \; | grep "^$hash"
    done | \
    fzf --multi \
        --preview 'bat --color=always {2}' \
        --header 'Duplicate files (select to delete)'
}
```

### Search and Replace
```bash
# Interactive search and replace
fsr() {
  local pattern replacement files
  read -p "Search pattern: " pattern
  read -p "Replacement: " replacement

  files=$(rg -l "$pattern" | \
    fzf --multi \
        --preview "rg --color=always '$pattern' {}" \
        --header 'Select files for replacement')

  if [ -n "$files" ]; then
    echo "$files" | xargs sed -i '' "s/$pattern/$replacement/g"
    echo "Replaced in selected files"
  fi
}

# Find and edit
ffind() {
  local query result
  read -p "Search query: " query

  result=$(rg --line-number --color=always "$query" | \
    fzf --ansi \
        --delimiter ':' \
        --preview 'bat --color=always --highlight-line {2} {1}' \
        --preview-window=right:60%:+{2}/2 \
        --bind 'enter:execute(vim +{2} {1})+abort')
}
```

### Project Management
```bash
# Project switcher
fproj() {
  local project
  project=$(fd --max-depth 2 --type d . ~/Projects ~/Work | \
    fzf --preview 'ls -la {}' \
        --preview-window=up:40% \
        --bind 'enter:execute(cd {} && $SHELL)+abort')
}

# Todo manager (with todo.txt)
ftodo() {
  local task action
  task=$(cat ~/todo.txt | \
    fzf --preview 'echo {}' \
        --header 'Select task' \
        --bind 'ctrl-d:execute(sed -i "" "/^{}/d" ~/todo.txt)+reload(cat ~/todo.txt)' \
        --bind 'ctrl-e:execute(vim ~/todo.txt)+reload(cat ~/todo.txt)')

  if [ -n "$task" ]; then
    echo "Selected: $task"
  fi
}

# Bookmark manager
fbm() {
  local bookmarks="$HOME/.bookmarks"
  local url action

  action=$(echo -e "Add\nOpen\nEdit" | fzf --header 'Bookmark manager')

  case "$action" in
    "Add")
      read -p "URL: " url
      read -p "Title: " title
      echo "$url | $title" >> "$bookmarks"
      ;;
    "Open")
      url=$(cat "$bookmarks" | \
        fzf --delimiter=' | ' \
            --with-nth=2 \
            --preview 'echo {1}') &&
      open "$(echo "$url" | awk -F' | ' '{print $1}')"
      ;;
    "Edit")
      $EDITOR "$bookmarks"
      ;;
  esac
}
```
