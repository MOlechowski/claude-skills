---
name: tree
description: "Generate directory trees for documentation. Use when: (1) creating project structure docs, (2) visualizing folder layout, (3) updating directory trees in markdown files."
---

# Tree

Generate directory trees using the system `tree` command.

## Prerequisites

Requires `tree` command installed:

```bash
# macOS
brew install tree

# Ubuntu/Debian
apt install tree

# Check if installed
which tree || echo "tree not installed"
```

## Usage

```bash
tree [path] -L <depth> -I '<pattern1>|<pattern2>'
```

**Common options:**
- `-L N` - Limit depth to N levels
- `-I 'pattern'` - Ignore patterns (pipe-separated)
- `-d` - Directories only
- `--noreport` - Omit file/directory count at end

## Examples

**Basic tree with depth 3:**
```bash
tree -L 3
```

**Ignore common directories:**
```bash
tree -L 3 -I 'node_modules|.git|__pycache__|.venv|dist|build|coverage'
```

**Directories only:**
```bash
tree -d -L 2
```

**Specific path:**
```bash
tree src -L 2
```

## Standard Ignore Pattern

Use this for most projects:

```bash
tree -L 3 -I 'node_modules|.git|__pycache__|.venv|venv|dist|build|.next|.cache|coverage|.pytest_cache|.mypy_cache|.DS_Store|.idea|.vscode'
```

## Output Format

```
project/
├── src/
│   ├── components/
│   │   ├── Button.tsx
│   │   └── Modal.tsx
│   └── utils/
│       └── helpers.ts
├── tests/
│   └── Button.test.tsx
├── package.json
└── README.md
```

## Error Handling

If `tree` is not installed, the command will fail. Install it using the instructions above.
