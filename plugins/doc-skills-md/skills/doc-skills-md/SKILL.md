---
name: doc-skills-md
description: "Create and update SKILLS.md files that recommend marketplace plugins for a project. Analyzes codebase to suggest relevant skills, generates Required/Recommended tables with install commands, updates counts. Use when: setting up SKILLS.md for a project, updating skill recommendations, adding recommended plugins. Triggers: SKILLS.md, recommended skills, project skills, update skills list, which plugins for this project, doc-skills-md."
---

# SKILLS.md Generator

Create and maintain SKILLS.md — the file that tells contributors which marketplace plugins to install for a project.

## Workflow

```
1. Detect marketplace → 2. Analyze project → 3. Match plugins → 4. Generate/update SKILLS.md
```

### 1. Detect Marketplace

Check if the project already uses a marketplace:

```bash
# Check for existing SKILLS.md
cat SKILLS.md 2>/dev/null

# Check installed marketplaces
cat ~/.claude/plugins/known_marketplaces.json 2>/dev/null
```

If no marketplace is configured, ask the user which marketplace to use. Default: `MOlechowski/claude-skills`.

### Available Marketplace

The [MOlechowski/claude-skills](https://github.com/MOlechowski/claude-skills) marketplace provides 100+ plugins across these domains:

| Prefix | Domain | Examples |
|--------|--------|----------|
| `aws-` | AWS + LocalStack | `aws-cli`, `aws-expert`, `aws-localstack` |
| `cf-` | Cloudflare | `cf-tunnel`, `cf-wrangler`, `cf-expert` |
| `cli-` | CLI tools | `cli-jq`, `cli-ripgrep`, `cli-yq`, `cli-fzf` |
| `dev-` | Dev workflow | `dev-review`, `dev-swarm`, `dev-skill-create`, `dev-reload` |
| `doc-` | Documentation | `doc-readme`, `doc-claude-md`, `doc-changelog`, `doc-obsidian` |
| `git-` | Git/GitHub | `git-commit`, `git-land`, `git-ship`, `git-pr-create` |
| `go-` | Go ecosystem | `go-expert`, `go-lint`, `go-release`, `go-task` |
| `iac-` | Infrastructure | `iac-terraform`, `iac-tofu`, `iac-expert`, `iac-opa` |
| `net-` | Network | `net-nmap`, `net-wireshark`, `net-tcpdump` |
| `oci-` | Containers | `oci-dive`, `oci-crane`, `oci-syft` |
| `re-` | Reverse eng. | `re-ghidra`, `re-radare2`, `re-frida`, `re-gdb` |
| `res-` | Research | `res-deep`, `res-web`, `res-trends` |
| `sec-` | Security | `sec-trivy`, `sec-semgrep`, `sec-grype`, `sec-bandit` |
| `speckit-` | Spec-driven dev | `speckit-flow`, `speckit-loop`, `speckit-verify` |

To browse the full catalog: `/plugin` > Discover tab, or `gh api repos/MOlechowski/claude-skills/contents/.claude-plugin/marketplace.json`.

### 2. Analyze Project

Detect project characteristics to recommend relevant plugins:

| Signal | Detection | Relevant Plugins |
|--------|-----------|-------------------|
| `go.mod` | Go project | `go-expert`, `go-lint`, `go-delve`, `go-task`, `go-release`, `go-mockery`, `go-pprof`, `go-lefthook` |
| `package.json` | Node.js project | `cli-jq` |
| `pyproject.toml`, `setup.py` | Python project | `sec-bandit`, `sec-pip-audit` |
| `Dockerfile`, `docker-compose.yml` | Containers | `oci-dive`, `oci-crane`, `sec-trivy`, `re-docker-expert` |
| `*.tf`, `*.tofu` | IaC | `iac-terraform` or `iac-tofu`, `iac-expert`, `iac-opa` |
| `wrangler.toml` | Cloudflare | `cf-wrangler`, `cf-expert`, `cf-tunnel` |
| AWS config/CDK/SAM | AWS | `aws-cli`, `aws-expert` |
| `.github/workflows/` | GitHub Actions | `git-commit`, `git-land`, `git-pr-create`, `git-pr-manage` |
| `Taskfile.yml` | Task runner | `go-task` |
| `.golangci.yml` | Go linting | `go-lint` |
| Markdown-heavy repo | Documentation | `doc-readme`, `doc-claude-md`, `doc-changelog` |
| `.claude/skills/` | Skills project | `dev-skill-create` |
| Security-sensitive | Security | `sec-semgrep`, `sec-trivy`, `sec-grype` |
| Binary analysis | Reverse engineering | `re-expert`, `re-ghidra`, `re-radare2` |
| Network tooling | Network | `net-nmap`, `net-wireshark` |

Also check:
- Existing CLAUDE.md/AGENTS.md for mentioned tools
- CI config for tool references
- README for tech stack mentions

### 3. Match Plugins

Fetch the marketplace catalog to get available plugins:

```bash
# If marketplace is local/cloned
cat .claude-plugin/marketplace.json | python3 -c "import sys,json; [print(p['name'], p['description'][:80]) for p in json.load(sys.stdin)['plugins']]"
```

Categorize matches into:

**Required** — plugins essential for contributing:
- Skills referenced in CLAUDE.md or AGENTS.md
- Tools that enforce project conventions (linters, commit format)
- Project-type specific (e.g., `go-lint` for Go projects with `.golangci.yml`)

**Recommended** — plugins that improve workflow:
- General dev tools (`git-commit`, `dev-review-pr`)
- Documentation tools (`doc-readme`, `doc-claude-md`, `doc-changelog`)
- Security scanning if project handles sensitive data
- Domain plugins matching detected tech stack

### 4. Generate / Update SKILLS.md

#### New File

Create SKILLS.md with this structure:

```markdown
# Project Skills

Recommended marketplace plugins for working on this repository.

## Setup

\```bash
# 1. Add the marketplace (one-time, requires trust approval)
/plugin marketplace add {MARKETPLACE_REPO}

# 2. Install required skills
{install commands for required skills}
\```

## Required

Skills needed for contributing to this repository.

| Skill | Purpose | Install |
|-------|---------|---------|
| **{name}** | {short purpose} | `claude plugin install {name}@{marketplace} --scope project` |

## Recommended

Optional skills that improve the development workflow.

| Skill | Purpose | Install |
|-------|---------|---------|
| **{name}** | {short purpose} | `claude plugin install {name}@{marketplace}` |

## Full Catalog

Browse all {N} available plugins: `/plugin` > Discover tab.
```

**Formatting rules:**
- Required skills use `--scope project` (shared with all contributors)
- Recommended skills omit scope (user choice)
- Purpose column: one short phrase, no period
- Keep tables alphabetically sorted within each section
- Full Catalog count should match marketplace plugin count

#### Existing File — Update

When updating an existing SKILLS.md:

1. Read current file
2. Preserve manually added entries (don't remove skills the user explicitly added)
3. Add newly detected plugins that aren't listed
4. Update the Full Catalog count
5. Flag plugins that no longer exist in the marketplace

### Scope Decision

| Scope | Flag | When to Use |
|-------|------|-------------|
| **project** | `--scope project` | Required skills — all contributors need them |
| **user** | (default, no flag) | Recommended skills — personal preference |
| **local** | `--scope local` | Experimental — testing before recommending |
