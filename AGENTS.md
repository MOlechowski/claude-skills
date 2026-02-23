---
last_validated: 2026-02-24T00:00:00Z
project_type: plugin-marketplace
skill_count: 105
---

# Agent Instructions: claude-skills

This file provides guidance to Claude Code when working with code in this repository.

## Repository Overview

This is a Claude Skills **plugin marketplace** following Anthropic's Agent Skills framework. Each skill is packaged as an individual plugin, allowing users to install and enable only the skills they need via `/plugin install` and `/plugin enable/disable`.

## Repository Structure

```
.
├── .claude-plugin/
│   └── marketplace.json           # Marketplace catalog (105 plugins)
├── plugins/                       # 105 individual skill plugins
│   ├── aws-cli/
│   │   ├── .claude-plugin/
│   │   │   └── plugin.json        # Plugin metadata (name, version, description)
│   │   └── skills/
│   │       └── aws-cli/
│   │           ├── SKILL.md       # Main skill definition
│   │           └── references/    # Optional supporting files
│   ├── aws-expert/
│   │   ├── .claude-plugin/
│   │   │   └── plugin.json
│   │   └── skills/
│   │       └── aws-expert/
│   │           ├── SKILL.md
│   │           └── references/
│   └── ... (105 plugins total)
├── .claude/
│   ├── skills/                    # Project-local skills (gitignored, see SKILLS.md)
│   └── settings.local.json
├── AGENTS.md                      # This file
├── CLAUDE.md                      # Reference pointer
├── README.md                      # Public documentation
├── SKILLS.md                      # Recommended skills for this repo
├── CHANGELOG.md                   # Version history
└── LICENSE                        # MIT license
```

## Project Skills

For working on this repository, install the recommended plugins listed in @SKILLS.md. Project-local skills installed to `.claude/skills/` are gitignored — each developer installs from the marketplace.

## Searching the Codebase with qmd

This repository is indexed as a `qmd` collection for fast keyword and semantic search across all 105 plugins.

### Setup

```bash
qmd collection add /path/to/claude-skills --name claude-skills --mask "**/*.md"
qmd embed
```

### Usage

```bash
# Keyword search
qmd search "terraform" -c claude-skills -n 10

# Semantic search (find skills by concept, not exact words)
qmd vsearch "how to analyze container images" -c claude-skills -n 5

# Hybrid search (best quality)
qmd query "reverse engineering binaries" -c claude-skills

# Keep index fresh after adding/editing plugins
qmd update && qmd embed
```

## Plugin Marketplace

### How It Works

This repository is a Claude Code plugin marketplace. Users install it once:

```bash
/plugin install https://github.com/MOlechowski/claude-skills
```

Then enable/disable individual skills:

```bash
/plugin enable aws-cli
/plugin disable re-ghidra
```

Only enabled plugins consume context tokens at startup.

### Plugin Structure

Each plugin in `plugins/<name>/` contains:

```
plugins/<name>/
├── .claude-plugin/
│   └── plugin.json          # Required: name, version, description
└── skills/
    └── <name>/
        ├── SKILL.md         # Required: skill definition with YAML frontmatter
        ├── references/      # Optional: additional reference docs
        └── scripts/         # Optional: executable code
```

### marketplace.json

The root `.claude-plugin/marketplace.json` catalogs all 105 plugins with:
- `pluginRoot`: `"./plugins"` — base path for all plugins
- `plugins[]`: array of entries with name, description, version, category, tags, path

### plugin.json

Each plugin's `.claude-plugin/plugin.json` contains **only** these three fields (Claude Code rejects unknown keys):

```json
{
  "name": "skill-name",
  "version": "1.0.0",
  "description": "What this skill does and when to use it"
}
```

Category, tags, and author metadata belong in `marketplace.json` entries, not in individual plugin manifests.

## Skills Framework

### Progressive Disclosure

Skills use **progressive disclosure** to maximize efficiency:
1. **Level 1 (Startup)**: Metadata (name + description) loads into system prompt
2. **Level 2 (Activation)**: Full `SKILL.md` loads when skill is relevant
3. **Level 3+ (On-Demand)**: Additional bundled files load as needed

### SKILL.md Format

```markdown
---
name: skill-identifier
description: Clear explanation of purpose and when to use
---

# Skill Instructions

Detailed instructions for Claude...
```

### Required Frontmatter Fields

- **name** (string): Unique identifier, kebab-case
- **description** (string): Concise explanation of purpose and usage scenarios

### Skill Description Best Practices

- Maximum 1024 characters (enforced by validator)
- Include "Use when:" or "Use for:" patterns to help Claude recognize when to activate
- Include "Triggers:" with keywords that should activate the skill
- Be specific about what problems the skill solves

## Naming Convention

All skills use a **domain prefix** for namespace grouping:

| Prefix | Domain | Category Tag | Example |
|--------|--------|-------------|---------|
| `aws-` | AWS + LocalStack | `aws` | `aws-cli`, `aws-localstack` |
| `cf-` | Cloudflare | `cloudflare` | `cf-tunnel`, `cf-wrangler` |
| `cli-` | CLI tool wrappers | `cli` | `cli-jq`, `cli-ripgrep` |
| `dev-` | Dev workflow & review | `dev` | `dev-swarm`, `dev-review` |
| `doc-` | Documentation & notes | `documentation` | `doc-readme`, `doc-obsidian` |
| `git-` | Git/GitHub/VCS | `git` | `git-commit`, `git-ship` |
| `go-` | Go ecosystem | `go` | `go-lint`, `go-expert` |
| `iac-` | Infrastructure as Code | `iac` | `iac-terraform`, `iac-tofu` |
| `net-` | Network & HTTP | `network` | `net-nmap`, `net-wireshark` |
| `oci-` | Container/OCI images | `containers` | `oci-dive`, `oci-crane` |
| `re-` | Reverse engineering | `reverse-engineering` | `re-ghidra`, `re-frida` |
| `res-` | Research | `research` | `res-deep`, `res-web` |
| `sec-` | Security scanning | `security` | `sec-trivy`, `sec-semgrep` |
| `speckit-` | Spec-driven dev | `speckit` | `speckit-flow`, `speckit-loop` |

**Rules:**
- Prefixes are 2-4 chars (except `speckit-` which is a product name)
- Knowledge/expertise skills use `-expert` suffix: `aws-expert`, `cf-expert`, `go-expert`
- All names are kebab-case

## Development Guidelines

### Creating New Plugins

1. **Create directory** `plugins/<name>/` with kebab-case name
2. **Write plugin.json** in `plugins/<name>/.claude-plugin/plugin.json`
3. **Write SKILL.md** in `plugins/<name>/skills/<name>/SKILL.md` with required frontmatter
4. **Add resources** as needed (reference docs, scripts, data)
5. **Update marketplace.json** — add entry to `.claude-plugin/marketplace.json`
6. **Test locally** by copying `plugins/<name>/skills/<name>` to `~/.claude/skills/<name>`
7. **Document** in README and CHANGELOG

### Skill Design Principles

**Single Responsibility:**
- Each skill focuses on one specific domain or task type
- Clear boundaries between different skills
- Avoid feature creep or scope expansion

**Progressive Disclosure:**
- Start with minimal metadata that helps Claude recognize relevance
- Provide detailed instructions only when skill is activated
- Reference additional files only when actually needed

**Self-Contained:**
- Bundle all necessary resources within the plugin directory
- Don't depend on external files or other plugins
- Include sample data or examples if helpful

**Clear Activation:**
- Description must make it obvious when skill applies
- Include concrete examples of trigger scenarios
- Define the specific problems the skill solves

## Skills vs Agents Comparison

| Aspect | Skills | Agents |
|--------|--------|--------|
| **Location** | `~/.claude/skills/[name]/` | `~/.claude/agents/[name].md` |
| **Structure** | Directory | Single file |
| **Resources** | Multiple bundled files | Single markdown |
| **Code** | Separate script files | Via Bash tool |
| **Loading** | Progressive (3 levels) | Full load |
| **Maturity** | Production | Stable |

## Git Workflow

```bash
git status

# Add new plugin
git add plugins/new-skill/

# Commit with conventional commit message
git commit -m "feat(skills): add new-skill plugin for [purpose]"

git push origin master
```

## Resources

- [Anthropic: Agent Skills Framework](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [Claude Code Plugins](https://code.claude.com/docs/en/plugins)
- [Claude Code Plugin Marketplaces](https://code.claude.com/docs/en/plugin-marketplaces)
- [claude-agents repository](https://github.com/MOlechowski/claude-agents)
