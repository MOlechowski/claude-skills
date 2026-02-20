---
last_validated: 2026-02-20T12:00:00Z
project_type: skills-repository
skill_count: 93
---

# Agent Instructions: claude-skills

This file provides guidance to Claude Code when working with code in this repository.

## Repository Overview

This is a Claude Skills configuration repository following Anthropic's Agent Skills framework. It stores specialized skills that provide focused capabilities for Claude Code, Claude.ai, and the Claude Agent SDK through progressive disclosure and modular architecture.

## Repository Structure

```
.
├── .claude
│   ├── commands
│   │   ├── speckit.analyze.md
│   │   ├── speckit.checklist.md
│   │   ├── speckit.clarify.md
│   │   ├── speckit.constitution.md
│   │   ├── speckit.implement.md
│   │   ├── speckit.plan.md
│   │   ├── speckit.specify.md
│   │   ├── speckit.tasks.md
│   │   └── speckit.taskstoissues.md
│   ├── settings.local.json
│   └── skills/                  # 93 skills with domain prefixes
│       ├── # aws-  AWS + LocalStack
│       ├── aws-cli/
│       ├── aws-expert/
│       ├── aws-local/
│       ├── aws-localstack/
│       ├── aws-localstack-expert/
│       ├── # cf-  Cloudflare
│       ├── cf-ctl/
│       ├── cf-expert/
│       ├── cf-tunnel/
│       ├── cf-wrangler/
│       ├── # cli-  CLI Tool Wrappers
│       ├── cli-ast-grep/
│       ├── cli-fastmod/
│       ├── cli-fzf/
│       ├── cli-jq/
│       ├── cli-parallel/
│       ├── cli-ripgrep/
│       ├── cli-tmux/
│       ├── cli-tree/
│       ├── cli-yq/
│       ├── # dev-  Dev Workflow & Review
│       ├── dev-backlog/
│       ├── dev-compress/
│       ├── dev-learn/
│       ├── dev-review/
│       ├── dev-review-file/
│       ├── dev-review-pr/
│       ├── dev-rlm/
│       ├── dev-skill-create/
│       ├── dev-swarm/
│       ├── # doc-  Documentation & Notes
│       ├── doc-claude-md/
│       ├── doc-confluence/
│       ├── doc-mermaid/
│       ├── doc-mermaid-render/
│       ├── doc-notesmd/
│       ├── doc-obsidian/
│       ├── doc-qmd/
│       ├── doc-readme/
│       ├── # git-  Git & Version Control
│       ├── git-commit/
│       ├── git-land/
│       ├── git-pr-create/
│       ├── git-pr-manage/
│       ├── git-repo/
│       ├── git-ship/
│       ├── git-worktree/
│       ├── # go-  Go Ecosystem
│       ├── go-delve/
│       ├── go-expert/
│       ├── go-lefthook/
│       ├── go-lint/
│       ├── go-mockery/
│       ├── go-pprof/
│       ├── go-release/
│       ├── go-task/
│       ├── # iac-  Infrastructure as Code
│       ├── iac-expert/
│       ├── iac-hcloud/
│       ├── iac-opa/
│       ├── iac-terraform/
│       ├── iac-tofu/
│       ├── # net-  Network & HTTP
│       ├── net-httpx/
│       ├── net-mitmproxy/
│       ├── net-nmap/
│       ├── net-tcpdump/
│       ├── net-wireshark/
│       ├── # oci-  Container & OCI Images
│       ├── oci-crane/
│       ├── oci-dive/
│       ├── oci-skopeo/
│       ├── oci-syft/
│       ├── # re-  Reverse Engineering
│       ├── re-binwalk/
│       ├── re-docker-expert/
│       ├── re-dtrace/
│       ├── re-expert/
│       ├── re-frida/
│       ├── re-gdb/
│       ├── re-ghidra/
│       ├── re-lldb/
│       ├── re-objcopy/
│       ├── re-patchelf/
│       ├── re-pwntools/
│       ├── re-python-expert/
│       ├── re-radare2/
│       ├── re-strace/
│       ├── re-xxd/
│       ├── # res-  Research
│       ├── res-deep/
│       ├── res-trends/
│       ├── res-web/
│       ├── # sec-  Security Scanning
│       ├── sec-bandit/
│       ├── sec-grype/
│       ├── sec-nuclei/
│       ├── sec-pip-audit/
│       ├── sec-semgrep/
│       ├── sec-trivy/
│       ├── # speckit-  Spec-Driven Development
│       ├── speckit-audit/
│       ├── speckit-flow/
│       ├── speckit-loop/
│       ├── speckit-retro/
│       └── speckit-verify/
├── .specify
│   ├── memory
│   ├── scripts
│   └── templates
├── scripts
│   ├── common.py
│   └── speckit_*.py
├── specs
│   └── [spec-directories]
├── *.skill                       # Packaged skill archives
├── AGENTS.md                     # This file
├── CLAUDE.md                     # Reference pointer
├── README.md                     # Public documentation
├── CHANGELOG.md                  # Version history
├── LICENSE                       # MIT license
└── install.sh                    # Installation script
```

## Skills Framework

### What are Skills?

Skills use **progressive disclosure** to maximize efficiency:
1. **Level 1 (Startup)**: Metadata (name + description) loads into system prompt
2. **Level 2 (Activation)**: Full `SKILL.md` loads when skill is relevant
3. **Level 3+ (On-Demand)**: Additional bundled files load as needed

### Skill Structure

Each skill directory must contain:
- `SKILL.md` - Main definition file with YAML frontmatter

Optional components:
- Additional `.md` files for reference material
- `.py` files for executable code
- Configuration or data files

### SKILL.md Format

```markdown
---
name: skill-identifier
description: Clear explanation of purpose and when to use
---

# Skill Instructions

Detailed instructions for Claude...
```

## Primary Purpose

This repository serves as:
- **Central storage** for reusable Claude Skills
- **Distribution mechanism** via installation script
- **Documentation** of skill patterns and best practices
- **Community resource** for sharing domain expertise

## Development Guidelines

### Creating New Skills

1. **Create directory** in `.claude/skills/` with kebab-case name
2. **Write SKILL.md** with required frontmatter
3. **Add resources** as needed (reference docs, scripts, data)
4. **Test locally** by installing to `~/.claude/skills/`
5. **Document** in README and CHANGELOG

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
- Bundle all necessary resources within the skill directory
- Don't depend on external files or other skills
- Include sample data or examples if helpful

**Clear Activation:**
- Description must make it obvious when skill applies
- Include concrete examples of trigger scenarios
- Define the specific problems the skill solves

### File Organization

```
.claude/skills/
├── domain-expert/
│   ├── SKILL.md           # Core definition
│   ├── reference.md       # Deep reference material
│   ├── examples.md        # Usage examples
│   └── tools.py           # Executable utilities
├── another-skill/
│   └── SKILL.md
```

### Required Frontmatter Fields

- **name** (string): Unique identifier, kebab-case
- **description** (string): Concise explanation of purpose and usage scenarios

### Skill Description Best Practices

**Description guidelines:**
- Maximum 1024 characters (enforced by validator)
- Include "Use when:" or "Use for:" patterns to help Claude recognize when to activate
- Include "Triggers:" with keywords that should activate the skill
- Be specific about what problems the skill solves

**Example:**

```yaml
---
name: cf-tunnel
description: "Cloudflare Tunnel CLI for exposing local services. Use for: quick tunnels (dev), named tunnels (prod), DNS routing, system service setup. Triggers: cloudflared, tunnel, expose localhost."
---
```

### Naming Convention

All skills use a **domain prefix** for namespace grouping:

| Prefix | Domain | Example |
|--------|--------|---------|
| `aws-` | AWS + LocalStack | `aws-cli`, `aws-localstack` |
| `cf-` | Cloudflare | `cf-tunnel`, `cf-wrangler` |
| `cli-` | CLI tool wrappers | `cli-jq`, `cli-ripgrep` |
| `dev-` | Dev workflow & review | `dev-swarm`, `dev-review`, `dev-backlog` |
| `doc-` | Documentation & notes | `doc-readme`, `doc-obsidian` |
| `git-` | Git/GitHub/VCS | `git-commit`, `git-ship` |
| `go-` | Go ecosystem | `go-lint`, `go-expert` |
| `iac-` | Infrastructure as Code | `iac-terraform`, `iac-tofu` |
| `net-` | Network & HTTP | `net-nmap`, `net-wireshark` |
| `oci-` | Container/OCI images | `oci-dive`, `oci-crane` |
| `re-` | Reverse engineering | `re-ghidra`, `re-frida` |
| `res-` | Research | `res-deep`, `res-web` |
| `sec-` | Security scanning | `sec-trivy`, `sec-semgrep` |
| `speckit-` | Spec-driven dev | `speckit-flow`, `speckit-loop` |

**Rules:**
- Prefixes are 2-4 chars (except `speckit-` which is a product name)
- Knowledge/expertise skills use `-expert` suffix: `aws-expert`, `cf-expert`, `go-expert`
- All names are kebab-case

## Installation and Usage

### Installing Skills

```bash
# Run the installation script
./install.sh
```

The script copies all skill directories from `.claude/skills/` to `~/.claude/skills/`.

### Using Skills

Skills work automatically once installed:
- Claude Code recognizes available skills at startup
- Skills activate based on context and user requests
- Additional resources load on-demand as needed

### Testing Skills

1. Install skill to `~/.claude/skills/`
2. Start Claude Code session
3. Trigger skill with relevant request
4. Verify skill activates and behaves correctly
5. Check that additional files load when referenced

## Current Status

**Claude Code 1.0+:** Skills are fully supported (production-ready since October 16, 2025). The framework is stable and widely adopted across Claude platforms.

**This repository:** Provides curated, production-ready skills by:
- Offering proven skill patterns and structure
- Providing simple installation mechanism
- Documenting best practices from real-world usage
- Creating reusable skill templates for common workflows

## Skills vs Agents Comparison

| Aspect | Skills | Agents |
|--------|--------|--------|
| **Location** | `~/.claude/skills/[name]/` | `~/.claude/agents/[name].md` |
| **Structure** | Directory | Single file |
| **Resources** | Multiple bundled files | Single markdown |
| **Code** | Separate script files | Via Bash tool |
| **Loading** | Progressive (3 levels) | Full load |
| **Maturity** | Production | Stable |

Both systems are production-ready and valuable for different use cases.

## Contributing

### Adding Skills

1. Create skill directory following conventions
2. Write clear, focused SKILL.md
3. Test installation and functionality
4. Update README with skill description
5. Add changelog entry
6. Submit pull request

### Updating Skills

1. Maintain backward compatibility when possible
2. Version skill if breaking changes needed
3. Update documentation
4. Test thoroughly
5. Document changes in CHANGELOG

## Git Workflow

```bash
# Check status
git status

# Add new skill
git add .claude/skills/new-skill/

# Commit with conventional commit message
git commit -m "feat: add new-skill for [purpose]"

# Push to repository
git push origin master
```

## Future Enhancements

As skills support matures in Claude Code:
- Additional example skills
- Domain-specific skill collections
- Integration with MCP for enhanced capabilities
- Automated skill discovery and installation
- Skill composition patterns

## Resources

- [Anthropic: Agent Skills Framework](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [Claude Code Documentation](https://docs.claude.com/en/docs/claude-code)
- [claude-agents repository](https://github.com/MOlechowski/claude-agents)

This repository builds on Anthropic's vision for modular, composable AI capabilities through the skills framework.
