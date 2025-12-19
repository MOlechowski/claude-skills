# Agent Instructions: claude-skills

This file provides guidance to Claude Code when working with code in this repository.

## Repository Overview

This is a Claude Skills configuration repository following Anthropic's Agent Skills framework. It stores specialized skills that provide focused capabilities for Claude Code, Claude.ai, and the Claude Agent SDK through progressive disclosure and modular architecture.

## Repository Structure

```
claude-skills/
├── .claude/
│   ├── skills/                # Skill directories
│   │   └── [skill-name]/      # Each skill in its own directory
│   │       ├── SKILL.md       # Main skill definition
│   │       ├── *.md           # Optional reference files
│   │       ├── *.py           # Optional executable code
│   │       └── *              # Other resources
│   └── settings.local.json    # Local permissions
├── AGENTS.md                  # This file (source of truth)
├── CLAUDE.md                  # Reference pointer
├── README.md                  # Public documentation
├── CHANGELOG.md               # Version history
├── LICENSE                    # MIT license
└── install.sh                 # Installation script
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

Include:
- **Purpose**: What does this skill do?
- **When to use**: Specific scenarios that trigger it
- **Examples**: Concrete use cases
- **Capabilities**: Key features or operations

Example:
```yaml
description: |
  This skill provides expertise in React performance optimization.

  Use this skill when:
  - Analyzing React component render performance
  - Implementing memoization strategies
  - Optimizing bundle sizes

  Examples:
  - "My React app is slow, help optimize"
  - "Implement memoization for this component"
```

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
