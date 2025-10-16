# Claude Skills

A curated collection of Claude Skills following Anthropic's [Agent Skills framework](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills) for use with Claude Code, Claude.ai, and the Claude Agent SDK.

## What are Claude Skills?

Skills are organized directories containing instructions, scripts, and resources that enable Claude to perform specialized tasks. They use **progressive disclosure** - loading information only when needed - to maximize efficiency and capability.

### Key Features

- **Modular Design**: Each skill is self-contained in its own directory
- **Progressive Loading**: Metadata loads first, then full instructions, then additional resources on-demand
- **Executable Code**: Skills can include Python scripts and other tools for deterministic operations
- **Context Efficient**: Unbounded resources accessed via filesystem without bloating context
- **Composable**: Package and share domain expertise across teams and projects

## Repository Structure

```
claude-skills/
├── .claude/
│   ├── skills/                # Skill directories
│   │   ├── example-skill/    # Each skill in its own directory
│   │   │   ├── SKILL.md      # Main skill definition with YAML frontmatter
│   │   │   ├── forms.md      # Optional: Additional reference files
│   │   │   └── script.py     # Optional: Executable code
│   └── settings.local.json    # Local permissions configuration
├── install.sh                 # Installation script
├── CLAUDE.md                  # Repository guidance for Claude
├── CHANGELOG.md               # Version history
├── LICENSE                    # MIT license
└── README.md                  # This file
```

## Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/MOlechowski/claude-skills.git
cd claude-skills

# Run the installation script
./install.sh
```

The installation script will:
- Create `~/.claude/skills/` directory if it doesn't exist
- Copy all skill directories to your user directory
- Prompt for confirmation before overwriting existing skills
- Provide a summary of installed skills

### Manual Installation

```bash
# Copy skills to Claude's configuration directory
cp -r .claude/skills/* ~/.claude/skills/
```

## Creating Skills

### Skill Structure

Each skill follows Anthropic's specification with a `SKILL.md` file containing YAML frontmatter:

```markdown
---
name: skill-name
description: Clear description of what this skill does and when to use it
---

# Skill Instructions

Detailed instructions for Claude on how to use this skill...
```

### Required Frontmatter

- **name**: Unique identifier for the skill
- **description**: Concise explanation of the skill's purpose and usage

### Optional Components

Skills can include additional files in their directory:
- Reference documents (`.md` files)
- Python scripts (`.py` files)
- Configuration files
- Data files

### Progressive Disclosure Pattern

1. **Level 1 (Startup)**: Name and description load into system prompt
2. **Level 2 (Activation)**: Full `SKILL.md` loads when skill is relevant
3. **Level 3+ (On-Demand)**: Additional files load as needed

## Available Skills

*Currently this repository is in initial setup. Skills will be added soon.*

## Usage

Once installed, skills automatically become available to Claude Code. Claude will:
1. See skill metadata at startup
2. Activate appropriate skills based on context
3. Load additional resources on-demand as needed

### With Claude Code

```bash
# Skills work automatically in Claude Code sessions
claude

# Claude will recognize when to use skills based on your requests
```

### With Claude Agent SDK

```typescript
import { ClaudeAgent } from '@anthropic-ai/claude-agent-sdk';

// Skills are automatically discovered from ~/.claude/skills/
const agent = new ClaudeAgent({
  // ... configuration
});
```

## Skills vs Agents

| Feature | Skills | Agents |
|---------|--------|--------|
| **Location** | `~/.claude/skills/` | `~/.claude/agents/` |
| **Structure** | Directory with SKILL.md | Single .md file |
| **Resources** | Multiple files in directory | Embedded in single file |
| **Code Execution** | Bundled scripts | Via Bash tool |
| **Progressive Loading** | Yes (3 levels) | Partial |
| **Status** | Experimental (as of Claude Code 2.0.20) | Fully supported |

## Compatibility

**Supported Platforms:**
- Claude.ai (web interface)
- Claude Code (CLI tool)
- Claude Agent SDK (programmatic access)
- Claude Developer Platform (API)

**Current Status:** Skills support is in early stages for Claude Code 2.0.20. This repository prepares for broader skills adoption as the feature matures.

## Development

### Creating a New Skill

1. Create a directory in `.claude/skills/` with your skill name
2. Add a `SKILL.md` file with YAML frontmatter
3. Include any additional files needed
4. Test the skill locally
5. Submit a pull request

### Skill Guidelines

- **Single Responsibility**: Each skill should focus on one domain
- **Clear Description**: Make it obvious when the skill applies
- **Self-Contained**: Bundle all necessary resources
- **Documentation**: Include examples in the skill description
- **Testing**: Verify the skill works as intended

### Example Skill Template

```markdown
---
name: example-skill
description: |
  This skill helps with [specific task]. Use it when you need to [scenario].

  Examples:
  - "I need to [use case 1]" → Activate this skill
  - "Help me with [use case 2]" → Activate this skill
---

# Example Skill Instructions

You are an expert in [domain]. Your role is to [primary function].

## Core Capabilities

1. **Capability 1**: Description
2. **Capability 2**: Description
3. **Capability 3**: Description

## Usage Guidelines

- When to use this skill: [conditions]
- Key techniques: [approaches]
- Output format: [expectations]

## Additional Resources

You can reference additional files in this skill directory:
- `reference.md` - Additional documentation
- `script.py` - Executable code for deterministic operations
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add your skill following the guidelines
4. Test thoroughly
5. Submit a pull request with clear description

## Related Projects

- [claude-agents](https://github.com/MOlechowski/claude-agents) - Custom agent definitions for Claude Code

## Resources

- [Anthropic: Equipping Agents for the Real World with Agent Skills](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [Claude Code Documentation](https://docs.claude.com/en/docs/claude-code)
- [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

This repository follows Anthropic's Agent Skills framework and is designed to complement Claude Code's capability system.
