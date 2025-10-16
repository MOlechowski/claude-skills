---
name: template-skill
description: |
  This is a template skill that demonstrates the structure for creating custom skills.

  Use this skill as a starting point when:
  - Creating a new custom skill from scratch
  - Learning the skills format and structure
  - Understanding progressive disclosure patterns

  Examples:
  - "Show me how to create a custom skill"
  - "I need a template for a new skill"
---

# Template Skill Instructions

This is a template demonstrating how to create Claude Skills following Anthropic's framework.

## Purpose

Skills are modular, self-contained directories that teach Claude how to complete specific tasks in a repeatable way using progressive disclosure.

## Structure

A skill consists of:
1. **SKILL.md** (required) - This file with YAML frontmatter + instructions
2. **Additional files** (optional) - Reference docs, scripts, data files

## Progressive Disclosure Levels

**Level 1 (Startup):**
Only the `name` and `description` from YAML frontmatter load into Claude's system prompt. This helps Claude recognize when the skill is relevant.

**Level 2 (Activation):**
When Claude determines this skill applies, the full SKILL.md content loads.

**Level 3+ (On-Demand):**
Additional files in the skill directory can be referenced by name and load only when needed.

## YAML Frontmatter Requirements

```yaml
---
name: your-skill-name           # Required: kebab-case identifier
description: |                  # Required: Clear explanation
  Brief description of what this skill does.

  When to use:
  - Scenario 1
  - Scenario 2

  Examples:
  - "User request example 1"
  - "User request example 2"
---
```

## Writing Effective Descriptions

The description should answer:
- **What**: What does this skill do?
- **When**: When should it activate?
- **Examples**: Concrete user requests that trigger it

## Instruction Section

After the frontmatter, write clear instructions for Claude:

### Define the Role
"You are an expert in [domain]..."

### Specify Capabilities
List what the skill can do:
1. Capability one
2. Capability two
3. Capability three

### Provide Guidelines
- When to use specific techniques
- How to format outputs
- What to avoid

### Reference Additional Resources

If you have other files in the skill directory:
```markdown
For detailed examples, see `examples.md` in this skill directory.
To process data, use `process.py` script.
```

## Best Practices

**Focus:**
- Single, well-defined purpose
- Clear scope and boundaries
- Avoid feature creep

**Clarity:**
- Simple, direct language
- Concrete examples
- Obvious activation conditions

**Modularity:**
- Self-contained
- No dependencies on other skills
- Bundle all necessary resources

**Testing:**
- Install to `~/.claude/skills/`
- Verify activation with relevant requests
- Check that additional files load correctly

## Example Additional Files

You can include:
- `reference.md` - Detailed reference documentation
- `examples.md` - Usage examples and patterns
- `script.py` - Executable code for deterministic operations
- `data.json` - Configuration or sample data

Claude can reference these by name when needed.

## Adapting This Template

1. Replace `template-skill` with your skill name (kebab-case)
2. Write a clear, specific description with examples
3. Add your skill-specific instructions
4. Include any additional files needed
5. Test the skill locally before sharing

## Resources

- [Anthropic Skills Framework](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [Official Skills Repository](https://github.com/anthropics/skills)
- [Claude Code Documentation](https://docs.claude.com/en/docs/claude-code)

This template provides the foundation for creating effective, reusable Claude Skills.
