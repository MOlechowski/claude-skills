---
name: skill-creator
description: Guide for creating effective skills. This skill should be used when users want to create a new skill (or update an existing skill) that extends Claude's capabilities with specialized knowledge, workflows, or tool integrations.
license: Complete terms in LICENSE.txt
---

# Skill Creator

Guide for creating effective skills.

## About Skills

Skills are modular packages that extend Claude's capabilities with specialized knowledge, workflows, and tools. They transform Claude into a specialized agent with procedural knowledge no model fully possesses.

### What Skills Provide

1. Specialized workflows - Multi-step procedures for specific domains
2. Tool integrations - Instructions for specific file formats or APIs
3. Domain expertise - Company-specific knowledge, schemas, business logic
4. Bundled resources - Scripts, references, and assets for complex/repetitive tasks

## Core Principles

### Concise is Key

The context window is a shared resource with system prompt, conversation history, other Skills' metadata, and user requests.

**Default assumption: Claude is already smart.** Only add context Claude lacks. Challenge each piece: "Does Claude need this?" and "Does this justify its token cost?"

Prefer concise examples over verbose explanations.

### Set Appropriate Degrees of Freedom

Match specificity to task fragility and variability:

**High freedom (text instructions)**: Multiple approaches valid, decisions context-dependent, heuristics guide approach.

**Medium freedom (pseudocode/scripts with parameters)**: Preferred pattern exists, some variation acceptable, configuration affects behavior.

**Low freedom (specific scripts, few parameters)**: Operations fragile/error-prone, consistency critical, specific sequence required.

Think of Claude exploring a path: narrow bridge with cliffs needs guardrails (low freedom), open field allows many routes (high freedom).

### Anatomy of a Skill

Every skill consists of a required SKILL.md file and optional bundled resources:

```
skill-name/
├── SKILL.md (required)
│   ├── YAML frontmatter metadata (required)
│   │   ├── name: (required)
│   │   └── description: (required)
│   └── Markdown instructions (required)
└── Bundled Resources (optional)
    ├── scripts/          - Executable code (Python/Bash/etc.)
    ├── references/       - Documentation intended to be loaded into context as needed
    └── assets/           - Files used in output (templates, icons, fonts, etc.)
```

#### SKILL.md (required)

Every SKILL.md consists of:

- **Frontmatter** (YAML): Contains `name` and `description` fields. Claude reads these to determine when to use the skill. Be clear and comprehensive about what the skill does and when to use it.
- **Body** (Markdown): Instructions for using the skill. Loaded only AFTER the skill triggers.

#### Bundled Resources (optional)

##### Scripts (`scripts/`)

Executable code (Python/Bash/etc.) for tasks requiring deterministic reliability or repeatedly rewritten.

- **When to include**: Same code rewritten repeatedly or deterministic reliability needed
- **Example**: `scripts/rotate_pdf.py` for PDF rotation
- **Benefits**: Token efficient, deterministic, can execute without loading into context
- **Note**: Scripts may need reading for patching or environment-specific adjustments

##### References (`references/`)

Documentation loaded as needed to inform Claude's process.

- **When to include**: Documentation Claude should reference while working
- **Examples**: `references/finance.md` for schemas, `references/mnda.md` for NDA template, `references/api_docs.md` for API specs
- **Use cases**: Database schemas, API docs, domain knowledge, company policies, workflow guides
- **Benefits**: Keeps SKILL.md lean, loaded only when needed
- **Best practice**: For large files (>10k words), include grep patterns in SKILL.md
- **Avoid duplication**: Information lives in SKILL.md OR references, not both. Prefer references for detailed info. Keep only essential procedural instructions in SKILL.md; move schemas and examples to references.

##### Assets (`assets/`)

Files used in output, not loaded into context.

- **When to include**: Skill needs files for final output
- **Examples**: `assets/logo.png` for brand assets, `assets/slides.pptx` for templates, `assets/frontend-template/` for boilerplate
- **Use cases**: Templates, images, icons, boilerplate code, fonts, sample documents
- **Benefits**: Separates output resources from documentation, enables file use without context loading

#### What NOT to Include

Only include essential files supporting functionality. Do NOT create:

- README.md
- INSTALLATION_GUIDE.md
- QUICK_REFERENCE.md
- CHANGELOG.md

Include only information needed for an AI agent to do the job. Exclude creation process context, setup procedures, user-facing documentation.

### Progressive Disclosure

Skills use three-level loading for context efficiency:

1. **Metadata (name + description)** - Always in context (~100 words)
2. **SKILL.md body** - When skill triggers (<5k words)
3. **Bundled resources** - As needed (unlimited since scripts can execute without loading)

#### Progressive Disclosure Patterns

Keep SKILL.md under 500 lines. Split content into separate files when approaching this limit. Reference split files from SKILL.md with clear descriptions of when to read them.

**Key principle:** For multiple variations/frameworks/options, keep core workflow and selection guidance in SKILL.md. Move variant-specific details to reference files.

**Pattern 1: High-level guide with references**

```markdown
# PDF Processing

## Quick start

Extract text with pdfplumber:
[code example]

## Advanced features

- **Form filling**: See [FORMS.md](FORMS.md) for complete guide
- **API reference**: See [REFERENCE.md](REFERENCE.md) for all methods
- **Examples**: See [EXAMPLES.md](EXAMPLES.md) for common patterns
```

Claude loads FORMS.md, REFERENCE.md, or EXAMPLES.md only when needed.

**Pattern 2: Domain-specific organization**

For Skills with multiple domains, organize content by domain to avoid loading irrelevant context:

```
bigquery-skill/
├── SKILL.md (overview and navigation)
└── reference/
    ├── finance.md (revenue, billing metrics)
    ├── sales.md (opportunities, pipeline)
    ├── product.md (API usage, features)
    └── marketing.md (campaigns, attribution)
```

When a user asks about sales metrics, Claude only reads sales.md.

Similarly, for skills supporting multiple frameworks or variants, organize by variant:

```
cloud-deploy/
├── SKILL.md (workflow + provider selection)
└── references/
    ├── aws.md (AWS deployment patterns)
    ├── gcp.md (GCP deployment patterns)
    └── azure.md (Azure deployment patterns)
```

When the user chooses AWS, Claude only reads aws.md.

**Pattern 3: Conditional details**

Show basic content, link to advanced content:

```markdown
# DOCX Processing

## Creating documents

Use docx-js for new documents. See [DOCX-JS.md](DOCX-JS.md).

## Editing documents

For simple edits, modify the XML directly.

**For tracked changes**: See [REDLINING.md](REDLINING.md)
**For OOXML details**: See [OOXML.md](OOXML.md)
```

Claude reads REDLINING.md or OOXML.md only when the user needs those features.

**Guidelines:**

- **Avoid deep nesting** - Keep references one level deep from SKILL.md.
- **Structure long files** - For 100+ line files, include table of contents at top.

## Skill Creation Process

Steps:

1. Understand the skill with concrete examples
2. Plan reusable contents (scripts, references, assets)
3. Initialize the skill (run init_skill.py)
4. Edit the skill (implement resources and write SKILL.md)
5. Package the skill (run package_skill.py)
6. Iterate based on real usage

Follow in order; skip only with clear reason.

### Step 1: Understanding with Concrete Examples

Skip only when usage patterns are already clear. Valuable even for existing skills.

Understand concrete examples of how the skill will be used through direct user examples or generated examples validated with feedback.

Example questions for an image-editor skill:

- "What functionality should the image-editor skill support?"
- "Can you give examples of how this skill would be used?"
- "What would a user say that should trigger this skill?"

Avoid overwhelming users with too many questions at once. Start with the most important questions and follow up as needed.

Conclude when the skill's required functionality is clear.

### Step 2: Planning Reusable Contents

Analyze each example by:

1. Considering how to execute from scratch
2. Identifying helpful scripts, references, and assets for repeated workflows

Example: `pdf-editor` for "Help me rotate this PDF":
- Rotating PDF requires rewriting same code each time
- `scripts/rotate_pdf.py` stores the reusable script

Example: `frontend-webapp-builder` for "Build me a todo app":
- Frontend webapp requires same boilerplate each time
- `assets/hello-world/` stores boilerplate template

Example: `big-query` for "How many users logged in today?":
- Querying BigQuery requires rediscovering schemas each time
- `references/schema.md` documents table schemas

Analyze examples to create a list of reusable resources: scripts, references, and assets.

### Step 3: Initializing the Skill

Skip if skill already exists and needs iteration/packaging.

When creating from scratch, run `init_skill.py`. It generates a template skill directory with everything required.

Usage:

```bash
scripts/init_skill.py <skill-name> --path <output-directory>
```

The script:

- Creates skill directory at specified path
- Generates SKILL.md template with frontmatter and TODO placeholders
- Creates example directories: `scripts/`, `references/`, `assets/`
- Adds example files that can be customized or deleted

After initialization, customize or remove generated files as needed.

### Step 4: Edit the Skill

The skill is for another Claude instance. Include beneficial, non-obvious information. Consider procedural knowledge, domain details, or reusable assets that help execute tasks effectively.

#### Learn Proven Design Patterns

Consult these guides based on skill needs:

- **Multi-step processes**: See references/workflows.md for sequential workflows and conditional logic
- **Specific output formats**: See references/output-patterns.md for template and example patterns

#### Start with Reusable Contents

Begin with identified reusable resources: `scripts/`, `references/`, `assets/`. This may require user input (e.g., brand assets, templates, documentation).

Test added scripts by running them to ensure no bugs and expected output. For many similar scripts, test a representative sample.

Delete unneeded example files. The initialization script creates examples to demonstrate structure, but most skills won't need all of them.

#### Update SKILL.md

**Writing Guidelines:** Use imperative/infinitive form.

##### Frontmatter

Write YAML frontmatter with `name` and `description`:

- `name`: The skill name
- `description`: Primary triggering mechanism. Include what the skill does AND specific triggers/contexts.
  - Include all "when to use" information here, not in body (body loads after triggering).
  - Example for `docx` skill: "Document creation, editing, and analysis with tracked changes, comments, formatting preservation, text extraction. Use for: (1) Creating documents, (2) Editing content, (3) Tracked changes, (4) Adding comments"

No other fields in YAML frontmatter.

##### Body

Write instructions for using the skill and bundled resources.

### Step 5: Packaging a Skill

Package into distributable .skill file. Process validates first.

```bash
scripts/package_skill.py <path/to/skill-folder>
```

Optional output directory:

```bash
scripts/package_skill.py <path/to/skill-folder> ./dist
```

The script:

1. **Validates** automatically:
   - YAML frontmatter format and required fields
   - Naming conventions and directory structure
   - Description completeness
   - File organization and references

2. **Packages** if validation passes, creating a .skill file (zip with .skill extension) maintaining directory structure.

If validation fails, fix errors and run again.

### Step 6: Iterate

Users may request improvements after testing, often with fresh context of skill performance.

**Iteration workflow:**

1. Use skill on real tasks
2. Notice struggles or inefficiencies
3. Identify needed updates to SKILL.md or resources
4. Implement changes and test again
