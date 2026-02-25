---
name: doc-vault-project
description: "Manage multi-note research projects in Obsidian vault with phased subdirectory structure (concept, research, design, implementation). Scaffold new projects, add component notes, track status, link existing research, promote topics to projects. Use when: creating a project, adding to a project, checking project status, linking research to a project, promoting a research topic to a full project. Triggers: project init, project add, project status, project link, project promote, create project, new project."
---

# Vault Project

Manage multi-note research projects in an Obsidian vault with phased subdirectory structure.

## Prerequisites

| Skill | Required | Purpose |
|-------|----------|---------|
| doc-obsidian | Yes | Vault CRUD via notesmd-cli + search via qmd |

## Directory Structure

```
projects/{project-slug}/
├── _index.md              # MOC: status, component links, linked research
├── concept/               # Problem definition, threat models, requirements
├── research/              # Deep dives per component, tech evaluation
├── design/                # Architecture, API design, data models
└── implementation/        # Build plans, code refs, test plans
```

Projects live in `projects/` (top-level). Separate from `research/` (knowledge).

Four phases are always created. Empty dirs signal "not started yet."

## Step 0: Setup

Run before every operation:

```bash
VAULT=$(notesmd-cli print-default --path-only)
qmd status
```

If either fails, stop and tell the user to set up doc-obsidian first.

## Commands

### init — Scaffold New Project

**Trigger:** "create project {name}", "new project {name}", "project init {name}"

#### Workflow

1. Parse project name → kebab-case slug (max 40 chars)
2. Check if `projects/{slug}/` exists — if yes, abort and show existing project
3. Create directory structure:

```bash
VAULT=$(notesmd-cli print-default --path-only)
mkdir -p "$VAULT/projects/{slug}/concept"
mkdir -p "$VAULT/projects/{slug}/research"
mkdir -p "$VAULT/projects/{slug}/design"
mkdir -p "$VAULT/projects/{slug}/implementation"
```

4. Load `references/index-template.md` and `references/frontmatter-schemas.md`
5. Build `_index.md` with project frontmatter and empty status table
6. Write `_index.md`:

```bash
# Use Write tool → "$VAULT/projects/{slug}/_index.md"
```

7. Re-index: `qmd update && qmd embed`
8. Confirm:

```
Created: [[{slug}]]
Path: projects/{slug}/
Phases: concept/ research/ design/ implementation/
Components: 0
```

### add — Add Component Note

**Trigger:** "add {note} to project {name}", "project add {note} to {phase}"

#### Workflow

1. Identify project slug and target phase (concept/research/design/implementation)
2. If phase not specified, infer from content:
   - Problem/threat/requirement → `concept`
   - Deep dive/evaluation/comparison → `research`
   - Architecture/API/data model → `design`
   - Plan/code/test/deploy → `implementation`
3. If ambiguous, ask the user
4. Generate note slug (kebab-case, max 60 chars)
5. Check for duplicates in the phase directory
6. Load frontmatter schema from `references/frontmatter-schemas.md`
7. Build component note with `type: project-component` frontmatter
8. Save:

```bash
VAULT=$(notesmd-cli print-default --path-only)
# Write tool → "$VAULT/projects/{project-slug}/{phase}/{note-slug}.md"
```

9. Update `_index.md`:
   - Add wikilink under the correct phase section
   - Update status table counts
   - Update `components:` and `updated:` in frontmatter
10. Re-index: `qmd update && qmd embed`
11. Confirm:

```
Added: [[{note-slug}]]
Path: projects/{project-slug}/{phase}/{note-slug}
Phase: {phase}
Status: pending
Project components: {N}
```

### status — Show Project Status

**Trigger:** "project status", "project status {name}", "how is project {name}"

#### Workflow

1. If no project specified, list all projects:

```bash
VAULT=$(notesmd-cli print-default --path-only)
ls "$VAULT/projects/"
```

2. For a specific project, read `_index.md` frontmatter and list components:

```bash
VAULT=$(notesmd-cli print-default --path-only)
# Read _index.md for project metadata
# List files in each phase directory
# Read frontmatter status from each component
```

3. Display:

```
Project: {name}
Status: {project-status}
Updated: {date}

| Phase | Component | Status |
|-------|-----------|--------|
| concept | [[threat-model]] | complete |
| concept | [[gap-analysis]] | in-progress |
| research | [[endpoint-security]] | pending |
| design | — | — |
| implementation | — | — |

Progress: 1/3 complete
```

### link — Link Existing Research

**Trigger:** "link research to project {name}", "project link {note} to {name}"

#### Workflow

1. Identify project and target research notes
2. If no specific notes given, search for related research:

```bash
qmd vsearch "{project topic}" --json -n 10
```

3. Filter results: only notes in `research/`, exclude score < 0.3
4. Present candidates with scores, let user pick
5. Read project `_index.md`
6. Add wikilinks under `### Linked Research` section:

```markdown
### Linked Research

- [[existing-note]] — {brief relevance}
```

7. Do NOT move files — research stays in `research/`
8. Update `updated:` in frontmatter
9. Re-index: `qmd update && qmd embed`
10. Confirm:

```
Linked to [[{project}]]:
- [[note-1]] — {relevance}
- [[note-2]] — {relevance}
```

### promote — Promote Research Topic to Project

**Trigger:** "promote {topic} to project", "make {topic} a project"

#### Workflow

1. Find existing research notes on the topic:

```bash
qmd vsearch "{topic}" --json -n 15
```

2. Present candidates, let user confirm which notes relate
3. Run `init` to scaffold the project
4. Run `link` to wikilink the existing research notes
5. Optionally create initial component notes in `concept/` if the research already covers problem definition
6. Confirm:

```
Promoted: {topic} → [[{project}]]
Linked research: {N} notes
Components: {N} created
```

Promote does NOT move existing notes. It creates a project that references them.

## Constraints

**DO:**
- Always run Step 0 first
- Always use fixed four phases (concept/research/design/implementation)
- Always update `_index.md` after adding/linking components
- Always re-index after changes
- Resolve vault path dynamically via `notesmd-cli print-default --path-only`
- Keep research notes in `research/` — link, don't move
- Read notes before editing

**DON'T:**
- Create custom phases or skip phase directories
- Move existing research notes into project directories
- Create projects without `_index.md`
- Skip re-indexing
- Hardcode vault paths
- Auto-trigger — only respond to explicit project commands

## References

- `references/frontmatter-schemas.md` — Frontmatter for _index.md and component notes, field rules, status transitions
- `references/index-template.md` — _index.md scaffold template, status table update rules, linked research format
