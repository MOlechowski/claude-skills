# Frontmatter Schemas

## _index.md (Project MOC)

```yaml
---
type: project
topic: "{Project Name}"
status: researching | designing | implementing | complete | on-hold
components: {N}
date: "{YYYY-MM-DD}"
updated: "{YYYY-MM-DD}"
tags:
    - project
    - {domain-tag-1}
    - {domain-tag-2}
---
```

### Field Rules

| Field | Required | Rule |
|-------|----------|------|
| type | Yes | Always `project` |
| topic | Yes | Human-readable project name |
| status | Yes | One of: `researching`, `designing`, `implementing`, `complete`, `on-hold` |
| components | Yes | Count of component notes across all phases |
| date | Yes | Creation date |
| updated | Yes | Last modification date |
| tags | Yes | Always includes `project` + 2-4 domain tags |

### Status Transitions

```
researching → designing → implementing → complete
     ↓            ↓            ↓
  on-hold      on-hold      on-hold
```

Update status when the majority of work shifts to a new phase.

## Component Note

```yaml
---
type: project-component
project: "{project-slug}"
phase: concept | research | design | implementation
status: pending | in-progress | complete | blocked
date: "{YYYY-MM-DD}"
tags:
    - {domain-tags}
---
```

### Field Rules

| Field | Required | Rule |
|-------|----------|------|
| type | Yes | Always `project-component` |
| project | Yes | Kebab-case project slug matching directory name |
| phase | Yes | Must match the subdirectory: `concept`, `research`, `design`, or `implementation` |
| status | Yes | One of: `pending`, `in-progress`, `complete`, `blocked` |
| date | Yes | Creation date |
| tags | Yes | 2-4 domain tags (no `project` tag — that's for _index.md only) |

### Phase Descriptions

| Phase | Contains | Example notes |
|-------|----------|--------------|
| `concept` | Problem definition, threat models, gap analysis, requirements | `threat-model.md`, `gap-analysis.md`, `requirements.md` |
| `research` | Deep dives per component, technology evaluation, prior art | `endpoint-security-framework.md`, `mute-inversion.md` |
| `design` | Architecture decisions, API design, data models | `architecture.md`, `xpc-communication.md` |
| `implementation` | Build plans, code references, test plans, deployment | `implementation-plan.md`, `test-plan.md` |
