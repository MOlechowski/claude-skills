# Task File Format

Tasks are plain markdown files with YAML frontmatter stored in `backlog/tasks/`.

## Filename Convention

`{prefix}-{id} - {Title}.md`

Examples:
- `back-1 - Add-OAuth-System.md`
- `task-42 - Fix-login-redirect.md`

The prefix defaults to `task` but is configurable via `prefixes.task` in `config.yml`.

## Full Template

```yaml
---
id: BACK-208
title: Add paste-as-markdown support in Web UI
status: To Do
assignee: []
reporter: john.doe
created_date: '2025-07-26 14:30'
updated_date: '2025-11-30 14:46'
labels:
  - web-ui
  - enhancement
dependencies: []
references: []
documentation: []
priority: medium
milestone: v1.0
parent_task_id: task-10
subtasks: [task-20, task-21]
ordinal: 100
onStatusChange: "echo $TASK_ID"
---

## Description

Task description and context.

## Acceptance Criteria

<!-- AC:BEGIN -->
- [ ] Criterion #1
- [ ] Criterion #2
- [x] Completed criterion #3
<!-- AC:END -->

## Definition of Done

<!-- DOD:BEGIN -->
- [ ] Tests pass
- [ ] Docs updated
<!-- DOD:END -->

## Implementation Plan

Research and approach details.

## Implementation Notes

Work-in-progress notes and findings.

## Final Summary

PR-style summary when complete.
```

## Frontmatter Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique identifier (e.g., `BACK-1`) |
| `title` | string | yes | Task title |
| `status` | string | yes | One of configured statuses (default: `To Do`, `In Progress`, `Done`) |
| `assignee` | string[] | no | List of `@name` assignees |
| `reporter` | string | no | Who created the task |
| `created_date` | string | auto | ISO date with optional time |
| `updated_date` | string | auto | Updated on each edit |
| `labels` | string[] | no | Categorization tags |
| `dependencies` | string[] | no | Task IDs this depends on |
| `references` | string[] | no | External links or file paths |
| `documentation` | string[] | no | Linked documentation |
| `priority` | string | no | `high`, `medium`, or `low` |
| `milestone` | string | no | Associated milestone name |
| `parent_task_id` | string | no | Parent task for subtasks |
| `subtasks` | string[] | no | Child task IDs |
| `ordinal` | number | no | Sequencing/ordering value |
| `onStatusChange` | string | no | Per-task shell callback |

## Structured Sections

Acceptance criteria and definition of done use HTML comment markers (`AC:BEGIN`/`AC:END`, `DOD:BEGIN`/`DOD:END`) to delimit parseable checkbox lists. Each item is a markdown checkbox: `- [ ]` (unchecked) or `- [x]` (checked).

## Status Change Callback Variables

When `onStatusChange` fires (global or per-task): `$TASK_ID`, `$OLD_STATUS`, `$NEW_STATUS`, `$TASK_TITLE`.
