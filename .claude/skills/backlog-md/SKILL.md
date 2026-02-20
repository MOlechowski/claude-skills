---
name: backlog-md
description: "Markdown-native task manager and Kanban board for Git repositories. Use for: (1) managing project backlogs with tasks stored as markdown files, (2) spec-driven AI development with acceptance criteria and implementation plans, (3) Kanban board visualization (TUI and web), (4) task dependencies, milestones, and decision records. Triggers: backlog, kanban, task management, project backlog, acceptance criteria, definition of done."
---

# Backlog.md

Markdown-native task manager embedded in Git repos. All data stored as `.md` files in a `backlog/` directory. Provides CLI, TUI Kanban board, web UI, and MCP integration.

## Prerequisites

Verify installation: `backlog --version`

Install if missing:
```bash
npm i -g backlog.md    # or: bun add -g backlog.md
```

## Initialization

```bash
backlog init "Project Name"
```

Creates `backlog/` directory with `config.yml` and `tasks/` subdirectory. The wizard asks for integration choice (MCP recommended) and instruction file generation.

Re-run `backlog init` to update settings without losing data.

## Spec-Driven AI Workflow

The recommended workflow for AI-assisted development:

1. **Decompose** - Create tasks with clear descriptions and acceptance criteria
2. **Plan** - Research codebase, write implementation plan in the task
3. **Review** - User reviews plan before implementation
4. **Implement** - Execute the plan
5. **Verify** - Check acceptance criteria, run tests
6. **Complete** - Mark task done with final summary

Always search for existing tasks before creating new ones to prevent duplicates.

## Task Operations

### Create

```bash
backlog task create "Title"
backlog task create "Title" -d "Description" -a @me -s "To Do" --priority high
backlog task create "Title" --ac "Must do X" --ac "Must do Y" --plan "1. Research\n2. Implement"
backlog task create "Title" --dep task-1,task-2 --ref src/api.ts --doc docs/spec.md
backlog task create "Subtask" -p 14           # subtask of task-14
backlog task create "Spike" --draft           # draft/spike task
```

### List and View

```bash
backlog task list                              # all tasks
backlog task list -s "In Progress"             # by status
backlog task list -a @me                       # by assignee
backlog task list --parent 42                  # subtasks of task-42
backlog task 7                                 # interactive view
backlog task 7 --plain                         # plain text (for AI/scripts)
```

### Edit

```bash
backlog task edit 7 -s "In Progress" -a @me
backlog task edit 7 --plan "Implementation approach"
backlog task edit 7 --notes "Completed X, working on Y"
backlog task edit 7 --append-notes "New findings"
backlog task edit 7 --final-summary "PR-style summary"
backlog task edit 7 --ac "New criterion"       # add acceptance criterion
backlog task edit 7 --check-ac 1               # mark AC #1 done
backlog task edit 7 --uncheck-ac 2             # mark AC #2 not done
backlog task edit 7 --remove-ac 3              # remove AC #3
backlog task edit 7 --dod "Ship notes"         # add definition of done
backlog task edit 7 --check-dod 1              # mark DoD #1 done
backlog task edit 7 --dep task-1 --dep task-2  # add dependencies
```

### Complete and Archive

```bash
backlog task edit 7 -s "Done"                  # mark done
backlog task archive 7                         # archive task
backlog cleanup                                # archive old completed tasks
```

### Search

```bash
backlog search "auth"                          # fuzzy search
backlog search "api" --status "In Progress"    # filter by status
backlog search "bug" --priority high           # filter by priority
backlog search "feature" --plain               # plain text output
```

## Board and Views

```bash
backlog board                                  # interactive Kanban TUI
backlog board export                           # export to markdown
backlog board export --readme                  # embed in README.md
backlog browser                                # web UI (port 6420)
backlog browser --port 8080                    # custom port
backlog overview                               # project statistics
```

## Documents, Decisions, Milestones

```bash
backlog doc create "API Guidelines"
backlog doc create "Setup Guide" -p guides
backlog doc list
backlog doc view doc-1

backlog decision create "Use PostgreSQL"
backlog decision create "Migrate to TS" -s proposed

backlog milestone add "v1.0"
backlog milestone list
```

## Task File Format

Tasks are markdown files at `backlog/tasks/{prefix}-{id} - {Title}.md`. See [references/task-format.md](references/task-format.md) for the full format specification.

## Configuration

```bash
backlog config                                 # interactive wizard
backlog config list                            # view all settings
backlog config get defaultEditor               # get specific value
backlog config set autoCommit true             # set value
```

Key settings: `statuses`, `defaultStatus`, `labels`, `definition_of_done`, `defaultEditor`, `defaultPort`, `autoCommit`, `bypassGitHooks`, `checkActiveBranches`, `onStatusChange`. See [references/config.md](references/config.md) for all options.

## Multi-line Input

The CLI does not auto-convert `\n`. Use shell-specific syntax:

```bash
# Bash/Zsh
backlog task create "Feature" --desc $'Line1\nLine2\n\nParagraph'
# POSIX sh
backlog task create "Feature" --desc "$(printf 'Line1\nLine2')"
```

## MCP Integration

For AI agent integration via Model Context Protocol:

```bash
claude mcp add backlog --scope user -- backlog mcp start
```

MCP provides tools: `task_create`, `task_list`, `task_search`, `task_edit`, `task_view`, `task_archive`, `task_complete`, `document_*`, `milestone_*`, and workflow guides.

## Directory Structure

```
backlog/
├── config.yml          # project configuration
├── tasks/              # active tasks
├── drafts/             # draft/spike tasks
├── completed/          # completed tasks
├── archive/            # archived items
├── docs/               # documentation (nested subdirs supported)
├── decisions/          # architecture decision records
└── milestones/         # release milestones
```
