---
name: speckit-flow
description: "Full spec-to-implementation workflow. Use when: (1) starting a new feature from scratch, (2) want end-to-end spec-driven development, (3) need autonomous workflow with minimal intervention. Triggers: implement [feature], build from spec, run full speckit flow, create and implement feature."
---

# Speckit Flow: Full Spec-to-Implementation Workflow

Orchestrates the complete pipeline from user story to PR creation using Python scripts.

## Writing Style

All generated artifacts follow these rules:

- Short sentences
- Active voice
- No filler words (just, really, very, basically)
- No em dashes
- Natural tone, not robotic
- Lead with action or outcome
- Match repo language

## Overview

End-to-end spec-driven development pipeline:

```text
CREATE -> CLARIFY -> ANALYZE -> TASKS -> CHECKLIST -> PR -> [IMPLEMENT]
                                                              ^
                                                  (only if impl repo)
```

Fully autonomous - halts only on errors. Creates PR for spec artifacts. Implementation is conditional based on repo type.

## Phase Scripts

Each phase is implemented as a Python script in `scripts/`:

| Phase | Script | Usage |
|-------|--------|-------|
| 1. CREATE (specify) | `speckit_specify.py` | `python scripts/speckit_specify.py "feature description"` |
| 2. CREATE (plan) | `speckit_plan.py` | `python scripts/speckit_plan.py` |
| 3. CLARIFY | `speckit_clarify.py` | `python scripts/speckit_clarify.py` |
| 4. ANALYZE | `speckit_analyze.py` | `python scripts/speckit_analyze.py` |
| 5. TASKS | `speckit_tasks.py` | `python scripts/speckit_tasks.py` |
| 6. CHECKLIST | `speckit_checklist.py` | `python scripts/speckit_checklist.py` |
| 7. PR | `speckit_pr.py` | `python scripts/speckit_pr.py` |
| 8. IMPLEMENT | `speckit_implement.py` | `python scripts/speckit_implement.py` |

All scripts support:
- `--json` for machine-readable output
- `--help` for usage information
- Consistent exit codes (0=success, 1=validation error, 2=bash error)

## Quick Start

```bash
# 1. Create specification (creates branch and spec.md)
python scripts/speckit_specify.py "Add user authentication with OAuth2"

# 2. Create implementation plan
python scripts/speckit_plan.py

# 3. Scan for ambiguities
python scripts/speckit_clarify.py

# 4. Analyze consistency
python scripts/speckit_analyze.py

# 5. Generate tasks
python scripts/speckit_tasks.py

# 6. Generate checklists
python scripts/speckit_checklist.py

# 7. Create PR
python scripts/speckit_pr.py

# 8. Track implementation (if impl repo)
python scripts/speckit_implement.py
```

---

## Resume Detection

Check for existing artifacts using the common module:

```bash
python scripts/common.py --check-paths --json
```

**Resume Logic:**
- If `tasks.md` exists AND all tasks marked `[X]` -> Skip to Phase 7 (PR)
- If `tasks.md` exists with incomplete tasks AND is impl repo -> Skip to Phase 8 (IMPLEMENT)
- If `tasks.md` exists -> Skip to Phase 7 (PR)
- If `plan.md` exists -> Skip to Phase 3 (CLARIFY)
- If `spec.md` exists -> Skip to Phase 2 (CREATE - plan)
- Otherwise -> Start from Phase 1 (CREATE - specify)

---

## Implementation Repo Detection

Check if the repo supports implementation:

```bash
python scripts/common.py --is-impl-repo
```

**Detection Logic:**
- If source directories (src/, lib/, app/) or project files (package.json, go.mod) exist -> Implementation repo
- If only `.specify/` and `specs/` exist -> Spec-only repo

---

## Phase 1: CREATE (Specification)

**Script:** `speckit_specify.py`

```bash
python scripts/speckit_specify.py "Add user authentication" --short-name "user-auth"
```

**Options:**
- `--short-name <name>` - Custom branch name suffix
- `--number <N>` - Manual branch number
- `--json` - JSON output

**Outputs:**
- Creates feature branch (e.g., `001-user-auth`)
- Creates `specs/{branch}/spec.md` from template

---

## Phase 2: CREATE (Planning)

**Script:** `speckit_plan.py`

```bash
python scripts/speckit_plan.py --agent claude
```

**Options:**
- `--agent <type>` - Specific agent to update (claude, gemini, copilot, etc.)
- `--skip-agent` - Skip agent context update
- `--json` - JSON output

**Outputs:**
- Creates `specs/{branch}/plan.md` from template
- Updates agent context files (CLAUDE.md, etc.)

---

## Phase 3: CLARIFY

**Script:** `speckit_clarify.py`

```bash
python scripts/speckit_clarify.py --max-questions 3
```

**Options:**
- `--max-questions N` - Maximum questions to generate (default: 5)
- `--json` - JSON output

**Detects:**
- Explicit markers: `[TODO]`, `[TBD]`, `NEEDS CLARIFICATION`
- Uncertainty: "should", "might", "could"
- Vagueness: "etc.", "various", "as needed"

---

## Phase 4: ANALYZE

**Script:** `speckit_analyze.py`

```bash
python scripts/speckit_analyze.py --strict
```

**Options:**
- `--strict` - Fail on HIGH severity issues
- `--json` - JSON output

**Checks:**
- Empty sections in spec.md and plan.md
- Unresolved markers
- Cross-artifact consistency

**Severity Levels:**
- CRITICAL - Blocks progress
- HIGH - Significant issue
- MEDIUM - Minor inconsistency
- LOW - Suggestion

---

## Phase 5: TASKS

**Script:** `speckit_tasks.py`

```bash
python scripts/speckit_tasks.py
```

**Options:**
- `--json` - JSON output

**Outputs:**
- Creates `specs/{branch}/tasks.md` from template
- Parses user stories from spec.md
- Extracts phases from plan.md

---

## Phase 6: CHECKLIST

**Script:** `speckit_checklist.py`

```bash
python scripts/speckit_checklist.py --type api
```

**Options:**
- `--type <type>` - Force specific type (api, ux, security, performance, general)
- `--json` - JSON output

**Auto-detects domains from spec.md:**
- API keywords -> api checklist
- UI/UX keywords -> ux checklist
- Auth/security keywords -> security checklist
- Performance keywords -> performance checklist

---

## Phase 7: PR

**Script:** `speckit_pr.py`

```bash
python scripts/speckit_pr.py --draft
```

**Options:**
- `--draft` - Create as draft PR
- `--no-push` - Skip pushing to remote
- `--json` - JSON output

**Steps:**
1. Stage all changes
2. Create commit with conventional commit message
3. Push branch
4. Create PR via `gh pr create`

---

## Phase 8: IMPLEMENT (Conditional)

**Script:** `speckit_implement.py`

```bash
python scripts/speckit_implement.py --force
```

**Options:**
- `--force` - Run even in non-implementation repos
- `--json` - JSON output

**Skips if:** Not an implementation repo (use `--force` to override)

**Outputs:**
- Parses tasks.md
- Reports completion progress
- Lists remaining tasks

---

## Error Handling

| Phase | Error | Action |
|-------|-------|--------|
| CREATE (specify) | Script fails | Halt, show error |
| CREATE (plan) | Script fails | Halt, show error |
| CLARIFY | Script fails | Halt, show context |
| ANALYZE | CRITICAL issues | Halt, show report |
| TASKS | Script fails | Halt, suggest speckit_plan.py |
| CHECKLIST | Generation fails | **Continue** (non-blocking) |
| PR | Git/GH error | Halt, show command that failed |
| IMPLEMENT | Task fails | Halt, show task ID and error |

---

## Shared Utilities

The `common.py` module provides:

- **Status emojis**: `Status.SUCCESS` (✅), `Status.ERROR` (❌), etc.
- **Exit codes**: `EXIT_SUCCESS`, `EXIT_VALIDATION_ERROR`, `EXIT_BASH_ERROR`
- **Bash wrapper**: `run_bash_script()` for calling .specify scripts
- **Path utilities**: `get_repo_root()`, `get_feature_paths()`
- **Template loading**: `load_template()`
- **Git/GH commands**: `run_git_command()`, `run_gh_command()`

---

## Notes

- Python scripts wrap existing bash scripts in `.specify/scripts/bash/`
- Context passes through artifacts and git branch state
- Resume detection allows partial workflow continuation
- PR is created but NOT auto-merged
- IMPLEMENT phase only runs in implementation repos
