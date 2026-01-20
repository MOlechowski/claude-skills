---
name: speckit-flow
description: "Full spec-to-implementation workflow. Use when: (1) starting a new feature from scratch, (2) want end-to-end spec-driven development, (3) need autonomous workflow with minimal intervention. Triggers: implement [feature], build from spec, run full speckit flow, create and implement feature."
---

# Speckit Flow: Full Spec-to-Implementation Workflow

Orchestrates pipeline from user story to PR using Python scripts.

## Writing Style

Generated artifacts rules:

- Short sentences, active voice
- No filler words (just, really, very, basically)
- No em dashes
- Natural tone, lead with action/outcome
- Match repo language

## Overview

End-to-end spec-driven development:

```text
CREATE -> CLARIFY -> ANALYZE -> TASKS -> CHECKLIST -> PR -> [IMPLEMENT]
                                                              ^
                                                  (only if impl repo)
```

Fully autonomous, halts only on errors. Creates PR for spec artifacts. Implementation conditional on repo type.

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
| Validate | `speckit_validate.py` | `python scripts/speckit_validate.py` |

All scripts support `--json` for machine output, `--help` for usage, and consistent exit codes (0=success, 1=validation error, 2=bash error).

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

Check existing artifacts:

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

Check if repo supports implementation:

```bash
python scripts/common.py --is-impl-repo
```

**Detection:**
- Source dirs (src/, lib/, app/) or project files (package.json, go.mod) exist -> implementation repo
- Only `.specify/` and `specs/` exist -> spec-only repo

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

**Skips if:** Not implementation repo (use `--force` to override)

**Outputs:** Parses tasks.md, reports completion progress, lists remaining tasks.

---

## Validation

**Script:** `speckit_validate.py`

```bash
python scripts/speckit_validate.py [FEATURE_DIR] [OPTIONS]
```

**Options:**
- `--strict` - Fail on warnings (not just errors)
- `--json` - JSON output

**Validates:**

| File | Required Sections | Checks |
|------|-------------------|--------|
| spec.md | overview, requirements | User stories, acceptance criteria (recommended) |
| plan.md | tech stack, architecture | Dependencies, risks (recommended), language defined |
| tasks.md | - | Checkbox format, task count, phase structure |

**Unresolved Markers Detected:**
- `[TODO]`, `[TBD]`, `NEEDS CLARIFICATION`
- `[unclear]`, `[PLACEHOLDER]`, `XXX`

**Exit Codes:**
- 0: All checks pass
- 1: Validation errors found
- 2: Warnings found (with --strict)

**Example Output:**
```
🔍 Validating feature: 001-my-feature

spec.md
  ✅ File exists
  ✅ Has overview section
  ⚠️ Missing recommended section: user stories

plan.md
  ✅ File exists
  ✅ Language defined: Python 3.11

tasks.md
  ✅ Found 12 tasks (3 completed)
  ✅ Found 4 phases

Summary: 0 errors, 1 warning
```

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

`common.py` provides status emojis (SUCCESS, ERROR), exit codes, bash wrapper (`run_bash_script()`), path utilities (`get_repo_root()`, `get_feature_paths()`), template loading, and Git/GH commands.

---

## Notes

- Python scripts wrap bash scripts in `.specify/scripts/bash/`
- Context passes through artifacts and git branch state
- Resume detection allows partial workflow continuation
- PR created but not auto-merged
- IMPLEMENT phase runs only in implementation repos
