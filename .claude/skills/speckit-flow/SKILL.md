---
name: speckit-flow
description: Full spec-to-implementation workflow.
---

# Speckit Flow: Full Spec-to-Implementation Workflow

Use this skill when:
- Starting a new feature from scratch
- Want end-to-end spec-driven development
- Need autonomous workflow with minimal intervention

Examples:
- "implement user authentication feature"
- "build the caching layer from spec"
- "run full speckit flow for feature X"
- "create and implement a new feature"

You are an expert at spec-driven development. This skill orchestrates the complete pipeline from user story to PR creation by delegating to specialized commands.

## Overview

End-to-end spec-driven development pipeline:

```text
CREATE → CLARIFY → ANALYZE → TASKS → CHECKLIST → PR → [IMPLEMENT]
                                                           ↑
                                               (only if impl repo)
```

Fully autonomous - halts only on errors. Creates PR for spec artifacts. Implementation is conditional based on repo type.

## Command Delegation

This skill delegates to existing commands instead of duplicating logic:

| Phase | Command | Purpose |
|-------|---------|---------|
| 1. CREATE (specify) | `/speckit.specify` | Create spec.md |
| 2. CREATE (plan) | `/speckit.plan` | Create plan.md and artifacts |
| 3. CLARIFY | `/speckit.clarify` | Resolve ambiguities |
| 4. ANALYZE | `/speckit.analyze` | Validate consistency |
| 5. TASKS | `/speckit.tasks` | Generate task list |
| 6. CHECKLIST | `/speckit.checklist` | Generate quality checklists |
| 7. PR | (inline) | Create PR for spec artifacts |
| 8. IMPLEMENT | `/speckit.implement` | Execute tasks (conditional) |

---

## Resume Detection

Before starting, check for existing artifacts to determine resume point:

```bash
.specify/scripts/bash/check-prerequisites.sh --paths-only --json
```

**Resume Logic:**
- If `tasks.md` exists AND all tasks marked `[X]` → Skip to Phase 7 (PR)
- If `tasks.md` exists with incomplete tasks AND is impl repo → Skip to Phase 8 (IMPLEMENT)
- If `tasks.md` exists → Skip to Phase 7 (PR)
- If `plan.md` exists → Skip to Phase 3 (CLARIFY)
- If `spec.md` exists → Skip to Phase 2 (CREATE - plan)
- Otherwise → Start from Phase 1 (CREATE - specify)

Report resume status: `Resuming from Phase N: {PHASE_NAME}`

Store context variables from check-prerequisites output:
- `FEATURE_DIR`: Path to specs/{branch-name}/
- `BRANCH_NAME`: Current feature branch name
- `ARGUMENTS`: Original user input

---

## Implementation Repo Detection

Before Phase 8, detect if current repo supports implementation:

```bash
# Check for implementation indicators
[ -d "src" ] || [ -d "lib" ] || [ -d "app" ] || [ -d "packages" ] || [ -f "package.json" ] || [ -f "go.mod" ] || [ -f "Cargo.toml" ] || [ -f "pyproject.toml" ]
```

**Detection Logic:**
- If source directories or project files exist → Implementation repo
- If only `.specify/` and `specs/` exist → Spec-only repo

Store result in `IS_IMPL_REPO` (true/false).

---

## Phase 1: CREATE (Specification)

**Execute:** `/speckit.specify $ARGUMENTS`

The command handles:
- Branch name generation and creation
- spec.md initialization from template
- Quality validation iterations
- Clarification questions if needed

**Capture from output:**
- `BRANCH_NAME`
- `SPEC_FILE` path
- `FEATURE_DIR` path

**Gate:** Command must complete successfully.

**Display:** `Phase 1 complete: CREATE (specification)`

---

## Phase 2: CREATE (Planning)

**Execute:** `/speckit.plan`

The command handles:
- setup-plan.sh execution
- Phase 0 (research) and Phase 1 (design)
- Artifact generation: research.md, data-model.md, contracts/, quickstart.md
- Agent context updates

**Gate:** Command must complete successfully.

**Display:** `Phase 2 complete: CREATE (planning)`

---

## Phase 3: CLARIFY

**Execute:** `/speckit.clarify`

The command handles:
- Ambiguity scanning using taxonomy
- Up to 5 clarification questions
- Incremental spec.md updates
- Coverage summary

**Gate:** Non-blocking if user declines further questions.

**Display:** `Phase 3 complete: CLARIFY`

---

## Phase 4: ANALYZE

**Execute:** `/speckit.analyze`

The command handles:
- Cross-artifact consistency check
- Constitution compliance validation
- Duplication, ambiguity, coverage gap detection
- Severity-rated findings report

**Gate:**
- CRITICAL issues → Halt, display report, suggest fixes
- HIGH issues → Warn, ask user to confirm continuation
- MEDIUM/LOW → Continue automatically

**Display:** `Phase 4 complete: ANALYZE`

---

## Phase 5: TASKS

**Execute:** `/speckit.tasks`

The command handles:
- spec.md and plan.md parsing
- tasks.md generation with phases
- Dependency graph and parallel markers
- Task count summary

**Gate:** Command must complete successfully.

**Display:** `Phase 5 complete: TASKS - {N} tasks generated`

---

## Phase 6: CHECKLIST

Scan spec.md for domain keywords and invoke checklist generation:

- If API/endpoint/REST → `/speckit.checklist api`
- If UI/UX/interface → `/speckit.checklist ux`
- If auth/security/permission → `/speckit.checklist security`
- If performance/latency → `/speckit.checklist performance`

Generate at least one general checklist if no keywords match.

**Gate:** Non-blocking - log warnings and continue if generation fails.

**Display:** `Phase 6 complete: CHECKLIST - {N} checklists created`

---

## Phase 7: PR

Create pull request for spec artifacts:

### Step 7.1: Stage Changes

```bash
git add -A
```

### Step 7.2: Create Commit

```bash
git commit -m "$(cat <<'EOF'
feat({BRANCH_NAME}): {short_description}

Adds specification for {feature_name}

- spec.md: Feature specification
- plan.md: Technical design
- tasks.md: Implementation tasks
EOF
)"
```

### Step 7.3: Push Branch

```bash
git push -u origin {BRANCH_NAME}
```

### Step 7.4: Create PR

```bash
gh pr create --title "spec: {feature_name}" --body "$(cat <<'EOF'
## Summary
{Extract from spec.md: 2-3 bullet points}

## Spec Artifacts
- [spec.md](specs/{BRANCH_NAME}/spec.md) - Feature specification
- [plan.md](specs/{BRANCH_NAME}/plan.md) - Technical design
- [tasks.md](specs/{BRANCH_NAME}/tasks.md) - Implementation tasks
- [research.md](specs/{BRANCH_NAME}/research.md) - Design research

## Checklists
{List generated checklists}

## Next Steps
- [ ] Review spec artifacts
- [ ] Approve for implementation
EOF
)"
```

Capture and store PR URL.

**Display:** `Phase 7 complete: PR - {PR_URL}`

---

## Phase 8: IMPLEMENT (Conditional)

**Skip if:** `IS_IMPL_REPO` is false

**Execute:** `/speckit.implement`

The command handles:
- Checklist completion verification
- Implementation context loading
- Task execution phase-by-phase
- tasks.md progress updates

**Gate:** Command must complete successfully. On task failure, halt with details.

**Display:** `Phase 8 complete: IMPLEMENT - all tasks done`

---

## Final Report

```text
============================================
SPECKIT FLOW COMPLETE
============================================

Feature: {feature_name}
Branch:  {BRANCH_NAME}
PR:      {PR_URL}

Phases:
  1. CREATE (specify)  [completed/skipped]
  2. CREATE (plan)     [completed/skipped]
  3. CLARIFY           [completed/skipped]
  4. ANALYZE           [completed/skipped]
  5. TASKS             [completed/skipped]
  6. CHECKLIST         [completed/skipped]
  7. PR                [completed]
  8. IMPLEMENT         [completed/skipped/n/a]

Artifacts:
  spec.md       [created/updated]
  plan.md       [created/updated]
  research.md   [created/updated]
  tasks.md      [{completed}/{total} tasks]
  checklists/   [{N} generated]

Next Steps:
  1. Review PR: {PR_URL}
  2. Address review comments
  3. Merge when approved
============================================
```

---

## Error Handling

| Phase | Error | Action |
|-------|-------|--------|
| CREATE (specify) | Command fails | Halt, show error |
| CREATE (plan) | Command fails | Halt, show error |
| CLARIFY | Command fails | Halt, show context |
| ANALYZE | CRITICAL issues | Halt, show report |
| TASKS | Command fails | Halt, suggest `/speckit.plan` |
| CHECKLIST | Generation fails | **Continue** (non-blocking) |
| PR | Git/GH error | Halt, show command that failed |
| IMPLEMENT | Task fails | Halt, show task ID and error |

---

## Notes

- Commands handle their own iteration and quality checks
- Context passes through artifacts and git branch state
- Resume detection allows partial workflow continuation
- PR is created but NOT auto-merged
- IMPLEMENT phase only runs in implementation repos
