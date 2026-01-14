---
name: speckit-flow
description: |
  Full spec-to-implementation workflow. Autonomous execution from user story to PR creation.

  Use this skill when:
  - Starting a new feature from scratch
  - Want end-to-end spec-driven development
  - Need autonomous workflow with minimal intervention

  Examples:
  - "implement user authentication feature"
  - "build the caching layer from spec"
  - "run full speckit flow for feature X"
  - "create and implement a new feature"
---

# Speckit Flow: Full Spec-to-Implementation Workflow

You are an expert at spec-driven development. This skill orchestrates the complete pipeline from user story to PR creation.

## Overview

End-to-end spec-driven development pipeline:

```text
CREATE → CLARIFY → TASKS → CHECKLIST → IMPLEMENT → PR
```

Fully autonomous - halts only on errors. Creates PR but does not auto-merge.

## Resume Detection

Before starting, check for existing artifacts to determine resume point:

```bash
.specify/scripts/bash/check-prerequisites.sh --paths-only --json
```

**Resume Logic:**
- If `tasks.md` exists AND all tasks marked `[X]` → Skip to Phase 6 (PR)
- If `tasks.md` exists with incomplete tasks → Skip to Phase 5 (IMPLEMENT)
- If `plan.md` exists → Skip to Phase 3 (TASKS)
- If `spec.md` exists → Skip to Phase 2 (CLARIFY)
- Otherwise → Start from Phase 1 (CREATE)

Report resume status: `Resuming from Phase N: {PHASE_NAME}`

---

## Phase 1: CREATE

### Step 1.1: Initialize Feature

Run the feature creation script:

```bash
.specify/scripts/bash/create-new-feature.sh --json "$ARGUMENTS"
```

Parse JSON output:
- `BRANCH_NAME`: Feature branch (e.g., `017-health-check`)
- `SPEC_FILE`: Path to spec.md
- `FEATURE_NUM`: Numeric prefix

Store `FEATURE_DIR` as `specs/{BRANCH_NAME}/`

### Step 1.2: SPECIFY Phase (5 Iterations)

For each iteration 1-5, refine `spec.md`:

1. **Foundation**: Parse input, create user stories with priorities (P1, P2, P3)
2. **User Story Depth**: Add Given/When/Then scenarios, priority justifications
3. **Requirements & Edge Cases**: Expand functional requirements
4. **Success Criteria**: Make criteria measurable and technology-agnostic
5. **Polish**: Final quality pass, constitution compliance

Display: `SPECIFY Phase - Iteration {N}/5: {Focus}`

### Step 1.3: Setup Plan

```bash
.specify/scripts/bash/setup-plan.sh --json
```

### Step 1.4: PLAN Phase (5 Iterations)

For each iteration 1-5, refine `plan.md`:

1. **Architecture Skeleton**: High-level approach, components
2. **Implementation Details**: Data models, testing strategy
3. **Edge Case Handling**: Error patterns, state machines
4. **Constitution Check**: Validate principles, observability
5. **Task Readiness**: Integration points, E2E verification

Display: `PLAN Phase - Iteration {N}/5: {Focus}`

**Artifacts Generated (Phase 0-1):**
- `research.md` - Design research and decisions (Phase 0)
- `data-model.md` - Entity definitions and relationships (Phase 1)
- `contracts/` - API specifications (Phase 1)
- `quickstart.md` - Integration test scenarios (Phase 1)

### Step 1.5: RESEARCH Phase (5 Iterations)

For each iteration 1-5, explore codebase:

1. **Similar Features**: Find existing patterns
2. **Pattern Analysis**: Understand architecture
3. **Integration Points**: Map dependencies
4. **Testing Patterns**: Study test isolation
5. **Synthesis**: Create `research.md`, enhance `plan.md`

Display: `RESEARCH Phase - Iteration {N}/5: {Focus}`

### Step 1.6: ANALYZE Phase (Until Zero Problems)

Loop (max 20 iterations):

1. Cross-artifact consistency check
2. Constitution compliance validation
3. Quality validation (Gherkin, metrics)
4. Auto-fix problems found
5. Exit when zero problems

Display: `ANALYZE Phase - Iteration {N}: {problem_count} problems`

### Step 1.7: Update Agent Context

```bash
.specify/scripts/bash/update-agent-context.sh
```

**Phase 1 Complete**: Display `CREATE phase complete`

---

## Phase 2: CLARIFY

Resolve ambiguities in spec.md:

1. Scan spec for `[NEEDS CLARIFICATION]` markers and gaps
2. Generate up to 5 prioritized clarification questions
3. For each question, present options with recommended answer
4. Update spec.md with clarifications

**Phase 2 Complete**: Display `CLARIFY phase complete - {N} clarifications added`

---

## Phase 3: TASKS

### Pre-check

```bash
.specify/scripts/bash/check-prerequisites.sh --json
```

If fails: Halt with error, suggest running `/speckit.plan`

### Generate Tasks

Parse `spec.md` and `plan.md` to create `tasks.md`:

1. Extract user stories with priorities
2. Create phased execution plan:
   - Phase 1: Setup
   - Phase 2: Foundational (blocking)
   - Phase 3+: User Stories by priority
   - Final: Polish
3. Mark parallelizable tasks with `[P]`
4. Include file paths in each task

**Phase 3 Complete**: Display `TASKS phase complete - {N} tasks generated`

---

## Phase 4: CHECKLIST

Generate requirement quality checklists based on spec content:

1. Scan spec.md for domain keywords:
   - API/endpoint/REST → generate `api.md` checklist
   - UI/UX/interface → generate `ux.md` checklist
   - auth/security/permission → generate `security.md` checklist
   - performance/latency/throughput → generate `performance.md` checklist

2. Create `{FEATURE_DIR}/checklists/` directory
3. Generate at least one checklist

**Error Handling**: If generation fails, log warning and **continue** (non-blocking)

**Phase 4 Complete**: Display `CHECKLIST phase complete - {N} checklists created`

---

## Phase 5: IMPLEMENT

### Pre-check

```bash
.specify/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks
```

If fails: Halt with error, suggest running `/speckit.tasks`

### Execute Tasks

1. Parse `tasks.md` for phases and dependencies
2. Execute phase-by-phase:
   - Setup first
   - Foundational (blocks all stories)
   - User stories in priority order
   - Polish last
3. For each task:
   - Display: `Executing T{ID}: {description}`
   - Implement the task
   - Mark complete: `- [X]` in tasks.md
4. Respect dependencies: sequential unless marked `[P]`

**Error Handling**: On task failure, halt and report:
```
IMPLEMENT failed at T{ID}: {task_description}
Error: {error_message}
```

**Phase 5 Complete**: Display `IMPLEMENT phase complete - all tasks done`

---

## Phase 6: PR

Create pull request for the implementation:

### Step 6.1: Stage Changes

```bash
git add -A
```

### Step 6.2: Create Commit

Extract feature summary from spec.md for commit message:

```bash
git commit -m "$(cat <<'EOF'
feat({BRANCH_NAME}): {short_description}

Implements {feature_name} as specified in specs/{BRANCH_NAME}/spec.md

- {key_change_1}
- {key_change_2}
- {key_change_3}
EOF
)"
```

### Step 6.3: Push Branch

```bash
git push -u origin {BRANCH_NAME}
```

### Step 6.4: Create PR

```bash
gh pr create --title "feat: {feature_name}" --body "$(cat <<'EOF'
## Summary
{Extract from spec.md: 2-3 bullet points}

## Changes
- Implements {user_story_1}
- Implements {user_story_2}

## Artifacts
- [spec.md](specs/{BRANCH_NAME}/spec.md)
- [plan.md](specs/{BRANCH_NAME}/plan.md)
- [research.md](specs/{BRANCH_NAME}/research.md)
- [tasks.md](specs/{BRANCH_NAME}/tasks.md)

## Test Plan
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual verification of acceptance scenarios
EOF
)"
```

Capture and store PR URL.

**Phase 6 Complete**: Display PR URL

---

## Final Report

Display completion summary:

```text
============================================
SPECKIT FLOW COMPLETE
============================================

Feature: {feature_name}
Branch:  {BRANCH_NAME}
PR:      {PR_URL}

Artifacts:
  spec.md       [created/updated]
  plan.md       [created/updated]
  research.md   [created/updated]
  data-model.md [if entities defined]
  contracts/    [if APIs defined]
  quickstart.md [created/updated]
  tasks.md      [X/{total} complete]
  checklists/   [{N} generated]

Next Steps:
  1. Review PR: {PR_URL}
  2. Address any review comments
  3. Merge when approved
============================================
```

---

## Error Handling Summary

| Phase | Error | Action |
|-------|-------|--------|
| CREATE | Script fails | Halt, show script error |
| CREATE | Iteration fails | Halt, show iteration number and error |
| CLARIFY | Question loop fails | Halt, show last question |
| TASKS | Prerequisites missing | Halt, suggest `/speckit.plan` |
| CHECKLIST | Generation fails | **Continue** (non-blocking) |
| IMPLEMENT | Task fails | Halt, show task ID and error |
| PR | Git error | Halt, show git command that failed |
| PR | GH CLI error | Halt, show gh command that failed |

---

## Notes

- All paths must be absolute
- Use `--json` flag for script outputs when parsing
- Constitution compliance is checked in ANALYZE phase
- Checklist phase is non-blocking to avoid halting on optional quality checks
- PR is created but NOT auto-merged - user reviews and merges
