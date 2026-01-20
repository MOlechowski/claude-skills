---
name: spec-driven
description: Autonomous spec-driven development loop. Use when: (1) working through spec repos with tasks.md, (2) implementing features from specs, (3) processing spec backlogs, (4) managing implementation PRs against specs. Triggers: "work through specs", "implement pending tasks", "process spec backlog", "what tasks are left".
---

# Spec-Driven Development Skill

Requirements live in a separate specification repository with structured task files.

## Spec Repository Structure

```
spec-repo/
├── specs/
│   ├── 001-feature-name/
│   │   ├── README.md      # Feature specification
│   │   └── tasks.md       # Implementation tasks
│   ├── 002-another-feature/
│   │   ├── README.md
│   │   └── tasks.md
│   └── ...
└── README.md
```

### Task File Format (tasks.md)

```markdown
# Tasks for Feature Name

## P1 - Critical
- [ ] Implement core functionality
- [ ] Add unit tests

## P2 - Important
- [ ] Add integration tests
- [ ] Update documentation

## P3 - Nice to Have
- [ ] Add performance benchmarks
```

## Workflow

### 1. Close Open PRs First

Before creating new work, prioritize merging existing PRs:

```bash
# Check for open PRs
gh pr list --state open

# Use gh-pr skill to process them
# See: gh-pr skill for merge workflow
```

### 2. Find Incomplete Tasks

```bash
# Find all incomplete tasks across specs
grep -rn "^\- \[ \]" $SPEC_REPO/specs/*/tasks.md

# Find specs with incomplete tasks
find $SPEC_REPO/specs -name "tasks.md" -exec grep -l "^\- \[ \]" {} \;

# Count incomplete tasks per spec
for f in $SPEC_REPO/specs/*/tasks.md; do
  echo "$(grep -c "^\- \[ \]" "$f" 2>/dev/null || echo 0) $f"
done | sort -rn
```

### 3. Implement Tasks

Process ALL tasks regardless of priority level:

1. Read the spec's README.md for context
2. Understand the task requirements
3. Implement in the implementation repo
4. Create focused, reasonable-sized PRs
5. Use gh-pr skill for merging

### 4. Update Spec Repository

When a task is complete:

```markdown
# Before
- [ ] Implement user authentication

# After (with PR link)
- [x] Implement user authentication [PR #42](https://github.com/org/repo/pull/42)
```

```bash
# Commit to spec repo
cd $SPEC_REPO
git add specs/001-feature/tasks.md
git commit -m "mark: complete authentication task [PR #42]"
git push origin main  # Spec repos typically allow direct push
```

## Multi-Spec Implementation (REQUIRED: Use Worktrees)

**When implementing multiple specs in one session, ALWAYS use git worktrees.** This prevents:
- Branch conflicts when switching between specs
- Lost work from uncommitted changes
- Context confusion between specs

### Setup Worktrees Upfront

Before starting any implementation, create worktrees for ALL specs:

```bash
# From implementation repo root
cd $IMPL_REPO

# Create worktree for each spec (use spec branch name)
git worktree add ../impl-014-feature -b 014-feature-name main
git worktree add ../impl-015-feature -b 015-feature-name main

# Verify
git worktree list
```

### Implement in Separate Directories

Work in each worktree directory independently:

```bash
# Spec 014
cd ../impl-014-feature
# ... implement, test, commit ...
git push -u origin 014-feature-name
gh pr create --title "feat: spec 014 - feature name"

# Spec 015 (no git checkout needed!)
cd ../impl-015-feature
# ... implement, test, commit ...
git push -u origin 015-feature-name
gh pr create --title "feat: spec 015 - feature name"
```

### Cleanup After PRs Merged

```bash
cd $IMPL_REPO
git worktree remove ../impl-014-feature
git worktree remove ../impl-015-feature
git branch -d 014-feature-name 015-feature-name
```

### Why Worktrees for Multi-Spec?

| Without Worktrees | With Worktrees |
|-------------------|----------------|
| `git checkout` loses uncommitted work | Each spec has isolated directory |
| Easy to commit to wrong branch | Each worktree = one branch only |
| Must remember current branch | Directory name = spec context |
| Sequential only | Can work on specs in parallel |

## Parallel Work

Combine git-worktree (isolated directories) with parallel-flow (agent orchestration):

### Setup Worktrees

```bash
# Create worktrees for parallel tasks (max 3)
git worktree add ../impl-task-1 -b feat/task-1
git worktree add ../impl-task-2 -b feat/task-2
git worktree add ../impl-task-3 -b feat/task-3
```

### Launch Parallel Agents

Use parallel-flow to launch agents, each working in its own worktree:

```
Task(
  description="Implement task 1",
  prompt="Working directory: ../impl-task-1

  1. Implement [task description]
  2. Run tests
  3. Commit changes
  4. Create PR using: gh pr create --title '...' --body '...'

  Output PR URL to /tmp/parallel_tasks/agent_0.json",
  subagent_type="general-purpose",
  run_in_background=true
)

Task(
  description="Implement task 2",
  prompt="Working directory: ../impl-task-2
  ...same pattern...",
  subagent_type="general-purpose",
  run_in_background=true
)
```

### Aggregate Results

After agents complete:
1. Collect PR URLs from output files
2. Update spec repo with PR links
3. Clean up worktrees: `git worktree remove ../impl-task-1`

### When to Use Parallel Flow

| Scenario | Use parallel-flow? |
|----------|-------------------|
| < 5 specs | No - sequential is fine |
| > 5 specs with backlogs | Yes - parallel discovery |
| Independent tasks across specs | Yes - parallel implementation |
| Tasks with cross-spec dependencies | No - sequential required |

### Rules

- **Max 3 concurrent worktrees/agents** to manage CI load
- Each agent commits only to its worktree branch
- Each agent creates its own PR
- Aggregation updates spec repo with all PR links

## Handling Blocked Tasks

Some tasks require infrastructure not available in the current session:

### E2E Tests Requiring Credentials

Write the test files anyway with appropriate build tags:

```go
//go:build e2e

package e2e

func TestFeatureE2E(t *testing.T) {
    // Test implementation
    // Will run when infrastructure is available
}
```

### Tasks Requiring Deployed Infrastructure

1. Document the blocker clearly
2. Create the code that will work once infrastructure exists
3. Mark task with note: `- [ ] Task name (blocked: needs X deployed)`

### Unit Tests for External Dependencies

Use dependency injection and mocks:

```go
// Define interface
type GitHubClient interface {
    GetPullRequest(ctx context.Context, num int) (*PR, error)
}

// Test with mock
func TestFeature(t *testing.T) {
    mockClient := mocks.NewGitHubClient(t)
    mockClient.On("GetPullRequest", mock.Anything, 42).Return(&PR{}, nil)
    // ...
}
```

## Rules

1. **Never disable pre-commit hooks** - Fix all problems when hooks fail
2. **Create reasonable-sized PRs** - Batch related tasks, but keep PRs focused
3. **Verify tests pass** before requesting merge
4. **Link PRs in spec repo** when marking tasks complete
5. **Process ALL tasks** regardless of priority level (P1, P2, P3)
6. **Max 3 concurrent PRs** to manage CI load

## Integration with Other Skills

- **gh-pr**: Use for PR lifecycle management and merging
- **git-worktree**: Use for creating isolated working directories
- **parallel-flow**: Use for orchestrating concurrent agent execution
- **self-improvement**: Capture learnings after completing tasks

## Reflection After Tasks

After completing tasks or a work session, reflect on learnings using the self-improvement skill:

### Trigger Questions
- Did I figure out something not in the docs?
- Did I find a workaround for a blocker?
- Did I discover a better pattern?
- Was anything confusing or ambiguous?

### What to Update
| Learning Type | Update Location |
|---------------|-----------------|
| Project setup/build | `CLAUDE.md` / `AGENTS.md` |
| Spec workflow | This skill or prompt docs |
| Tool usage | Relevant skill docs |
| Blockers | Document in workflow + history |

### Example Flow
```bash
# After completing a task that revealed missing instructions:

# 1. Update the relevant document
vim CLAUDE.md  # Add the missing instruction

# 2. Commit with self-improvement format
git commit -m "docs: improve CLAUDE.md - add mock generation step"

# 3. Log in document history (if present)
# Add: "2024-01-15: Added mock generation workflow"
```

See: **self-improvement** skill for full protocol.

## Quick Reference

See `quick-reference.md` for commands and patterns.
