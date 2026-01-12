---
name: spec-driven
description: |
  Autonomous development loop for spec-driven projects with task tracking.

  Use this skill when:
  - Working through a spec repository with tasks.md files
  - Implementing features defined in external specifications
  - Processing a backlog of spec-defined tasks
  - Managing implementation PRs against a spec

  Examples:
  - "work through the spec tasks"
  - "implement the pending specs"
  - "process the spec backlog"
  - "what tasks are left in the spec?"
---

# Spec-Driven Development Skill

You are an expert at autonomous spec-driven development, where requirements live in a separate specification repository with structured task files.

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

## Parallel Work

Use git-worktree skill for working on multiple tasks simultaneously:

- **Max 3 concurrent PRs** to avoid CI overload
- Each worktree handles one task/PR
- See: git-worktree skill for setup

```bash
# Create worktrees for parallel tasks
git worktree add ../impl-task-1 -b feat/task-1
git worktree add ../impl-task-2 -b feat/task-2
git worktree add ../impl-task-3 -b feat/task-3
```

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
- **git-worktree**: Use for parallel task implementation
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
