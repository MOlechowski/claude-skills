# Spec Format Reference

Required sections and formats for speckit-flow artifacts.

## spec.md

| Section | Format | Notes |
|---------|--------|-------|
| Overview | Problem Statement, Solution Overview | Context and scope |
| User Scenarios | Gherkin (Given/When/Then) | Max 5 scenarios |
| Requirements | FR-XXX, NFR-XXX format | Functional and non-functional |
| Success Criteria | SC-XXX format with validation method | How to verify done |
| Edge Cases | Table: Case / Behavior / Mitigation | Failure modes |
| Out of Scope | Bullet list | Explicit boundaries |

### User Scenarios Example

```gherkin
Given [precondition]
When [action]
Then [expected result]
```

### Requirements Example

```markdown
### FR-1: Functional Requirement
The system shall [do something].

### NFR-1: Performance
Response time < 100ms.
```

### Success Criteria Example

| ID | Criteria | Validation |
|----|----------|------------|
| SC-1 | [What must be true] | [How to verify] |

### Edge Cases Example

| Case | Behavior | Mitigation |
|------|----------|------------|
| [failure mode] | [what happens] | [how to handle] |

## plan.md

| Section | Format | Notes |
|---------|--------|-------|
| Overview | Paragraph | Summary of approach |
| Tech Stack | Table: Category / Technology / Version | All dependencies |
| Phases | Numbered sections with milestones | Implementation order |
| Risks | Table: Risk / Likelihood / Impact / Mitigation | What could go wrong |
| Verification Checklist | Checkbox list | How to validate |
| Rollback Plan | Steps | How to undo if needed |

### Tech Stack Example

| Category | Technology | Version |
|----------|------------|---------|
| Language | Python | >= 3.11 |
| Framework | FastAPI | ~2.0 |

### Risks Example

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| [what could go wrong] | Low/Medium/High | Low/Medium/High | [how to prevent] |

## tasks.md

| Requirement | Rule |
|-------------|------|
| Max tasks | 20 per spec (split if exceeded) |
| Format | `- [ ] TXXX: Description` |
| Categories | Component, Integration, Verification |
| Dependencies | Document task order |
| Acceptance Criteria | Table with success metrics |

### Task Categories

```markdown
### Component Tasks
- [ ] T001: [standalone unit of work]

### Integration Tasks
- [ ] T002: [connects components together]

### Verification Tasks
- [ ] T003: E2E: [end-to-end validation]
```

### Acceptance Criteria Example

| Task | Criteria | Success Metric |
|------|----------|----------------|
| T001 | [what must be true] | [how to measure] |

## checklists/

- Directory must exist with at least one `.md` file
- Use CHK-XXX format for items
- Common types: security, infrastructure, api, ux

### Checklist Example

```markdown
# Security Checklist

- [ ] CHK001 Input validation implemented
- [ ] CHK002 Authentication required
- [ ] CHK003 No sensitive data in logs
```
