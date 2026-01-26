---
description: "Acceptance criteria and tests template for feature validation"
---

# Acceptance: [FEATURE NAME]

**Feature Branch**: `[###-feature-name]`
**Created**: [DATE]
**Status**: Pending Acceptance

## Acceptance Criteria

<!-- Derived from user stories in spec.md -->

### AC-001: [Criterion from User Story 1]

- **Source**: US-1 / FR-XXX
- **Condition**: [What must be true]
- **Verified**: [ ] Pass / [ ] Fail

### AC-002: [Criterion from User Story 2]

- **Source**: US-2 / FR-XXX
- **Condition**: [What must be true]
- **Verified**: [ ] Pass / [ ] Fail

### AC-003: [Criterion from User Story 3]

- **Source**: US-3 / FR-XXX
- **Condition**: [What must be true]
- **Verified**: [ ] Pass / [ ] Fail

---

## Acceptance Tests

### AT-001: [Test Name from AC-001]

```gherkin
Feature: [Feature Name]

  Scenario: [Scenario derived from acceptance criteria]
    Given [precondition/initial state]
    When [user action]
    Then [expected outcome]
    And [additional verification]
```

**Status**: [ ] Pass / [ ] Fail
**Tested By**: [Name]
**Date**: [Date]

### AT-002: [Test Name from AC-002]

```gherkin
Feature: [Feature Name]

  Scenario: [Another scenario]
    Given [precondition]
    When [action]
    Then [result]
```

**Status**: [ ] Pass / [ ] Fail
**Tested By**: [Name]
**Date**: [Date]

### AT-003: [Test Name from AC-003]

```gherkin
Feature: [Feature Name]

  Scenario: [Another scenario]
    Given [precondition]
    When [action]
    Then [result]
```

**Status**: [ ] Pass / [ ] Fail
**Tested By**: [Name]
**Date**: [Date]

---

## Automated Test Coverage

- [ ] Unit tests cover acceptance criteria
- [ ] Integration tests passing
- [ ] E2E scenarios implemented in test framework

---

## Sign-off Checklist

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | [ ] Approved |
| QA | | | [ ] Approved |
| Product Owner | | | [ ] Approved |

---

## Notes

[Any additional acceptance notes, edge cases discovered during testing, or known limitations]
