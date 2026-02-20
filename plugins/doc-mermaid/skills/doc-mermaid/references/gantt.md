# Gantt Chart Reference

Gantt charts visualize project schedules, tasks, and dependencies.

## Basic Syntax

```mermaid
gantt
    title Project Schedule
    dateFormat YYYY-MM-DD
    section Phase 1
    Task 1 :a1, 2024-01-01, 30d
    Task 2 :after a1, 20d
```

## Date Formats

### Input Format

```mermaid
gantt
    dateFormat YYYY-MM-DD
```

Common formats:
| Format | Example |
|--------|---------|
| `YYYY-MM-DD` | 2024-01-15 |
| `DD-MM-YYYY` | 15-01-2024 |
| `YYYY-MM-DDTHH:mm` | 2024-01-15T14:30 |

### Display Format

```mermaid
gantt
    dateFormat YYYY-MM-DD
    axisFormat %b %d    %% Jan 15
```

Axis format codes:
| Code | Output |
|------|--------|
| `%Y` | 2024 |
| `%y` | 24 |
| `%m` | 01 |
| `%b` | Jan |
| `%B` | January |
| `%d` | 15 |
| `%a` | Mon |
| `%A` | Monday |
| `%H` | 14 |
| `%M` | 30 |

## Sections

```mermaid
gantt
    title Project Plan
    section Planning
    Requirements :2024-01-01, 10d
    Design :2024-01-11, 15d

    section Development
    Backend :2024-01-26, 30d
    Frontend :2024-02-10, 25d

    section Testing
    QA :2024-03-01, 20d
```

## Task Definition

### Basic Task

```mermaid
gantt
    Task Name :2024-01-01, 10d
```

### Task with ID

```mermaid
gantt
    Task Name :taskId, 2024-01-01, 10d
```

### Duration Options

```mermaid
gantt
    Days :a1, 2024-01-01, 10d
    Weeks :a2, after a1, 2w
    Hours :a3, after a2, 48h
    End Date :a4, 2024-02-01, 2024-02-15
```

## Dependencies

### After Dependency

```mermaid
gantt
    Task A :a, 2024-01-01, 10d
    Task B :b, after a, 10d
    Task C :c, after a b, 5d    %% After both A and B
```

### Parallel Tasks

```mermaid
gantt
    Parent :p, 2024-01-01, 5d
    Child A :after p, 10d
    Child B :after p, 10d    %% Runs parallel to Child A
```

## Task States

### Status Markers

```mermaid
gantt
    Completed task :done, des1, 2024-01-01, 10d
    Active task :active, des2, after des1, 10d
    Critical task :crit, des3, after des2, 10d
    Future task :des4, after des3, 10d
```

### Combined States

```mermaid
gantt
    Critical and active :crit, active, 2024-01-01, 10d
    Critical and done :crit, done, 2024-01-11, 10d
```

## Milestones

```mermaid
gantt
    section Project
    Development :a1, 2024-01-01, 30d
    Release v1.0 :milestone, m1, after a1, 0d
    Post-release :after m1, 10d
```

## Excluding Days

### Weekends

```mermaid
gantt
    excludes weekends
    Task :2024-01-01, 10d    %% Skips Sat/Sun
```

### Specific Days

```mermaid
gantt
    excludes 2024-01-15, 2024-01-16
    Task :2024-01-10, 10d
```

### Multiple Exclusions

```mermaid
gantt
    excludes weekends, 2024-12-25, 2024-12-26
```

## Tick Interval

Control axis tick spacing:

```mermaid
gantt
    tickInterval 1week
    %% Options: 1day, 1week, 1month
```

## Today Marker

```mermaid
gantt
    todayMarker on    %% Shows current date line
    %% todayMarker off to hide
```

## Complete Example

```mermaid
gantt
    title Product Launch Plan
    dateFormat YYYY-MM-DD
    axisFormat %b %d
    excludes weekends
    todayMarker on

    section Planning
    Market Research :done, research, 2024-01-02, 2w
    Requirements :done, req, after research, 1w
    Technical Design :done, design, after req, 2w
    Planning Complete :milestone, m1, after design, 0d

    section Development
    Backend API :crit, active, backend, after design, 4w
    Database Setup :db, after design, 2w
    Frontend UI :frontend, after db, 3w
    Integration :crit, integration, after backend, 2w

    section Testing
    Unit Tests :unit, after backend, 2w
    Integration Tests :int, after integration, 2w
    UAT :crit, uat, after int, 2w
    Testing Complete :milestone, m2, after uat, 0d

    section Launch
    Documentation :docs, after integration, 2w
    Training :training, after docs, 1w
    Deployment :crit, deploy, after m2, 3d
    Go Live :milestone, m3, after deploy, 0d
    Support :after m3, 2w
```

## Common Patterns

### Sprint Planning

```mermaid
gantt
    title Sprint 1
    dateFormat YYYY-MM-DD
    axisFormat %a %d

    section Sprint 1 (Jan 8-19)
    Sprint Planning :milestone, 2024-01-08, 0d
    User Story 1 :us1, 2024-01-08, 3d
    User Story 2 :us2, 2024-01-08, 5d
    User Story 3 :us3, after us1, 4d
    Code Review :after us2 us3, 2d
    Sprint Review :milestone, 2024-01-19, 0d
```

### Release Timeline

```mermaid
gantt
    title Release Schedule 2024
    dateFormat YYYY-MM-DD
    axisFormat %b

    section Q1
    v1.0 Development :2024-01-01, 2024-02-28
    v1.0 Release :milestone, 2024-03-01, 0d

    section Q2
    v1.1 Development :2024-03-01, 2024-05-15
    v1.1 Release :milestone, 2024-05-15, 0d

    section Q3
    v2.0 Development :crit, 2024-05-15, 2024-08-31
    v2.0 Release :milestone, 2024-09-01, 0d
```

### Waterfall Project

```mermaid
gantt
    title Waterfall Project
    dateFormat YYYY-MM-DD

    section Analysis
    Requirements :req, 2024-01-01, 30d
    Sign-off :milestone, after req, 0d

    section Design
    System Design :des, after req, 20d
    Detail Design :after des, 15d
    Design Review :milestone, 2024-03-05, 0d

    section Implementation
    Development :crit, dev, 2024-03-06, 60d
    Code Complete :milestone, after dev, 0d

    section Testing
    System Test :test, after dev, 20d
    UAT :uat, after test, 15d
    Go Live :milestone, after uat, 0d
```

### Parallel Workstreams

```mermaid
gantt
    title Parallel Development
    dateFormat YYYY-MM-DD

    section Backend
    API Design :api_design, 2024-01-01, 10d
    API Development :api_dev, after api_design, 30d
    API Testing :api_test, after api_dev, 10d

    section Frontend
    UI Design :ui_design, 2024-01-01, 15d
    UI Development :ui_dev, after ui_design, 25d
    UI Testing :ui_test, after ui_dev, 10d

    section Integration
    Integration :crit, after api_dev ui_dev, 10d
    E2E Testing :crit, after integration, 10d
    Release :milestone, crit, after E2E Testing, 0d
```

## Tips

1. **Use IDs**: Assign IDs to tasks for dependencies
2. **Exclude Weekends**: Add `excludes weekends` for realistic timelines
3. **Milestones**: Use 0d duration for milestone markers
4. **Critical Path**: Mark `crit` on blocking tasks
5. **Active Tasks**: Use `active` to highlight current work
6. **Sections**: Group related tasks for clarity
7. **Axis Format**: Customize date display for readability
