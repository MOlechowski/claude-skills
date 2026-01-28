# Mermaid Quick Reference

Compact syntax cheatsheet for all diagram types.

## Flowchart

```mermaid
graph TD           # TD=top-down, LR=left-right, BT=bottom-top, RL=right-left
    A[Rectangle]   # Node shapes
    B(Rounded)
    C{Diamond}
    D([Stadium])
    E[[Subroutine]]
    F[(Database)]
    G((Circle))
    H>Asymmetric]
    I{{Hexagon}}
    J[/Parallelogram/]
    K[\Parallelogram alt\]
    L[/Trapezoid\]
    M[\Trapezoid alt/]

    A --> B        # Links
    B --- C        # Open link
    C -.-> D       # Dotted
    D ==> E        # Thick
    E --text--> F  # With text
    F -->|text| G  # Alt text syntax

    subgraph title # Subgraphs
        H --> I
    end
```

## Sequence Diagram

```mermaid
sequenceDiagram
    participant A as Alice       # Participants
    actor B as Bob              # Actor (stick figure)

    A->>B: Solid line           # Messages
    A-->>B: Dotted line
    A-xB: Cross end
    A-)B: Open arrow

    activate B                  # Activation
    B->>A: Response
    deactivate B

    Note over A,B: Note text    # Notes
    Note right of A: Side note

    loop Every minute           # Loops
        A->>B: Ping
    end

    alt Condition               # Conditionals
        A->>B: Yes
    else Otherwise
        A->>B: No
    end

    opt Optional                # Optional
        A->>B: Maybe
    end

    par Parallel                # Parallel
        A->>B: Task 1
    and
        A->>B: Task 2
    end

    rect rgb(200, 200, 200)     # Highlighting
        A->>B: Highlighted
    end
```

## Class Diagram

```mermaid
classDiagram
    class Animal {              # Class with members
        +String name            # + public
        -int age               # - private
        #String type            # # protected
        ~List~String~ tags     # ~ package/internal
        +eat() void
        +sleep()* void         # * abstract
        +move()$ void          # $ static
    }

    Animal <|-- Dog            # Inheritance
    Dog *-- Tail               # Composition
    Dog o-- Toy                # Aggregation
    Dog --> Owner              # Association
    Dog ..> Food               # Dependency
    Dog ..|> Pet               # Realization

    class Dog {
        <<interface>>          # Annotations
    }

    Dog "1" --> "*" Toy        # Cardinality
```

## State Diagram

```mermaid
stateDiagram-v2
    [*] --> Idle               # Initial state
    Idle --> Active : start
    Active --> Idle : stop
    Active --> [*]             # Final state

    state Active {             # Composite state
        [*] --> Running
        Running --> Paused
        Paused --> Running
    }

    state fork_state <<fork>>  # Fork/join
    state join_state <<join>>

    state choice <<choice>>    # Choice
    choice --> Option1 : if condition
    choice --> Option2 : else

    note right of Active       # Notes
        This is a note
    end note
```

## ER Diagram

```mermaid
erDiagram
    CUSTOMER ||--o{ ORDER : places     # Relationships
    # ||  exactly one
    # o|  zero or one
    # }|  one or more
    # }o  zero or more

    CUSTOMER {                          # Attributes
        int id PK                       # Primary key
        string email UK                 # Unique key
        string name
    }
    ORDER {
        int id PK
        int customer_id FK              # Foreign key
        date created_at
    }
```

## C4 Diagram

```mermaid
C4Context                              # Levels: C4Context, C4Container, C4Component
    title System Context

    Person(user, "User", "Description")
    System(sys, "System", "Description")
    System_Ext(ext, "External", "Description")
    SystemDb(db, "Database", "Description")
    SystemQueue(queue, "Queue", "Description")

    System_Boundary(boundary, "Boundary Title") {
        System(inner, "Inner System")
    }

    Rel(user, sys, "Uses", "HTTPS")    # Relationships
    Rel_L(sys, db, "Reads")            # Direction: L/R/U/D
    BiRel(sys, ext, "Syncs")           # Bidirectional
```

## Gantt Chart

```mermaid
gantt
    title Project Plan
    dateFormat YYYY-MM-DD
    excludes weekends                   # Exclude days

    section Phase 1
    Task 1 :a1, 2024-01-01, 30d        # id, start, duration
    Task 2 :a2, after a1, 20d          # after dependency
    Milestone :milestone, m1, 2024-02-20, 0d

    section Phase 2
    Task 3 :crit, 2024-02-01, 15d      # Critical path
    Task 4 :active, a4, after a2, 10d  # Active task
    Task 5 :done, 2024-01-15, 5d       # Completed
```

## Timeline

```mermaid
timeline
    title Product History
    section 2020
        Q1 : Initial development
        Q4 : Alpha release
    section 2021
        Q2 : Beta release
           : Bug fixes
        Q4 : v1.0 launch
    section 2022
        Q2 : v2.0 with new features
```

## User Journey

```mermaid
journey
    title User Signup Journey
    section Discovery
        Find website: 5: User         # Task: score: actor
        Read features: 4: User
    section Signup
        Click signup: 5: User
        Fill form: 3: User            # Lower score = friction
        Verify email: 2: User, System
    section Onboarding
        Complete tutorial: 4: User
        Explore features: 5: User
```

## Pie Chart

```mermaid
pie title Browser Usage
    "Chrome" : 65
    "Firefox" : 15
    "Safari" : 12
    "Edge" : 8
```

## Quadrant Chart

```mermaid
quadrantChart
    title Priority Matrix
    x-axis Low Effort --> High Effort
    y-axis Low Impact --> High Impact
    quadrant-1 Quick Wins
    quadrant-2 Major Projects
    quadrant-3 Fill-ins
    quadrant-4 Thankless Tasks

    Task A: [0.2, 0.8]
    Task B: [0.7, 0.9]
    Task C: [0.3, 0.3]
```

## Git Graph

```mermaid
gitGraph
    commit id: "Initial"
    branch develop
    commit id: "Feature A"
    checkout main
    commit id: "Hotfix"
    merge develop
    commit id: "Release"
```

## Mindmap

```mermaid
mindmap
    root((Topic))
        Branch 1
            Leaf 1
            Leaf 2
        Branch 2
            Leaf 3
            ::icon(fa fa-book)
        Branch 3
```

## Styling

### Inline Styles

```mermaid
graph LR
    A[Styled]:::custom --> B
    classDef custom fill:#f96,stroke:#333,stroke-width:2px
    style A fill:#bbf,stroke:#f66
```

### Theme Configuration

```json
{
  "theme": "dark",
  "themeVariables": {
    "primaryColor": "#BB2528",
    "edgeLabelBackground": "#fff"
  }
}
```

## Special Characters

- Use `#quot;` for double quotes
- Use `#semi;` for semicolons
- Use `<br/>` for line breaks in labels
- Wrap text in quotes for spaces: `A["Text with spaces"]`
