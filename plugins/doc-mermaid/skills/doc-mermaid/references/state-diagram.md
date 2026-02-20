# State Diagram Reference

State diagrams model state machines with states, transitions, and events.

## Basic Syntax

```mermaid
stateDiagram-v2
    [*] --> Active
    Active --> [*]
```

Use `stateDiagram-v2` for the modern syntax (recommended).

## States

### Simple States

```mermaid
stateDiagram-v2
    state1
    state2
    state3
```

### States with Descriptions

```mermaid
stateDiagram-v2
    state "Long State Name" as s1
    state "Another State" as s2
    s1 --> s2
```

### Initial and Final States

```mermaid
stateDiagram-v2
    [*] --> First     %% Initial state
    First --> Second
    Second --> [*]    %% Final state
```

## Transitions

### Basic Transitions

```mermaid
stateDiagram-v2
    Idle --> Active
    Active --> Idle
```

### Transitions with Labels

```mermaid
stateDiagram-v2
    Idle --> Active : start
    Active --> Idle : stop
    Active --> Error : fail
    Error --> Idle : reset
```

### Self-Transitions

```mermaid
stateDiagram-v2
    Active --> Active : process
```

## Composite States

### Nested States

```mermaid
stateDiagram-v2
    [*] --> Active

    state Active {
        [*] --> Running
        Running --> Paused : pause
        Paused --> Running : resume
        Running --> [*]
    }

    Active --> [*]
```

### Deeply Nested

```mermaid
stateDiagram-v2
    state Outer {
        state Inner {
            state DeepInner {
                s1 --> s2
            }
        }
    }
```

## Fork and Join

### Parallel States

```mermaid
stateDiagram-v2
    state fork_state <<fork>>
    [*] --> fork_state
    fork_state --> State1
    fork_state --> State2

    state join_state <<join>>
    State1 --> join_state
    State2 --> join_state
    join_state --> [*]
```

## Choice (Conditional)

```mermaid
stateDiagram-v2
    state check <<choice>>
    [*] --> check
    check --> Valid : if valid
    check --> Invalid : if invalid
```

### Complex Choice

```mermaid
stateDiagram-v2
    state decision <<choice>>
    Processing --> decision
    decision --> Success : result == ok
    decision --> Retry : result == retry
    decision --> Failure : result == error
```

## Notes

### Note Positioning

```mermaid
stateDiagram-v2
    State1 : Description here
    note right of State1
        This is a note
        on the right
    end note

    note left of State1 : Short note
```

### Notes on Transitions

```mermaid
stateDiagram-v2
    State1 --> State2
    note right of State1
        Transition happens
        when condition met
    end note
```

## Concurrency

### Concurrent Regions

```mermaid
stateDiagram-v2
    [*] --> Active

    state Active {
        [*] --> A1
        A1 --> A2

        --

        [*] --> B1
        B1 --> B2
    }
```

## Direction

```mermaid
stateDiagram-v2
    direction LR    %% Left to Right
    [*] --> A
    A --> B
    B --> [*]
```

Options: `LR`, `RL`, `TB`, `BT`

## Styling

### State Styling

```mermaid
stateDiagram-v2
    classDef important fill:#f96,stroke:#333
    classDef completed fill:#9f9,stroke:#333

    state1:::important
    state2:::completed
```

## Complete Example

```mermaid
stateDiagram-v2
    [*] --> Idle

    Idle --> Connecting : connect()
    Connecting --> Connected : success
    Connecting --> Error : timeout

    state Connected {
        [*] --> Ready
        Ready --> Processing : request
        Processing --> Ready : done

        state Processing {
            [*] --> Fetching
            Fetching --> Parsing
            Parsing --> [*]
        }
    }

    Connected --> Disconnecting : disconnect()
    Error --> Idle : retry
    Disconnecting --> Idle : done

    note right of Error
        Auto-retry after
        30 seconds
    end note
```

## Common Patterns

### Order Status

```mermaid
stateDiagram-v2
    [*] --> Pending

    Pending --> Confirmed : confirm
    Pending --> Cancelled : cancel

    Confirmed --> Processing : process
    Processing --> Shipped : ship
    Shipped --> Delivered : deliver

    Confirmed --> Cancelled : cancel
    Processing --> Cancelled : cancel

    Delivered --> [*]
    Cancelled --> [*]
```

### Authentication State

```mermaid
stateDiagram-v2
    [*] --> LoggedOut

    LoggedOut --> Authenticating : login
    Authenticating --> LoggedIn : success
    Authenticating --> LoggedOut : failure

    LoggedIn --> LoggedOut : logout
    LoggedIn --> SessionExpired : timeout
    SessionExpired --> LoggedOut : acknowledge

    state LoggedIn {
        [*] --> Active
        Active --> Idle : inactivity
        Idle --> Active : activity
    }
```

### Document Workflow

```mermaid
stateDiagram-v2
    [*] --> Draft

    Draft --> Review : submit
    Review --> Draft : reject
    Review --> Approved : approve

    state Review {
        [*] --> TechnicalReview
        TechnicalReview --> LegalReview
        LegalReview --> [*]
    }

    Approved --> Published : publish
    Published --> Archived : archive
    Archived --> [*]

    note right of Review
        Both reviews must
        pass before approval
    end note
```

### Connection State Machine

```mermaid
stateDiagram-v2
    [*] --> Disconnected

    Disconnected --> Connecting : connect

    state Connecting {
        [*] --> ResolvingDNS
        ResolvingDNS --> EstablishingTCP
        EstablishingTCP --> Handshaking
        Handshaking --> [*]
    }

    Connecting --> Connected : success
    Connecting --> Disconnected : failure

    Connected --> Disconnecting : disconnect
    Connected --> Reconnecting : error

    Reconnecting --> Connected : success
    Reconnecting --> Disconnected : max_retries

    Disconnecting --> Disconnected : done
```

### Traffic Light

```mermaid
stateDiagram-v2
    [*] --> Red
    Red --> Green : timer(30s)
    Green --> Yellow : timer(25s)
    Yellow --> Red : timer(5s)

    note right of Red : Stop
    note right of Yellow : Caution
    note right of Green : Go
```
