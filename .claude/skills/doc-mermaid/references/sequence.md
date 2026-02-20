# Sequence Diagram Reference

Sequence diagrams show interactions between participants over time.

## Basic Syntax

```mermaid
sequenceDiagram
    Alice->>Bob: Hello
    Bob-->>Alice: Hi
```

## Participants

### Defining Participants

```mermaid
sequenceDiagram
    participant A as Alice
    participant B as Bob
    A->>B: Message
```

### Actors

```mermaid
sequenceDiagram
    actor User
    participant System
    User->>System: Request
```

### Participant Order

Participants appear in definition order:

```mermaid
sequenceDiagram
    participant C as Third
    participant A as First
    participant B as Second
```

### Create and Destroy

```mermaid
sequenceDiagram
    Alice->>Bob: Hello
    create participant Carl
    Alice->>Carl: Hi
    destroy Carl
    Alice-x Carl: End
```

## Messages

### Arrow Types

| Type | Description |
|------|-------------|
| `->` | Solid line without arrow |
| `-->` | Dotted line without arrow |
| `->>` | Solid line with arrowhead |
| `-->>` | Dotted line with arrowhead |
| `-x` | Solid line with cross at end |
| `--x` | Dotted line with cross at end |
| `-)` | Solid line with open arrow |
| `--)` | Dotted line with open arrow |

### Message Examples

```mermaid
sequenceDiagram
    A->>B: Solid with arrow
    A-->>B: Dotted with arrow
    A-xB: Solid with cross
    A--xB: Dotted with cross
    A-)B: Solid open arrow
    A--)B: Dotted open arrow
```

## Activation

### Explicit Activation

```mermaid
sequenceDiagram
    Alice->>Bob: Request
    activate Bob
    Bob->>Alice: Response
    deactivate Bob
```

### Shorthand Activation

```mermaid
sequenceDiagram
    Alice->>+Bob: Request
    Bob->>-Alice: Response
```

### Nested Activation

```mermaid
sequenceDiagram
    Alice->>+Bob: First
    Alice->>+Bob: Second
    Bob-->>-Alice: Response 2
    Bob-->>-Alice: Response 1
```

## Notes

### Note Positions

```mermaid
sequenceDiagram
    participant A
    participant B
    Note left of A: Left note
    Note right of B: Right note
    Note over A: Over one
    Note over A,B: Over both
```

### Multiline Notes

```mermaid
sequenceDiagram
    Note over A,B: Line 1<br/>Line 2<br/>Line 3
```

## Control Flow

### Loops

```mermaid
sequenceDiagram
    loop Every minute
        A->>B: Heartbeat
        B-->>A: Ack
    end
```

### Alt (Conditionals)

```mermaid
sequenceDiagram
    A->>B: Request
    alt Success
        B->>A: OK
    else Error
        B->>A: Error
    else Timeout
        B->>A: Retry
    end
```

### Opt (Optional)

```mermaid
sequenceDiagram
    A->>B: Request
    opt Has cache
        B->>B: Check cache
    end
    B-->>A: Response
```

### Par (Parallel)

```mermaid
sequenceDiagram
    par Alice to Bob
        A->>B: Message 1
    and Alice to Carl
        A->>C: Message 2
    and Bob to Carl
        B->>C: Message 3
    end
```

### Critical (Must Complete)

```mermaid
sequenceDiagram
    critical Establish connection
        A->>B: Connect
    option Timeout
        A->>A: Retry
    option Error
        A->>A: Log
    end
```

### Break (Exit Loop)

```mermaid
sequenceDiagram
    loop Retry
        A->>B: Request
        break Response received
            B-->>A: OK
        end
    end
```

## Highlighting

### Rect (Background)

```mermaid
sequenceDiagram
    rect rgb(200, 220, 255)
        A->>B: Highlighted section
        B-->>A: Response
    end
```

### RGB and RGBA

```mermaid
sequenceDiagram
    rect rgb(255, 200, 200)
        Note over A,B: Red background
    end
    rect rgba(0, 255, 0, 0.3)
        Note over A,B: Transparent green
    end
```

## Sequence Numbers

```mermaid
sequenceDiagram
    autonumber
    A->>B: First
    B->>C: Second
    C-->>A: Third
```

## Box (Grouping Participants)

```mermaid
sequenceDiagram
    box Blue Team
        participant A
        participant B
    end
    box Red Team
        participant C
        participant D
    end
    A->>C: Cross-team message
```

### Box with Color

```mermaid
sequenceDiagram
    box rgb(200, 255, 200) Green Box
        participant A
        participant B
    end
```

## Links and Anchors

```mermaid
sequenceDiagram
    participant A
    participant B
    link A: Dashboard @ https://dashboard.example.com
    link B: API Docs @ https://api.example.com
```

## Complete Example

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant API
    participant Auth
    participant DB

    User->>+API: POST /login
    API->>+Auth: Validate credentials
    Auth->>+DB: Query user

    alt User found
        DB-->>-Auth: User data
        Auth->>Auth: Verify password
        alt Password valid
            Auth-->>API: Token
            API-->>User: 200 OK + Token
        else Invalid password
            Auth-->>API: Error
            API-->>User: 401 Unauthorized
        end
    else User not found
        DB-->>Auth: null
        Auth-->>-API: Error
        API-->>-User: 401 Unauthorized
    end
```

## Common Patterns

### Request-Response

```mermaid
sequenceDiagram
    Client->>+Server: Request
    Server-->>-Client: Response
```

### Async with Callback

```mermaid
sequenceDiagram
    Client->>Server: Start job
    activate Server
    Note right of Server: Processing...
    Server--)Client: Job complete (callback)
    deactivate Server
```

### Error Handling

```mermaid
sequenceDiagram
    Client->>API: Request
    API->>Service: Process
    alt Success
        Service-->>API: Result
        API-->>Client: 200 OK
    else Service Error
        Service-->>API: Error
        API-->>Client: 500 Error
    else Validation Error
        API-->>Client: 400 Bad Request
    end
```

### Retry Pattern

```mermaid
sequenceDiagram
    loop Max 3 retries
        Client->>API: Request
        alt Success
            API-->>Client: Response
            break
        else Failure
            Note over Client: Wait, retry
        end
    end
```
