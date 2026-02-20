# Flowchart Reference

Flowcharts visualize processes, workflows, and decision trees.

## Basic Syntax

```mermaid
graph TD
    A --> B
```

- `graph` or `flowchart` keyword starts the diagram
- Direction follows: `TD`, `TB`, `LR`, `RL`, `BT`

## Directions

| Direction | Meaning |
|-----------|---------|
| `TD` / `TB` | Top to bottom |
| `LR` | Left to right |
| `RL` | Right to left |
| `BT` | Bottom to top |

## Node Shapes

### Basic Shapes

```mermaid
graph LR
    A[Rectangle]
    B(Rounded rectangle)
    C([Stadium])
    D[[Subroutine]]
    E[(Database)]
    F((Circle))
```

### Decision and Special

```mermaid
graph LR
    A{Diamond / Decision}
    B{{Hexagon}}
    C>Asymmetric / Flag]
```

### Parallelograms and Trapezoids

```mermaid
graph LR
    A[/Parallelogram/]
    B[\Parallelogram alt\]
    C[/Trapezoid\]
    D[\Trapezoid alt/]
```

### Double Border

```mermaid
graph LR
    A[["Double rectangle"]]
    B(("Double circle"))
```

## Links / Edges

### Arrow Types

```mermaid
graph LR
    A --> B         %% Arrow
    B --- C         %% Open link
    C -.-> D        %% Dotted arrow
    D ==> E         %% Thick arrow
    E --o F         %% Circle end
    F --x G         %% Cross end
    G <--> H        %% Bidirectional
```

### Link Text

```mermaid
graph LR
    A -->|text| B
    A -- text --> B
    C -.text.-> D
    E ==text==> F
```

### Link Length

More dashes = longer link:

```mermaid
graph LR
    A --> B
    A ---> C
    A ----> D
```

### Chaining

```mermaid
graph LR
    A --> B --> C --> D
    E --> F & G --> H
```

## Subgraphs

### Basic Subgraph

```mermaid
graph TB
    subgraph one
        A --> B
    end
    subgraph two
        C --> D
    end
    A --> C
```

### Subgraph with Direction

```mermaid
graph LR
    subgraph sub1 [Title Here]
        direction TB
        A --> B
    end
```

### Nested Subgraphs

```mermaid
graph TB
    subgraph outer
        subgraph inner
            A --> B
        end
        C --> inner
    end
```

## Styling

### Style a Node

```mermaid
graph LR
    A[Styled]
    style A fill:#f9f,stroke:#333,stroke-width:4px
```

### Class Definitions

```mermaid
graph LR
    A:::someclass --> B
    classDef someclass fill:#f96,stroke:#333
    classDef default fill:#fff,stroke:#333
```

### Multiple Classes

```mermaid
graph LR
    A:::first:::second
    classDef first stroke:#f00
    classDef second fill:#0ff
```

### Style Properties

| Property | Description | Example |
|----------|-------------|---------|
| `fill` | Background color | `fill:#f96` |
| `stroke` | Border color | `stroke:#333` |
| `stroke-width` | Border width | `stroke-width:2px` |
| `stroke-dasharray` | Dashed border | `stroke-dasharray:5,5` |
| `color` | Text color | `color:#fff` |

### Link Styling

```mermaid
graph LR
    A --> B --> C
    linkStyle 0 stroke:#ff0,stroke-width:4px
    linkStyle 1 stroke:green
```

### Default Link Style

```mermaid
graph LR
    A --> B --> C
    linkStyle default stroke:#0f0
```

## Comments

```mermaid
graph LR
    %% This is a comment
    A --> B
```

## Special Characters

### Quotes for Spaces

```mermaid
graph LR
    A["Text with spaces"]
    B["Quotes: #quot;text#quot;"]
```

### Line Breaks

```mermaid
graph LR
    A["Line 1<br/>Line 2"]
```

### Entity Codes

| Code | Character |
|------|-----------|
| `#quot;` | " |
| `#semi;` | ; |
| `#amp;` | & |
| `#lt;` | < |
| `#gt;` | > |

## Interactions (Click Events)

```mermaid
graph LR
    A --> B
    click A "https://example.com"
    click B callback "Tooltip text"
```

## Complete Example

```mermaid
flowchart TD
    subgraph Input
        A[User Request] --> B{Valid?}
    end

    subgraph Processing
        B -->|Yes| C[Process Data]
        B -->|No| D[Show Error]
        C --> E{Success?}
        E -->|Yes| F[Save Result]
        E -->|No| G[Log Error]
        G --> D
    end

    subgraph Output
        F --> H([Return Response])
        D --> I([Return Error])
    end

    style A fill:#9f9
    style D fill:#f99
    style H fill:#99f
    style I fill:#f99
```

## Common Patterns

### Decision Tree

```mermaid
graph TD
    A{Start} --> B{Condition 1?}
    B -->|Yes| C{Condition 2?}
    B -->|No| D[Action A]
    C -->|Yes| E[Action B]
    C -->|No| F[Action C]
```

### Pipeline

```mermaid
graph LR
    A[Input] --> B[Step 1] --> C[Step 2] --> D[Step 3] --> E[Output]
```

### Branching and Merging

```mermaid
graph TD
    A[Start] --> B{Branch?}
    B -->|Option 1| C[Path 1]
    B -->|Option 2| D[Path 2]
    C --> E[Merge]
    D --> E
    E --> F[End]
```
