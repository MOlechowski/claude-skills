# Mermaid Examples

Real-world diagram patterns for common use cases.

## API Documentation

### REST API Flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant G as API Gateway
    participant A as Auth Service
    participant S as Business Service
    participant D as Database
    participant Ca as Cache

    C->>G: POST /api/resource
    G->>A: Validate JWT
    alt Token Valid
        A-->>G: OK
        G->>Ca: Check cache
        alt Cache Hit
            Ca-->>G: Cached data
            G-->>C: 200 OK (cached)
        else Cache Miss
            G->>S: Forward request
            S->>D: Query data
            D-->>S: Result
            S->>Ca: Update cache
            S-->>G: Response
            G-->>C: 200 OK
        end
    else Token Invalid
        A-->>G: 401 Unauthorized
        G-->>C: 401 Unauthorized
    end
```

### OAuth 2.0 Authorization Code Flow

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client App
    participant A as Auth Server
    participant R as Resource Server

    U->>C: Click Login
    C->>A: Authorization Request
    Note over A: User authenticates
    A->>U: Login Form
    U->>A: Credentials
    A->>C: Authorization Code
    C->>A: Exchange Code for Token
    A->>C: Access Token + Refresh Token
    C->>R: API Request + Access Token
    R->>C: Protected Resource
    C->>U: Display Data
```

## System Architecture

### Microservices Architecture

```mermaid
C4Container
    title E-Commerce Microservices

    Person(customer, "Customer")
    Person(admin, "Admin")

    System_Boundary(platform, "E-Commerce Platform") {
        Container(web, "Web App", "React", "Customer portal")
        Container(admin_ui, "Admin UI", "React", "Back office")
        Container(gateway, "API Gateway", "Kong", "Routing, auth, rate limiting")
        Container(users, "User Service", "Node.js", "User management")
        Container(products, "Product Service", "Go", "Product catalog")
        Container(orders, "Order Service", "Java", "Order processing")
        Container(payments, "Payment Service", "Python", "Payment processing")
        Container(notifications, "Notification Service", "Node.js", "Email, SMS, Push")
        ContainerDb(users_db, "Users DB", "PostgreSQL")
        ContainerDb(products_db, "Products DB", "MongoDB")
        ContainerDb(orders_db, "Orders DB", "PostgreSQL")
        ContainerQueue(events, "Event Bus", "Kafka")
    }

    System_Ext(stripe, "Stripe", "Payment processor")
    System_Ext(sendgrid, "SendGrid", "Email delivery")

    Rel(customer, web, "Uses")
    Rel(admin, admin_ui, "Uses")
    Rel(web, gateway, "API calls")
    Rel(admin_ui, gateway, "API calls")
    Rel(gateway, users, "Routes")
    Rel(gateway, products, "Routes")
    Rel(gateway, orders, "Routes")
    Rel(users, users_db, "Reads/Writes")
    Rel(products, products_db, "Reads/Writes")
    Rel(orders, orders_db, "Reads/Writes")
    Rel(orders, events, "Publishes")
    Rel(payments, events, "Subscribes")
    Rel(notifications, events, "Subscribes")
    Rel(payments, stripe, "Charges")
    Rel(notifications, sendgrid, "Sends")
```

### Event-Driven Architecture

```mermaid
flowchart LR
    subgraph Producers
        A[Order Service]
        B[User Service]
        C[Inventory Service]
    end

    subgraph Event Bus
        E[(Kafka)]
    end

    subgraph Consumers
        F[Notification Service]
        G[Analytics Service]
        H[Search Service]
        I[Audit Service]
    end

    A -->|OrderCreated| E
    A -->|OrderShipped| E
    B -->|UserRegistered| E
    B -->|UserUpdated| E
    C -->|StockUpdated| E

    E -->|OrderCreated| F
    E -->|UserRegistered| F
    E -->|*| G
    E -->|*| I
    E -->|ProductUpdated| H
```

## Database Design

### E-Commerce Schema

```mermaid
erDiagram
    customers ||--o{ orders : places
    customers ||--o{ addresses : has
    customers ||--o{ cart_items : has

    orders ||--|{ order_items : contains
    orders ||--o| payments : has
    orders ||--|| addresses : ships_to

    products ||--o{ order_items : ordered_in
    products ||--o{ cart_items : added_to
    products }o--|| categories : belongs_to
    products ||--o{ product_images : has
    products ||--o{ reviews : has

    customers {
        uuid id PK
        string email UK
        string password_hash
        string first_name
        string last_name
        timestamp created_at
    }

    addresses {
        uuid id PK
        uuid customer_id FK
        string street
        string city
        string state
        string postal_code
        string country
        boolean is_default
    }

    products {
        uuid id PK
        uuid category_id FK
        string sku UK
        string name
        text description
        decimal price
        integer stock
        boolean active
    }

    orders {
        uuid id PK
        uuid customer_id FK
        uuid shipping_address_id FK
        string status
        decimal subtotal
        decimal tax
        decimal shipping
        decimal total
        timestamp created_at
    }

    order_items {
        uuid id PK
        uuid order_id FK
        uuid product_id FK
        integer quantity
        decimal unit_price
        decimal total
    }

    payments {
        uuid id PK
        uuid order_id FK
        string provider
        string transaction_id
        decimal amount
        string status
        timestamp created_at
    }
```

## CI/CD Pipelines

### GitHub Actions Workflow

```mermaid
flowchart TD
    subgraph Trigger
        A[Push to main]
        B[Pull Request]
    end

    subgraph Build
        C[Checkout]
        D[Install Dependencies]
        E[Lint]
        F[Unit Tests]
        G[Build]
    end

    subgraph Test
        H[Integration Tests]
        I[E2E Tests]
        J[Security Scan]
    end

    subgraph Deploy
        K{Branch?}
        L[Deploy Staging]
        M[Smoke Tests]
        N[Deploy Production]
        O[Notify Team]
    end

    A --> C
    B --> C
    C --> D --> E --> F --> G
    G --> H & I & J

    H & I & J --> K
    K -->|main| L
    K -->|PR| O
    L --> M --> N --> O
```

### Multi-Environment Deployment

```mermaid
flowchart LR
    subgraph Development
        A[Dev Branch] --> B[Build]
        B --> C[Unit Tests]
        C --> D[Deploy Dev]
    end

    subgraph Staging
        D --> E{Merge to main?}
        E -->|Yes| F[Build Staging]
        F --> G[Integration Tests]
        G --> H[Deploy Staging]
        H --> I[QA Sign-off]
    end

    subgraph Production
        I -->|Approved| J[Deploy Blue]
        J --> K[Health Check]
        K -->|Pass| L[Switch Traffic]
        L --> M[Monitor]
        K -->|Fail| N[Rollback]
    end
```

## State Machines

### Order Status

```mermaid
stateDiagram-v2
    [*] --> Draft

    Draft --> Pending : submit
    Pending --> Confirmed : payment_success
    Pending --> Cancelled : payment_failed
    Pending --> Cancelled : user_cancel

    Confirmed --> Processing : start_fulfillment
    Confirmed --> Cancelled : admin_cancel

    Processing --> Shipped : ship
    Processing --> Cancelled : admin_cancel

    Shipped --> Delivered : deliver
    Shipped --> Returned : return_requested

    Delivered --> Completed : auto_complete
    Delivered --> Returned : return_requested

    Returned --> Refunded : process_return

    Completed --> [*]
    Cancelled --> [*]
    Refunded --> [*]
```

### Authentication Flow

```mermaid
stateDiagram-v2
    [*] --> Unauthenticated

    Unauthenticated --> Authenticating : login

    state Authenticating {
        [*] --> ValidatingCredentials
        ValidatingCredentials --> CheckingMFA : credentials_valid
        ValidatingCredentials --> [*] : credentials_invalid

        CheckingMFA --> WaitingForMFA : mfa_required
        CheckingMFA --> [*] : mfa_not_required
        WaitingForMFA --> [*] : mfa_success
        WaitingForMFA --> [*] : mfa_failed
    }

    Authenticating --> Authenticated : success
    Authenticating --> Unauthenticated : failure

    Authenticated --> SessionActive

    state SessionActive {
        [*] --> Active
        Active --> Idle : inactivity
        Idle --> Active : activity
        Idle --> [*] : timeout
    }

    SessionActive --> Unauthenticated : logout
    SessionActive --> Unauthenticated : session_expired
```

## Process Flows

### User Registration

```mermaid
flowchart TD
    A[Start] --> B[Enter Email]
    B --> C{Email Valid?}
    C -->|No| B
    C -->|Yes| D{Email Exists?}
    D -->|Yes| E[Show Login Option]
    D -->|No| F[Enter Password]
    F --> G{Password Strong?}
    G -->|No| F
    G -->|Yes| H[Enter Name]
    H --> I[Accept Terms]
    I --> J[Create Account]
    J --> K[Send Verification Email]
    K --> L{Email Verified?}
    L -->|No| M[Resend?]
    M -->|Yes| K
    L -->|Yes| N[Welcome Screen]
    N --> O[End]
```

### Checkout Process

```mermaid
flowchart TD
    subgraph Cart
        A[View Cart] --> B{Items Valid?}
        B -->|No| C[Update Cart]
        C --> A
        B -->|Yes| D[Proceed to Checkout]
    end

    subgraph Shipping
        D --> E[Enter Address]
        E --> F{Address Valid?}
        F -->|No| E
        F -->|Yes| G[Select Shipping Method]
    end

    subgraph Payment
        G --> H[Enter Payment]
        H --> I{Payment Valid?}
        I -->|No| H
        I -->|Yes| J[Review Order]
    end

    subgraph Confirmation
        J --> K[Place Order]
        K --> L{Payment Success?}
        L -->|No| M[Show Error]
        M --> H
        L -->|Yes| N[Confirmation Page]
        N --> O[Send Confirmation Email]
    end
```

## Project Management

### Sprint Planning

```mermaid
gantt
    title Sprint 12 - User Dashboard
    dateFormat YYYY-MM-DD
    excludes weekends

    section Planning
    Sprint Planning :done, plan, 2024-01-15, 1d
    Story Breakdown :done, 2024-01-15, 1d

    section Development
    Dashboard Layout :done, dash1, 2024-01-16, 2d
    Widget Components :active, dash2, after dash1, 3d
    Data Integration :dash3, after dash2, 2d
    User Preferences :dash4, after dash3, 2d

    section Testing
    Unit Tests :test1, after dash2, 2d
    Integration Tests :test2, after dash3, 2d
    E2E Tests :test3, after dash4, 1d

    section Review
    Code Review :review, after test3, 1d
    Sprint Review :milestone, after review, 0d
```

### Feature Roadmap

```mermaid
timeline
    title 2024 Product Roadmap
    section Q1 - Foundation
        January : Authentication system
                : User management
        February : Core API
                 : Admin dashboard
        March : Mobile responsive
              : Performance optimization
    section Q2 - Growth
        April : Team collaboration
              : Notifications
        May : Integrations
            : API documentation
        June : Analytics dashboard
             : Reporting
    section Q3 - Scale
        July : Enterprise SSO
             : Role-based access
        August : Audit logging
               : Compliance features
        September : Multi-region
                  : High availability
    section Q4 - Innovation
        October : AI features
                : Smart suggestions
        November : Mobile apps
                 : Offline support
        December : 2025 planning
                 : Customer feedback
```

## Class Diagrams

### Domain Model

```mermaid
classDiagram
    class User {
        +UUID id
        +String email
        +String name
        -String passwordHash
        +DateTime createdAt
        +register()
        +authenticate()
        +updateProfile()
    }

    class Organization {
        +UUID id
        +String name
        +Plan plan
        +addMember()
        +removeMember()
    }

    class Membership {
        +Role role
        +DateTime joinedAt
    }

    class Project {
        +UUID id
        +String name
        +Status status
        +create()
        +archive()
    }

    class Task {
        +UUID id
        +String title
        +Priority priority
        +Status status
        +assign()
        +complete()
    }

    User "1" --> "*" Membership
    Organization "1" --> "*" Membership
    Organization "1" --> "*" Project
    Project "1" --> "*" Task
    User "1" --> "*" Task : assigned
```

### Repository Pattern

```mermaid
classDiagram
    class IRepository~T~ {
        <<interface>>
        +findById(id) T
        +findAll() List~T~
        +save(entity) T
        +delete(id) void
    }

    class IUserRepository {
        <<interface>>
        +findByEmail(email) User
        +findByOrganization(orgId) List~User~
    }

    class UserRepository {
        -DataSource db
        +findById(id) User
        +findAll() List~User~
        +save(user) User
        +delete(id) void
        +findByEmail(email) User
        +findByOrganization(orgId) List~User~
    }

    class UserService {
        -IUserRepository repo
        +getUser(id) UserDTO
        +createUser(data) UserDTO
        +updateUser(id, data) UserDTO
    }

    IRepository <|-- IUserRepository
    IUserRepository <|.. UserRepository
    UserService --> IUserRepository
```
