# ER Diagram Reference

Entity-Relationship diagrams model database schemas and data relationships.

## Basic Syntax

```mermaid
erDiagram
    CUSTOMER ||--o{ ORDER : places
    ORDER ||--|{ LINE-ITEM : contains
```

## Entities

### Simple Entity

```mermaid
erDiagram
    CUSTOMER
    ORDER
    PRODUCT
```

### Entity with Attributes

```mermaid
erDiagram
    CUSTOMER {
        int id
        string name
        string email
    }
```

## Attribute Types

### Data Types

```mermaid
erDiagram
    EXAMPLE {
        int id
        string name
        text description
        float price
        bool active
        date created_at
        datetime updated_at
        timestamp deleted_at
    }
```

### Keys and Constraints

| Suffix | Meaning |
|--------|---------|
| `PK` | Primary Key |
| `FK` | Foreign Key |
| `UK` | Unique Key |

```mermaid
erDiagram
    CUSTOMER {
        int id PK
        string email UK
        string name
    }
    ORDER {
        int id PK
        int customer_id FK
        date order_date
    }
```

### Comments

```mermaid
erDiagram
    CUSTOMER {
        int id PK "Auto-increment"
        string email UK "Must be valid email"
        string name "Display name"
    }
```

## Relationships

### Cardinality Notation

Left side (first entity):
| Symbol | Meaning |
|--------|---------|
| `\|\|` | Exactly one |
| `\|o` | Zero or one |
| `}o` | Zero or more |
| `}\|` | One or more |

Right side (second entity):
| Symbol | Meaning |
|--------|---------|
| `\|\|` | Exactly one |
| `o\|` | Zero or one |
| `o{` | Zero or more |
| `\|{` | One or more |

### Relationship Examples

```mermaid
erDiagram
    A ||--|| B : "one to one"
    C ||--o{ D : "one to zero-or-many"
    E ||--|{ F : "one to one-or-many"
    G }o--o{ H : "many to many"
    I |o--o| J : "zero-or-one to zero-or-one"
```

### Common Relationships

```mermaid
erDiagram
    %% One-to-Many
    CUSTOMER ||--o{ ORDER : "places"

    %% Many-to-Many (via junction table)
    ORDER ||--|{ ORDER_PRODUCT : "contains"
    PRODUCT ||--|{ ORDER_PRODUCT : "in"

    %% One-to-One
    USER ||--|| PROFILE : "has"

    %% Self-referencing
    EMPLOYEE ||--o{ EMPLOYEE : "manages"
```

### Identifying Relationships

Use `--` for identifying (solid line) and `..` for non-identifying (dashed line):

```mermaid
erDiagram
    PARENT ||--o{ CHILD : "identifying"
    CATEGORY }o..o{ PRODUCT : "non-identifying"
```

## Relationship Labels

Labels appear after the colon:

```mermaid
erDiagram
    CUSTOMER ||--o{ ORDER : places
    ORDER ||--|{ LINE_ITEM : contains
    PRODUCT ||--o{ LINE_ITEM : "is ordered in"
```

## Complete Example

```mermaid
erDiagram
    CUSTOMER {
        int id PK
        string email UK
        string name
        string phone
        timestamp created_at
    }

    ADDRESS {
        int id PK
        int customer_id FK
        string street
        string city
        string state
        string zip
        bool is_primary
    }

    ORDER {
        int id PK
        int customer_id FK
        int shipping_address_id FK
        string status
        decimal total
        timestamp order_date
    }

    ORDER_ITEM {
        int id PK
        int order_id FK
        int product_id FK
        int quantity
        decimal unit_price
    }

    PRODUCT {
        int id PK
        int category_id FK
        string sku UK
        string name
        text description
        decimal price
        int stock
    }

    CATEGORY {
        int id PK
        int parent_id FK
        string name
        string slug UK
    }

    CUSTOMER ||--o{ ADDRESS : "has"
    CUSTOMER ||--o{ ORDER : "places"
    ORDER ||--|| ADDRESS : "ships to"
    ORDER ||--|{ ORDER_ITEM : "contains"
    PRODUCT ||--o{ ORDER_ITEM : "in"
    CATEGORY ||--o{ PRODUCT : "categorizes"
    CATEGORY ||--o{ CATEGORY : "parent of"
```

## Common Patterns

### User Authentication

```mermaid
erDiagram
    USER {
        int id PK
        string email UK
        string password_hash
        bool is_active
        timestamp created_at
        timestamp last_login
    }

    SESSION {
        string id PK
        int user_id FK
        string ip_address
        timestamp expires_at
        timestamp created_at
    }

    ROLE {
        int id PK
        string name UK
        string description
    }

    USER_ROLE {
        int user_id FK
        int role_id FK
    }

    PERMISSION {
        int id PK
        string name UK
        string resource
        string action
    }

    ROLE_PERMISSION {
        int role_id FK
        int permission_id FK
    }

    USER ||--o{ SESSION : "has"
    USER ||--o{ USER_ROLE : "has"
    ROLE ||--o{ USER_ROLE : "assigned to"
    ROLE ||--o{ ROLE_PERMISSION : "grants"
    PERMISSION ||--o{ ROLE_PERMISSION : "granted by"
```

### Blog System

```mermaid
erDiagram
    AUTHOR {
        int id PK
        string username UK
        string email UK
        string bio
    }

    POST {
        int id PK
        int author_id FK
        string title
        string slug UK
        text content
        string status
        timestamp published_at
    }

    COMMENT {
        int id PK
        int post_id FK
        int author_id FK
        int parent_id FK
        text content
        timestamp created_at
    }

    TAG {
        int id PK
        string name UK
        string slug UK
    }

    POST_TAG {
        int post_id FK
        int tag_id FK
    }

    AUTHOR ||--o{ POST : "writes"
    AUTHOR ||--o{ COMMENT : "writes"
    POST ||--o{ COMMENT : "has"
    COMMENT ||--o{ COMMENT : "replies to"
    POST ||--o{ POST_TAG : "tagged"
    TAG ||--o{ POST_TAG : "tags"
```

### E-commerce Inventory

```mermaid
erDiagram
    WAREHOUSE {
        int id PK
        string name
        string location
    }

    PRODUCT {
        int id PK
        string sku UK
        string name
        decimal price
    }

    INVENTORY {
        int id PK
        int warehouse_id FK
        int product_id FK
        int quantity
        int reserved
        int available
    }

    SUPPLIER {
        int id PK
        string name
        string contact_email
    }

    PURCHASE_ORDER {
        int id PK
        int supplier_id FK
        int warehouse_id FK
        string status
        timestamp order_date
    }

    PO_ITEM {
        int id PK
        int po_id FK
        int product_id FK
        int quantity
        decimal unit_cost
    }

    WAREHOUSE ||--o{ INVENTORY : "stores"
    PRODUCT ||--o{ INVENTORY : "stocked in"
    SUPPLIER ||--o{ PURCHASE_ORDER : "receives"
    WAREHOUSE ||--o{ PURCHASE_ORDER : "to"
    PURCHASE_ORDER ||--|{ PO_ITEM : "contains"
    PRODUCT ||--o{ PO_ITEM : "ordered"
```

## Tips

1. **Naming**: Use singular nouns for entities (CUSTOMER, not CUSTOMERS)
2. **Primary Keys**: Always define PK for each entity
3. **Foreign Keys**: Mark FK to show relationships
4. **Junction Tables**: Use for many-to-many relationships
5. **Self-References**: Useful for hierarchical data (categories, org charts)
6. **Attribute Order**: Put PK first, then FK, then other attributes
