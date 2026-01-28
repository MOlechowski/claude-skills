# Class Diagram Reference

Class diagrams show object-oriented structures with classes, interfaces, and relationships.

## Basic Syntax

```mermaid
classDiagram
    class Animal
    Animal : +String name
    Animal : +eat()
```

## Class Definition

### Inline Attributes

```mermaid
classDiagram
    class Animal {
        +String name
        +int age
        +eat()
        +sleep()
    }
```

### Colon Syntax

```mermaid
classDiagram
    class Animal
    Animal : +String name
    Animal : +int age
    Animal : +eat() void
    Animal : +sleep() void
```

## Visibility Modifiers

| Symbol | Meaning |
|--------|---------|
| `+` | Public |
| `-` | Private |
| `#` | Protected |
| `~` | Package/Internal |

```mermaid
classDiagram
    class Example {
        +String publicField
        -String privateField
        #String protectedField
        ~String packageField
        +publicMethod()
        -privateMethod()
    }
```

## Method Modifiers

### Abstract and Static

```mermaid
classDiagram
    class Animal {
        +eat()* void        %% Abstract method
        +count()$ int       %% Static method
    }
```

### Return Types

```mermaid
classDiagram
    class Service {
        +getData() List~String~
        +process(input) Result
        +validate() bool
    }
```

## Generic Types

```mermaid
classDiagram
    class List~T~ {
        +add(item T)
        +get(index int) T
    }
    class Map~K,V~ {
        +put(key K, value V)
        +get(key K) V
    }
```

## Relationships

### Relationship Types

| Type | Syntax | Description |
|------|--------|-------------|
| Inheritance | `<\|--` | Class extends another |
| Composition | `*--` | Strong ownership |
| Aggregation | `o--` | Weak ownership |
| Association | `-->` | Uses/has reference |
| Dependency | `..>` | Depends on |
| Realization | `..\|>` | Implements interface |
| Link | `--` | Simple connection |

### Direction

Arrows can point either direction:

```mermaid
classDiagram
    A <|-- B : extends
    C --|> D : extends
    E *-- F : contains
    G --* H : contained by
```

### Relationship Examples

```mermaid
classDiagram
    Animal <|-- Dog : Inheritance
    Dog *-- Tail : Composition
    Dog o-- Toy : Aggregation
    Dog --> Food : Association
    Dog ..> Veterinarian : Dependency
    Dog ..|> Pet : Realization
```

### Labels

```mermaid
classDiagram
    Student "1" --> "*" Course : enrolls
    Professor "1" --> "1..*" Course : teaches
```

## Cardinality

| Notation | Meaning |
|----------|---------|
| `1` | Exactly one |
| `0..1` | Zero or one |
| `*` | Many (0 or more) |
| `1..*` | One or more |
| `n` | Fixed number |
| `0..n` | Zero to n |

```mermaid
classDiagram
    Company "1" --> "*" Employee
    Employee "1" --> "0..1" Desk
    Department "1" --> "1..*" Employee
```

## Annotations

### Class Annotations

```mermaid
classDiagram
    class Interface1 {
        <<interface>>
        +method()
    }
    class Abstract1 {
        <<abstract>>
        +method()*
    }
    class Service1 {
        <<service>>
    }
    class Enum1 {
        <<enumeration>>
        VALUE1
        VALUE2
    }
```

### Custom Annotations

```mermaid
classDiagram
    class Config {
        <<singleton>>
    }
    class Factory {
        <<factory>>
    }
```

## Namespaces

```mermaid
classDiagram
    namespace com.example.models {
        class User
        class Order
    }
    namespace com.example.services {
        class UserService
        class OrderService
    }
```

## Notes

```mermaid
classDiagram
    class Animal
    note for Animal "This is the base class<br/>for all animals"
```

## Styling

### Style Individual Classes

```mermaid
classDiagram
    class Important
    style Important fill:#f9f,stroke:#333,stroke-width:4px
```

### CSS Classes

```mermaid
classDiagram
    class Styled:::customClass
    classDef customClass fill:#f96,stroke:#333
```

## Complete Example

```mermaid
classDiagram
    class User {
        <<entity>>
        +Long id
        +String email
        +String name
        -String passwordHash
        +authenticate(password) bool
        +updateProfile(data) void
    }

    class UserRepository {
        <<interface>>
        +findById(id) User
        +findByEmail(email) User
        +save(user) User
        +delete(id) void
    }

    class UserService {
        <<service>>
        -UserRepository repository
        +register(data) User
        +login(email, password) Token
        +getProfile(id) UserDTO
    }

    class UserDTO {
        <<dto>>
        +Long id
        +String email
        +String name
    }

    UserService ..> UserRepository : uses
    UserService ..> User : creates
    UserService ..> UserDTO : returns
    UserRepository ..> User : manages

    class Admin {
        +manageUsers()
        +viewReports()
    }

    User <|-- Admin
```

## Common Patterns

### Repository Pattern

```mermaid
classDiagram
    class Repository~T~ {
        <<interface>>
        +findById(id) T
        +findAll() List~T~
        +save(entity T) T
        +delete(id) void
    }

    class UserRepository {
        <<interface>>
        +findByEmail(email) User
    }

    Repository <|-- UserRepository
```

### Service Layer

```mermaid
classDiagram
    class Controller {
        -Service service
        +handleRequest()
    }
    class Service {
        -Repository repo
        +businessLogic()
    }
    class Repository {
        +dataAccess()
    }

    Controller --> Service
    Service --> Repository
```

### Factory Pattern

```mermaid
classDiagram
    class Product {
        <<interface>>
        +operation()
    }
    class ConcreteProductA {
        +operation()
    }
    class ConcreteProductB {
        +operation()
    }
    class Factory {
        +createProduct(type) Product
    }

    Product <|.. ConcreteProductA
    Product <|.. ConcreteProductB
    Factory ..> Product : creates
```

### Decorator Pattern

```mermaid
classDiagram
    class Component {
        <<interface>>
        +operation()
    }
    class ConcreteComponent {
        +operation()
    }
    class Decorator {
        <<abstract>>
        -Component component
        +operation()
    }
    class ConcreteDecorator {
        +operation()
        +addedBehavior()
    }

    Component <|.. ConcreteComponent
    Component <|.. Decorator
    Decorator <|-- ConcreteDecorator
    Decorator o-- Component
```
