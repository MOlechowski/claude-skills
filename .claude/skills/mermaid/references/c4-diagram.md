# C4 Diagram Reference

C4 diagrams visualize software architecture at different levels of abstraction.

## C4 Model Levels

1. **Context** (Level 1) - System in its environment
2. **Container** (Level 2) - High-level tech decisions
3. **Component** (Level 3) - Components within containers
4. **Code** (Level 4) - Implementation details (use class diagrams)

## Context Diagram (C4Context)

Shows the system and its relationships with users and external systems.

```mermaid
C4Context
    title System Context Diagram

    Person(user, "User", "A user of the system")
    Person_Ext(admin, "Admin", "System administrator")

    System(system, "Our System", "Main system description")
    System_Ext(email, "Email System", "Sends emails")
    System_Ext(payment, "Payment Provider", "Processes payments")

    Rel(user, system, "Uses", "HTTPS")
    Rel(admin, system, "Manages", "HTTPS")
    Rel(system, email, "Sends emails via", "SMTP")
    Rel(system, payment, "Processes payments", "HTTPS/API")
```

## Container Diagram (C4Container)

Shows the containers (applications, data stores) that make up the system.

```mermaid
C4Container
    title Container Diagram

    Person(user, "User")

    System_Boundary(boundary, "System") {
        Container(web, "Web App", "React", "User interface")
        Container(api, "API", "Node.js", "Business logic")
        ContainerDb(db, "Database", "PostgreSQL", "Stores data")
        ContainerQueue(queue, "Message Queue", "RabbitMQ", "Async processing")
    }

    System_Ext(email, "Email Service")

    Rel(user, web, "Uses", "HTTPS")
    Rel(web, api, "Calls", "JSON/HTTPS")
    Rel(api, db, "Reads/Writes", "SQL")
    Rel(api, queue, "Publishes", "AMQP")
    Rel(queue, email, "Sends", "SMTP")
```

## Component Diagram (C4Component)

Shows the components within a container.

```mermaid
C4Component
    title Component Diagram - API

    Container(spa, "SPA", "React")
    ContainerDb(db, "Database", "PostgreSQL")

    Container_Boundary(api, "API Application") {
        Component(auth, "Auth Controller", "Express", "Handles authentication")
        Component(users, "User Controller", "Express", "User management")
        Component(orders, "Order Controller", "Express", "Order processing")
        Component(service, "Business Service", "Node.js", "Core business logic")
        Component(repo, "Repository", "TypeORM", "Data access")
    }

    Rel(spa, auth, "Authenticates")
    Rel(spa, users, "User operations")
    Rel(spa, orders, "Order operations")
    Rel(auth, service, "Uses")
    Rel(users, service, "Uses")
    Rel(orders, service, "Uses")
    Rel(service, repo, "Uses")
    Rel(repo, db, "Reads/Writes")
```

## Elements

### People

```mermaid
C4Context
    Person(user, "User", "Description")
    Person_Ext(external, "External User", "External to system")
```

### Systems

```mermaid
C4Context
    System(main, "Main System", "Our system")
    System_Ext(external, "External System", "Third party")
```

### Containers

```mermaid
C4Container
    Container(app, "Application", "Technology", "Description")
    ContainerDb(db, "Database", "PostgreSQL", "Stores data")
    ContainerQueue(queue, "Queue", "RabbitMQ", "Message broker")
    Container_Ext(ext, "External Container", "Tech", "Description")
```

### Components

```mermaid
C4Component
    Component(comp, "Component", "Technology", "Description")
    Component_Ext(ext, "External Component", "Tech", "Description")
```

## Boundaries

### System Boundary

```mermaid
C4Container
    System_Boundary(sys, "System Name") {
        Container(a, "Container A")
        Container(b, "Container B")
    }
```

### Container Boundary

```mermaid
C4Component
    Container_Boundary(api, "API") {
        Component(ctrl, "Controller")
        Component(svc, "Service")
    }
```

### Enterprise Boundary

```mermaid
C4Context
    Enterprise_Boundary(ent, "Enterprise") {
        System(a, "System A")
        System(b, "System B")
    }
```

## Relationships

### Basic Relationships

```mermaid
C4Context
    Person(user, "User")
    System(sys, "System")

    Rel(user, sys, "Uses")
    Rel(user, sys, "Uses", "HTTPS")
    Rel(user, sys, "Uses", "HTTPS", "JSON")
```

### Directional Relationships

```mermaid
C4Context
    System(a, "A")
    System(b, "B")
    System(c, "C")
    System(d, "D")

    Rel_U(a, b, "Up")        %% Upward
    Rel_D(a, c, "Down")      %% Downward
    Rel_L(a, d, "Left")      %% Left
    Rel_R(a, b, "Right")     %% Right
```

### Bidirectional

```mermaid
C4Context
    System(a, "A")
    System(b, "B")

    BiRel(a, b, "Syncs with")
```

### Back Relationships

```mermaid
C4Context
    System(a, "A")
    System(b, "B")

    Rel_Back(a, b, "Returns to")
```

## Deployment Diagram

```mermaid
C4Deployment
    title Deployment Diagram

    Deployment_Node(cloud, "AWS", "Cloud") {
        Deployment_Node(region, "us-east-1", "Region") {
            Deployment_Node(vpc, "VPC", "Network") {
                Deployment_Node(web, "Web Tier", "EC2") {
                    Container(webapp, "Web App", "nginx")
                }
                Deployment_Node(app, "App Tier", "ECS") {
                    Container(api, "API", "Node.js")
                }
                Deployment_Node(data, "Data Tier", "RDS") {
                    ContainerDb(db, "Database", "PostgreSQL")
                }
            }
        }
    }

    Rel(webapp, api, "Calls")
    Rel(api, db, "Reads/Writes")
```

## Styling

### Update Element Style

```mermaid
C4Context
    Person(user, "User")
    System(sys, "System")

    UpdateElementStyle(user, $fontColor="red", $bgColor="white")
    UpdateElementStyle(sys, $bgColor="#438DD5")
```

### Layout Direction

```mermaid
C4Context
    UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="2")
```

## Complete Example

```mermaid
C4Context
    title E-Commerce System Context

    Person(customer, "Customer", "Buys products online")
    Person(support, "Support Agent", "Handles customer issues")

    Enterprise_Boundary(company, "Company") {
        System(ecommerce, "E-Commerce Platform", "Main sales platform")
        System(crm, "CRM System", "Customer management")
        System(warehouse, "Warehouse System", "Inventory management")
    }

    System_Ext(payment, "Payment Gateway", "Stripe")
    System_Ext(shipping, "Shipping Provider", "FedEx API")
    System_Ext(email, "Email Service", "SendGrid")

    Rel(customer, ecommerce, "Browses and buys", "HTTPS")
    Rel(support, crm, "Manages customers", "HTTPS")
    Rel(ecommerce, crm, "Syncs customer data")
    Rel(ecommerce, warehouse, "Checks inventory")
    Rel(ecommerce, payment, "Processes payments", "API")
    Rel(warehouse, shipping, "Creates shipments", "API")
    Rel(ecommerce, email, "Sends notifications", "API")
```

```mermaid
C4Container
    title E-Commerce Container Diagram

    Person(customer, "Customer")

    System_Boundary(platform, "E-Commerce Platform") {
        Container(web, "Web Store", "Next.js", "Customer-facing website")
        Container(mobile, "Mobile App", "React Native", "iOS/Android app")
        Container(api, "API Gateway", "Kong", "API routing and auth")
        Container(catalog, "Catalog Service", "Node.js", "Product catalog")
        Container(cart, "Cart Service", "Python", "Shopping cart")
        Container(order, "Order Service", "Java", "Order processing")
        ContainerDb(db, "Database", "PostgreSQL", "Main data store")
        ContainerDb(cache, "Cache", "Redis", "Session and cache")
        ContainerQueue(queue, "Message Queue", "Kafka", "Event streaming")
    }

    System_Ext(payment, "Stripe", "Payment processing")

    Rel(customer, web, "Uses", "HTTPS")
    Rel(customer, mobile, "Uses", "HTTPS")
    Rel(web, api, "Calls", "HTTPS")
    Rel(mobile, api, "Calls", "HTTPS")
    Rel(api, catalog, "Routes to")
    Rel(api, cart, "Routes to")
    Rel(api, order, "Routes to")
    Rel(catalog, db, "Reads")
    Rel(cart, cache, "Stores sessions")
    Rel(order, db, "Writes")
    Rel(order, queue, "Publishes events")
    Rel(order, payment, "Charges", "API")
```

## Tips

1. **Start with Context**: Always begin with a Context diagram
2. **Zoom In**: Only add Container/Component diagrams where needed
3. **Keep It Simple**: 5-10 elements per diagram is ideal
4. **Consistent Naming**: Use clear, consistent names across diagrams
5. **Descriptions**: Add brief descriptions to elements
6. **Technology Labels**: Include technology choices in containers
7. **Show Key Flows**: Focus on important relationships
