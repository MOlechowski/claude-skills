# User Journey Reference

User journey diagrams map user experiences with satisfaction scores.

## Basic Syntax

```mermaid
journey
    title User Journey Title
    section Section Name
        Task name: score: Actor
```

## Structure

### Title

```mermaid
journey
    title My User Journey
```

### Sections

Sections group related tasks in the journey:

```mermaid
journey
    title User Journey
    section Discovery
        Task 1: 5: User
    section Evaluation
        Task 2: 4: User
    section Purchase
        Task 3: 3: User
```

## Tasks

### Task Format

```
Task description: satisfaction_score: Actor1, Actor2
```

### Satisfaction Scores

Scores range from 0-5:

| Score | Meaning |
|-------|---------|
| 0 | Very negative |
| 1 | Negative |
| 2 | Somewhat negative |
| 3 | Neutral |
| 4 | Positive |
| 5 | Very positive |

### Score Examples

```mermaid
journey
    title Experience Scores
    section Examples
        Very easy: 5: User
        Easy: 4: User
        Neutral: 3: User
        Difficult: 2: User
        Very difficult: 1: User
```

## Actors

### Single Actor

```mermaid
journey
    title User Journey
    section Signup
        Enter email: 5: User
        Set password: 3: User
```

### Multiple Actors

```mermaid
journey
    title Support Interaction
    section Contact
        Submit ticket: 4: Customer
        Receive ticket: 5: Agent
    section Resolution
        Investigate: 3: Agent
        Respond: 4: Agent
        Receive response: 5: Customer
```

## Complete Examples

### E-commerce Purchase

```mermaid
journey
    title E-commerce Purchase Journey
    section Discovery
        Search for product: 5: Customer
        Browse categories: 4: Customer
        Read reviews: 5: Customer
    section Evaluation
        Compare prices: 4: Customer
        Check availability: 5: Customer
        View product details: 4: Customer
    section Purchase
        Add to cart: 5: Customer
        Enter shipping info: 3: Customer
        Enter payment info: 2: Customer
        Confirm order: 4: Customer
    section Fulfillment
        Receive confirmation: 5: Customer
        Track shipment: 4: Customer
        Receive package: 5: Customer
    section Post-Purchase
        Unbox product: 5: Customer
        Use product: 4: Customer
        Leave review: 3: Customer
```

### SaaS Onboarding

```mermaid
journey
    title SaaS Onboarding Journey
    section Signup
        Visit landing page: 5: User
        Click signup: 5: User
        Fill registration form: 3: User
        Verify email: 2: User
    section Setup
        Complete profile: 4: User
        Connect integrations: 2: User
        Import data: 3: User
    section Learning
        Watch tutorial video: 4: User
        Complete first task: 5: User
        Explore features: 4: User
    section Activation
        Invite team members: 3: User
        Set up workflow: 4: User
        First successful use: 5: User
```

### Customer Support

```mermaid
journey
    title Support Ticket Journey
    section Issue Discovery
        Encounter problem: 1: Customer
        Search help docs: 3: Customer
        Decide to contact support: 3: Customer
    section Contact
        Find contact form: 4: Customer
        Describe issue: 3: Customer
        Submit ticket: 4: Customer
    section Waiting
        Receive confirmation: 5: Customer
        Wait for response: 2: Customer
    section Resolution
        Receive initial response: 4: Customer
        Provide more info: 3: Customer
        Receive solution: 5: Customer
        Issue resolved: 5: Customer
    section Follow-up
        Rate support: 4: Customer
        Receive survey: 3: Customer
```

### Mobile App First Use

```mermaid
journey
    title Mobile App First Experience
    section Download
        Discover app: 5: User
        Read reviews: 4: User
        Download app: 5: User
    section Setup
        Open app: 5: User
        View onboarding: 4: User
        Create account: 3: User
        Set preferences: 4: User
    section First Use
        Navigate home: 4: User
        Try main feature: 5: User
        Encounter issue: 2: User
        Find help: 3: User
    section Engagement
        Complete first task: 5: User
        Receive notification: 3: User
        Return next day: 4: User
```

### Multi-Actor Journey

```mermaid
journey
    title Restaurant Ordering Journey
    section Order Placement
        Browse menu: 5: Customer
        Customize order: 4: Customer
        Submit order: 5: Customer
        Receive order: 5: Kitchen
    section Preparation
        Prepare food: 4: Kitchen
        Quality check: 5: Kitchen
        Notify ready: 5: Kitchen
    section Delivery
        Accept delivery: 4: Driver
        Pick up order: 5: Driver
        Navigate to customer: 3: Driver
        Deliver order: 5: Driver
    section Completion
        Receive order: 5: Customer
        Enjoy meal: 5: Customer
        Rate experience: 4: Customer
        Receive tip: 5: Driver
```

### B2B Sales Journey

```mermaid
journey
    title B2B Sales Journey
    section Awareness
        See content: 4: Prospect
        Visit website: 4: Prospect
        Download whitepaper: 5: Prospect
    section Interest
        Receive follow-up: 3: Prospect
        Schedule demo: 4: Prospect
        Attend demo: 5: Prospect, Sales Rep
    section Evaluation
        Receive proposal: 4: Prospect
        Internal discussion: 3: Prospect
        Request references: 4: Prospect
        Check references: 5: Prospect
    section Decision
        Negotiate terms: 3: Prospect, Sales Rep
        Get approval: 4: Prospect
        Sign contract: 5: Prospect, Sales Rep
    section Onboarding
        Kickoff meeting: 5: Customer, Account Manager
        Implementation: 3: Customer
        Training: 4: Customer
        Go live: 5: Customer
```

## Identifying Pain Points

Low scores highlight friction:

```mermaid
journey
    title Checkout Pain Points
    section Checkout
        View cart: 5: User
        Enter address: 3: User
        Address validation fails: 1: User
        Re-enter address: 2: User
        Select shipping: 4: User
        Enter payment: 2: User
        Payment declined: 1: User
        Try another card: 3: User
        Complete purchase: 5: User
```

## Tips

1. **Focus on Key Steps**: Include significant touchpoints, not every action
2. **Honest Scores**: Use realistic satisfaction levels to identify issues
3. **Multiple Actors**: Show handoffs between roles/systems
4. **Sections**: Group by phase, channel, or time period
5. **Identify Friction**: Low scores reveal improvement opportunities
6. **Tell a Story**: Order tasks chronologically
7. **Include Context**: Task descriptions should be self-explanatory
