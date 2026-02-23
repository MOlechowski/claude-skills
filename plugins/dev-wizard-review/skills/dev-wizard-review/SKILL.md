---
name: dev-wizard-review
description: "Review generated/scaffolded code for maintainability — can the user own it? Checks comprehension risks (magic config, implicit behavior), ownership gaps (hidden dependencies, swallowed errors), maintenance risks (framework coupling, upgrade fragility). Use when: reviewing AI-generated code, reviewing scaffolded code, checking generated output, wizard code review. Triggers: review generated code, review scaffolded code, wizard review, can I maintain this, explain this generated code."
---

# Wizard Review

Review generated or scaffolded code through one lens: **can the user maintain this without understanding the generator?**

This is not a quality review (use dev-review for that). This asks: will the person using this code understand it well enough to debug, modify, and extend it independently?

## When to Use

- After receiving code from AI assistants (Claude, Copilot, Cursor)
- After running scaffolders (`create-react-app`, `rails new`, `go generate`, `cookiecutter`)
- After framework generators produce boilerplate
- When inheriting code nobody on the team wrote
- When the user explicitly asks: "review this generated code", "can I maintain this?"

## Workflow

```
Identify Source → Read Code → Check Three Dimensions → Flag Sections → Report
```

### Phase 1: Identify Source

Determine what generated the code:
- User states it ("Claude wrote this", "I ran create-next-app")
- Visible markers: generator comments, scaffold signatures, boilerplate patterns
- If unclear, ask: "What generated this code?"

### Phase 2: Read Code

Read every file in scope. Understand the full picture before flagging anything.

### Phase 3: Check Three Dimensions

#### Comprehension Risks

Code that works but the user may not understand WHY:

**Magic configuration:**
- Config files with non-obvious defaults that affect behavior
- Environment variables referenced but never explained
- Build tool config (webpack, vite, esbuild) with subtle options
- Flag: "This `resolve.alias` config makes `@/` imports work. Removing it breaks all imports silently."

**Implicit behavior:**
- ORM lazy loading (queries fire on property access, not where you see SQL)
- Middleware ordering (auth before rate-limit vs. after changes behavior)
- Decorator/annotation side effects (`@Transactional`, `@Cacheable`, `@Inject`)
- Auto-serialization/deserialization (Jackson, Gson, serde)
- Convention over configuration (Rails: file naming controls routing)
- Flag: "This `@Transactional` on line 42 means the entire method runs in a single DB transaction. If the email send on line 58 fails, the user record on line 45 rolls back too."

**Framework-specific idioms:**
- Patterns that look like standard code but have framework-specific meaning
- Hook ordering dependencies (React useEffect cleanup, Vue lifecycle)
- Template syntax that compiles to non-obvious output
- Flag: "This `useEffect` with an empty dependency array runs once on mount. Adding `userId` to the array changes it to run on every user change."

#### Ownership Gaps

Code where the user doesn't have full control:

**Hidden dependencies:**
- Transitive dependencies the generator pulled in
- Peer dependencies with version constraints
- Native modules or platform-specific code
- Flag: "The generator added `sharp` (native image processing). This requires platform-specific binaries and may fail in CI without extra setup."

**Error handling that looks complete but isn't:**
- Generic catch-all that swallows specific errors
- Retry logic without backoff or max attempts
- Timeout handling that doesn't clean up resources
- Flag: "The catch on line 30 logs the error but returns a 200 status. The caller will think this succeeded."

**Security-relevant patterns:**
- Auth flows that need human verification (token storage, refresh logic, CSRF)
- Input validation that covers happy path only
- CORS configuration that's too permissive
- Flag: "CORS is set to `origin: '*'`. This allows any website to call your API with user credentials."

#### Maintenance Risks

Code that will cause problems over time:

**Framework version coupling:**
- Code using internal/unstable APIs that may change
- Deprecated patterns the generator hasn't updated
- Version-pinned dependencies with known upgrade friction
- Flag: "This uses `getInitialProps` which is deprecated in Next.js 13+. Migrating to `getServerSideProps` requires restructuring data flow."

**Upgrade fragility:**
- Generated config files that should not be manually edited
- Lock files and generated types that need regeneration
- Ejected configs that lose future generator updates
- Flag: "Running `eject` means you now own 47 webpack config files. Future create-react-app improvements won't apply to your project."

**Debugging opacity:**
- Code that can't be stepped through (compiled templates, macro expansions)
- Error messages that point to generated internals, not user code
- Abstraction layers that hide the actual behavior
- Flag: "Errors from this GraphQL resolver will show the generated schema location, not your resolver function. Add error boundaries to get useful stack traces."

### Phase 4: Report

```markdown
# Wizard Review: [scope]

**Source:** [What generated this code]
**Files reviewed:** [count]
**Attention needed:** [N] sections

## Sections Needing Your Attention

### 1. [Brief title — e.g., "Transaction rollback affects email send"]

**File:** `file:line-range`
**Dimension:** Comprehension | Ownership | Maintenance
**Risk:** What can go wrong if this isn't understood
**What it does:** [Plain-language explanation of the non-obvious behavior]
**What to verify:** [Specific action — read this doc, test this scenario, check this config]

### 2. [Next section...]

[...]

## Safe to Ignore

[List sections that look like magic but are standard, well-documented patterns. Brief explanation of why they're fine.]

## Recommended Reading

[2-3 specific documentation links for the frameworks/tools used, focused on the non-obvious behaviors flagged above.]
```

## Rules

1. **This is not a quality review.** Don't score pillars. Don't flag style issues. Only flag comprehension, ownership, and maintenance risks.
2. **Explain, don't just flag.** Every finding must include a plain-language explanation of what the code actually does. The whole point is helping the user understand.
3. **Be specific about what to verify.** "Read the docs" is useless. "Test what happens when the email send fails on line 58" is actionable.
4. **Include "Safe to Ignore."** Reduce noise. If something looks magical but is a well-known pattern, say so and move on.
5. **No false alarms on standard patterns.** `import React from 'react'` is not "implicit behavior." Calibrate to genuinely non-obvious things.
6. **Assume the user is competent but unfamiliar.** They can understand the code — they just need the non-obvious parts pointed out.
