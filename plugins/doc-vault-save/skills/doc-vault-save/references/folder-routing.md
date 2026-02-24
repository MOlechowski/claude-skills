# Folder Routing

Loaded on demand (Level 3), when routing a note in Step 2.

## Default Routes

| Content Type | Default Folder | Rationale |
|-------------|---------------|-----------|
| res-deep (any framework) | `research/` | Matches existing vault convention |
| res-price-compare | `research/` | Price comparisons are research artifacts |
| generic (note) | vault root | Let Obsidian's configured default handle it |

## User Override

| User Says | Route To |
|-----------|----------|
| "save to research" | `research/` |
| "save to projects" | `projects/` |
| "save to {folder}" | `{folder}/` |
| "save to projects/alpha" | `projects/alpha/` |

Intermediate directories are created automatically by notesmd-cli.

## Folder Validation

```bash
notesmd-cli list "{folder}" 2>/dev/null
```

If folder does not exist, inform user it will be created and proceed.

## Topic-Based Sub-routing (suggestions only)

For vaults with deep hierarchies, suggest sub-folders — but never auto-route without confirmation:

| Topic Domain | Suggested Sub-folder | Detection |
|-------------|---------------------|-----------|
| Hardware/products | `research/hardware/` | Product names, specs, pricing |
| Software/tools | `research/tools/` | Software names, repos, frameworks |
| Architecture/decisions | `research/decisions/` | Decision framework, "should we" topics |
| Home/renovation | `research/home/` | Construction, renovation, house topics |

Present as suggestion only:

```
Default: research/agent-swarms-hardware-decision
Suggestion: research/hardware/agent-swarms-hardware-decision
Use default or suggestion?
```

## Conflict Resolution

When a note name exists in a different folder:

| Scenario | Action |
|----------|--------|
| Same name, same folder | Step 3 dedup handles this |
| Same name, different folder | Show both locations, ask which to use |
| Similar name (fuzzy match) | Show both, let user decide |

```bash
# Search for name across vault
qmd search "{note-name}" --json -n 5
```

## Persistent Routing Rules

Users can establish routing preferences within a session:

> "Always save price comparisons to research/pricing/"
> "Put all AI research in research/ai/"

For cross-session persistence, user should document in vault (e.g., `meta/routing-rules.md`).
