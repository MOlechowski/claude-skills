---
name: doc-changelog
description: "Generate and update CHANGELOG.md from git history. Parses commits, PRs, and tags to produce Keep a Changelog entries grouped by type (Added, Changed, Fixed, Removed). Detects version bumps from tags, links PRs/issues, supports date ranges and unreleased sections. Use when: updating changelog, generating release notes, what changed since last release, changelog from git log. Triggers: changelog, release notes, update changelog, what changed, generate changelog, doc-changelog."
---

# Changelog Generator

Generate CHANGELOG.md entries from git history following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## Workflow

```
1. Detect range → 2. Collect commits → 3. Enrich with PRs → 4. Classify → 5. Format → 6. Update file
```

### 1. Detect Range

Determine what commits to include:

```bash
# Find latest version tag
git tag --sort=-v:refname | head -20
```

**Range selection:**
- If CHANGELOG.md has `## [Unreleased]` — collect commits since last version tag
- If user specifies a range — use that (`v1.0.0..HEAD`, `--since="2 weeks ago"`)
- If no tags exist — collect all commits on the default branch
- If user says "release X.Y.Z" — collect unreleased commits, stamp with version and date

### 2. Collect Commits

```bash
# Commits since last tag (or all if no tags)
git log v1.0.0..HEAD --format="%H|%s|%an|%aI" --no-merges
```

For merge-based workflows, also collect merge commits to find PR numbers:

```bash
git log v1.0.0..HEAD --format="%H|%s" --merges
```

### 3. Enrich with PR/Issue Data

If the repo is on GitHub, enrich commits with PR metadata:

```bash
# Get PRs merged since last tag
gh pr list --state merged --base main --json number,title,labels,mergedAt --limit 100
```

Or for a specific date range:

```bash
gh pr list --state merged --search "merged:>2026-01-01" --json number,title,labels,body --limit 100
```

Match commits to PRs via:
- PR number in commit message (e.g., `(#123)`)
- Merge commit references
- `gh pr list` merged date within range

### 4. Classify Changes

Map commits/PRs to Keep a Changelog categories using Conventional Commits prefixes and PR labels:

| Category | Conventional Commits | PR Labels |
|----------|---------------------|-----------|
| **Added** | `feat:`, `feat(scope):` | `feature`, `enhancement` |
| **Changed** | `refactor:`, `perf:`, `build:` | `refactor`, `performance` |
| **Deprecated** | `deprecate:` | `deprecation` |
| **Removed** | commit message contains "remove", "delete" | `removal` |
| **Fixed** | `fix:`, `fix(scope):` | `bug`, `bugfix` |
| **Security** | `security:` | `security`, `vulnerability` |

**Classification rules:**
- Conventional Commit prefix takes priority over PR labels
- If no prefix and no label, classify as **Changed**
- Skip commits matching: `chore:`, `ci:`, `docs:` (unless `docs:` adds user-facing docs)
- Skip commits matching: `Merge branch`, `Merge pull request` (metadata, not changes)
- Group by scope when present: `feat(auth):` → group under auth

### 5. Format Entries

Follow Keep a Changelog format strictly:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- **scope**: Description of feature ([#123](link))

### Fixed
- Description of fix ([#456](link))
```

**Formatting rules:**
- One bullet per logical change (merge related commits into single entry)
- Start each entry with bold **scope** if scope is present in commit
- Link PR numbers: `([#123](https://github.com/OWNER/REPO/pull/123))`
- Link issue numbers: `([#456](https://github.com/OWNER/REPO/issues/456))`
- Use imperative mood for descriptions (Add, Fix, Remove — not Added, Fixed, Removed)
- Keep entries concise — one line per change, details belong in PR descriptions
- Order categories: Added → Changed → Deprecated → Removed → Fixed → Security

### 6. Update File

**If CHANGELOG.md exists:**
- Insert new version section below `## [Unreleased]` header
- If stamping a release, replace `## [Unreleased]` content with versioned section, add empty `## [Unreleased]` above
- Update comparison links at bottom of file

**If CHANGELOG.md does not exist:**
- Create with full Keep a Changelog header
- Include `## [Unreleased]` section
- Add comparison links

**Comparison links** (bottom of file):

```markdown
[Unreleased]: https://github.com/OWNER/REPO/compare/vX.Y.Z...HEAD
[X.Y.Z]: https://github.com/OWNER/REPO/compare/vX.Y.Z-1...vX.Y.Z
```

## Usage Patterns

### Update Unreleased Section

Default behavior — collect all changes since last tag:

> "Update the changelog"

### Stamp a Release

Move unreleased entries to a versioned section:

> "Release v2.1.0"

Result: `## [Unreleased]` becomes empty, `## [2.1.0] - 2026-02-23` added with entries.

### Changelog for Range

Generate entries for a specific commit range:

> "Changelog for v1.0.0..v2.0.0"

### First Changelog

Create CHANGELOG.md from scratch for a repo without one:

> "Create a changelog for this project"

## Edge Cases

- **Squash merges**: Commit message often contains full PR description — extract the title line only
- **Monorepo**: If user specifies a path, filter commits with `-- path/to/package`
- **No Conventional Commits**: Fall back to PR titles and labels for classification; if neither available, list all as Changed
- **Amended/rebased history**: Use `--first-parent` to follow mainline only
- **Multiple tags on same commit**: Use the highest semver tag
