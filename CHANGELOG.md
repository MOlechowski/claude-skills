# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **cli-web-scrape** — Scrapling CLI wrapper: web scraping with browser impersonation, stealth headers, CSS selectors, Cloudflare bypass, JS rendering (3 fetcher tiers)
- **doc-vault-save** — save structured content to Obsidian vault with frontmatter, folder routing, deduplication, and wikilink generation
- **doc-daily-digest** — process Obsidian daily notes: classify URLs and ideas, fetch content, create structured notes, replace with wikilinks
- **doc-project** — orchestrator skill that updates CLAUDE.md, AGENTS.md, README.md, SKILLS.md, CHANGELOG.md in one pass (#123, #125)
- **doc-changelog** — generate and update CHANGELOG.md from git history (#116)
- **doc-skills-md** — generate SKILLS.md with marketplace plugin recommendations (#117, #118)
- **dev-broken-windows** — scan codebase for entropy indicators: skipped tests, dead code, TODO debt (#109)
- **dev-dry-audit** — detect DRY violations: code clones, repeated constants, knowledge duplication (#110)
- **dev-wizard-review** — review generated/scaffolded code for maintainability (#111)
- **dev-reload** — SIGHUP-based Claude Code configuration reload without full restart (#112)
- **res-x** — fetch X/Twitter tweet content by URL and search X posts
- **dev-review** Paranoia pillar — added as 7th review dimension (#108)

### Changed
- **cli-web-scrape** — replaced "Escalation Pattern" with "Auto-Escalation Protocol": content validation heuristics, 4-step tier progression (HTTP → validate → Dynamic → Stealthy), consumer skill integration guidance (#134)
- **res-deep** — scrapling fallback now uses auto-escalation protocol instead of bare HTTP tier (#134)
- **res-price-compare** — scrapling fallback now uses auto-escalation protocol instead of bare HTTP tier (#134)
- **doc-daily-digest** — scrapling fallback now uses auto-escalation protocol instead of bare HTTP tier (#134)
- **Plugin count** — marketplace now contains 108 plugins across 14 domain prefixes
- **plugin.json schema** — Claude Code only accepts `name`, `version`, `description`; category/tags/author moved to marketplace.json (#113, #114, #115)

### Fixed
- **doc-obsidian** — added partial edit workflow to prevent skill bypass (#107)
- **doc-skills-md** — added marketplace catalog reference with plugin domains (#118)
- **plugin manifests** — removed unsupported fields from 5 plugin.json files (#113, #114)

### Removed
- **speckit slash commands** — removed `.claude/commands/speckit.*.md` (#119)
- **`.specify/` directory** — removed legacy speckit working directory (#120)
- **`specs/` directory** — removed speckit test directory (#121)
- **`scripts/` directory** — removed legacy migration and speckit scripts (#122)
- **43 legacy `.skill` archives** — removed after plugin migration (#98)

## [1.0.0] - 2026-02-08

Initial plugin marketplace release with 97 plugins.

### Changed
- **Migrated to plugin marketplace architecture** — each skill is now an individual plugin in `plugins/<name>/` with `.claude-plugin/plugin.json`. Users install the marketplace once then enable/disable individual skills. Replaces the flat `~/.claude/skills/` directory and `install.sh`. (#93)
- **Standardized all skill names with domain prefixes** — 66 skills renamed across 14 namespaces. Key renames: `commit` → `git-commit`, `cloudflared` → `cf-tunnel`, `go-golangci-lint` → `go-lint`, `localstack` → `aws-localstack`, `terraform` → `iac-terraform`, `bandit` → `sec-bandit`. (#91)

### Added

#### AWS (5 plugins)
- **aws-cli** — AWS CLI v2: authentication, 20+ service commands, output formatting, multi-account patterns
- **aws-expert** — AWS architecture: Well-Architected Framework, service selection, cost optimization
- **aws-local** — thin wrapper around AWS CLI for LocalStack
- **aws-localstack** — LocalStack CLI for managing local AWS emulation
- **aws-localstack-expert** — LocalStack architecture: testing strategies, CI/CD, service parity

#### Cloudflare (4 plugins)
- **cf-ctl** — Cloudflare infrastructure CLI: DNS, firewall, zone management
- **cf-expert** — Cloudflare expertise: Zero Trust, Workers AI, MCP servers
- **cf-tunnel** — Cloudflare Tunnel CLI for exposing local services
- **cf-wrangler** — Cloudflare Workers CLI for serverless development

#### CLI Tools (9 plugins)
- **cli-ast-grep** — semantic code search using ASTs
- **cli-fastmod** — large-scale refactoring with interactive review
- **cli-fzf** — interactive fuzzy finder for files, history, lists
- **cli-jq** — JSON processing and transformation
- **cli-parallel** — GNU parallel for executing jobs in parallel
- **cli-ripgrep** — fast recursive code search
- **cli-tmux** — terminal multiplexer for session management
- **cli-tree** — directory tree visualization
- **cli-yq** — YAML/JSON/XML processor with jq-like syntax

#### Dev Workflow (9 plugins)
- **dev-backlog** — markdown-native task manager and Kanban board
- **dev-compress** — optimize token usage in markdown content
- **dev-learn** — capture learnings into documentation
- **dev-review** — code review orchestrator with 6 analysis pillars
- **dev-review-file** — deep code review of files and directories
- **dev-review-pr** — review git diffs, staged changes, and GitHub PRs
- **dev-rlm** — Repository Language Model context management
- **dev-skill-create** — create new skills following best practices
- **dev-swarm** — parallelize tasks using Claude agents

#### Documentation (11 plugins)
- **doc-book-reader** — read entire books (PDF, EPUB, DOCX, TXT) and produce synthesis reports
- **doc-claude-md** — create and maintain CLAUDE.md and AGENTS.md
- **doc-confluence** — create and update Confluence Data Center pages from Markdown
- **doc-extract** — document intelligence: extract text from PDFs, images using tiered OCR
- **doc-mermaid** — Mermaid diagramming for code visualization
- **doc-mermaid-render** — render Mermaid diagrams to themed SVG or ASCII art
- **doc-notesmd** — NotesMD CLI for Obsidian vault operations
- **doc-obsidian** — Obsidian vault management combining qmd search and CRUD
- **doc-pandoc** — universal document conversion with Pandoc
- **doc-qmd** — local on-device search engine for markdown knowledge bases
- **doc-readme** — create, update, and validate README.md files

#### Git (7 plugins)
- **git-commit** — generate Conventional Commits messages
- **git-land** — commit changes and create PR in one flow
- **git-pr-create** — create GitHub PRs with structured title and body
- **git-pr-manage** — autonomous PR lifecycle management
- **git-repo** — create GitHub repositories via OpenTofu
- **git-ship** — commit, create PR, and merge with CI skipped
- **git-worktree** — work on multiple branches simultaneously

#### Go (8 plugins)
- **go-delve** — debugger: breakpoints, stepping, variable inspection
- **go-expert** — idiomatic patterns, project structure, best practices
- **go-lefthook** — git hooks manager for Go projects
- **go-lint** — linter aggregator: 100+ linters
- **go-mockery** — mock generation for interfaces
- **go-pprof** — profiler: CPU, memory allocation, goroutine analysis
- **go-release** — release automation: cross-compilation, archives, checksums
- **go-task** — task runner (taskfile.dev)

#### Infrastructure as Code (5 plugins)
- **iac-expert** — IaC architecture: tool selection, module design, state management
- **iac-hcloud** — Hetzner Cloud CLI for server lifecycle, networking, storage
- **iac-opa** — Open Policy Agent for policy-as-code evaluation
- **iac-terraform** — HashiCorp Terraform for infrastructure provisioning
- **iac-tofu** — OpenTofu (open-source Terraform fork)

#### Network (5 plugins)
- **net-httpx** — fast HTTP toolkit for probing and technology detection
- **net-mitmproxy** — interactive HTTPS proxy for traffic interception
- **net-nmap** — network scanner for port discovery and service detection
- **net-tcpdump** — command-line packet analyzer
- **net-wireshark** — network protocol analyzer (tshark CLI)

#### Containers (4 plugins)
- **oci-crane** — container image manipulation: push, pull, copy, inspect
- **oci-dive** — Docker image layer explorer
- **oci-skopeo** — daemon-less container operations and image signing
- **oci-syft** — SBOM generation for containers and filesystems

#### Reverse Engineering (15 plugins)
- **re-binwalk** — firmware analysis: signature scanning, entropy, extraction
- **re-docker-expert** — container forensics: layer analysis, secret extraction
- **re-dtrace** — DTrace dynamic tracing for macOS/BSD
- **re-expert** — security analysis methodology and tool selection
- **re-frida** — dynamic instrumentation: hooking, tracing, mobile analysis
- **re-gdb** — GDB debugger: breakpoints, memory, runtime patching
- **re-ghidra** — Ghidra scripting, headless analysis, decompiler
- **re-lldb** — LLDB debugger for macOS/iOS
- **re-objcopy** — binary manipulation: sections, symbols, format conversion
- **re-patchelf** — ELF binary modification: RPATH, interpreter, dependencies
- **re-pwntools** — exploit development: ROP chains, shellcode, CTF utilities
- **re-python-expert** — Python reverse engineering: bytecode, decompilation
- **re-radare2** — radare2/rizin: disassembly, patching, debugging
- **re-strace** — Linux system call tracing
- **re-xxd** — hex dump and binary patching

#### Research (4 plugins)
- **res-deep** — iterative multi-round deep research with structured analysis
- **res-price-compare** — Polish market product price comparison
- **res-trends** — multi-source trend analysis with hybrid search
- **res-web** — web research and analysis

#### Security (6 plugins)
- **sec-bandit** — Python security linter
- **sec-grype** — vulnerability scanner for container images and filesystems
- **sec-nuclei** — template-based vulnerability scanner
- **sec-pip-audit** — Python dependency vulnerability scanner
- **sec-semgrep** — multi-language SAST tool
- **sec-trivy** — comprehensive vulnerability scanner

#### Speckit (5 plugins)
- **speckit-audit** — audit specifications for completeness and quality
- **speckit-flow** — manage spec-driven development flow
- **speckit-loop** — autonomous spec-driven development loop
- **speckit-retro** — retrospective analysis of spec implementations
- **speckit-verify** — verify implementations against specifications

- **Per-repo plugin configuration** — control which skills are active per repository via `.claude/settings.json` (#94)
- **SKILLS.md** — project-local skill documentation and recommendations (#97)
- **qmd search integration** — local on-device search across all plugins (#88)

[Unreleased]: https://github.com/MOlechowski/claude-skills/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/MOlechowski/claude-skills/commits/master
