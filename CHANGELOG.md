# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial repository setup following Anthropic's Skills framework
- Installation script for copying skills to `~/.claude/skills/`
- README with skills documentation and guidelines
- CLAUDE.md with repository guidance
- Directory structure for skill organization
- Template skill structure in `.claude/skills/`
- **fastmod skill** - Comprehensive expertise for large-scale codebase refactoring
  - Main SKILL.md with Rust regex syntax guidance
  - quick-reference.md for command lookup
  - examples.md with real-world refactoring patterns
- **Tier 1 Essential Skills** - Five foundational command-line tools
  - **jq skill** - JSON query language for data processing
    - Complete jq syntax reference with filters, operators, and functions
    - Real-world workflows for API processing, log analysis, config management
    - Advanced techniques: recursive descent, custom functions, reduce
  - **ripgrep skill** - High-performance code search tool
    - Type filtering, glob patterns, and advanced regex
    - Security auditing patterns and performance analysis
    - Integration with git, docker, kubernetes workflows
  - **ast-grep skill** - Semantic code search and transformation
    - AST-based pattern matching with metavariables
    - React, TypeScript, Python, Rust, Go patterns
    - Error handling, security, and refactoring patterns
  - **yq skill** - YAML/JSON/XML processor with jq-like syntax
    - Multi-format support (YAML, JSON, XML, CSV, TOML)
    - Kubernetes, Docker Compose, CI/CD configuration management
    - Format conversions and complex merging strategies
  - **fzf skill** - Interactive command-line fuzzy finder
    - Custom key bindings and preview windows
    - Git integration (branches, commits, files)
    - Docker/Kubernetes workflows and system administration

[Unreleased]: https://github.com/MOlechowski/claude-skills/commits/master
