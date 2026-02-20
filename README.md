# Claude Skills

A curated collection of Claude Skills distributed as a **plugin marketplace** for [Claude Code](https://docs.claude.com/en/docs/claude-code). Each skill is an individual plugin you can install, enable, and disable independently.

## What are Claude Skills?

Skills are organized directories containing instructions, scripts, and resources that enable Claude to perform specialized tasks. They use **progressive disclosure** - loading information only when needed - to maximize efficiency and capability.

### Key Features

- **Plugin Marketplace**: Install only the skills you need via `/plugin install`
- **Granular Control**: Enable/disable individual skills with `/plugin enable/disable`
- **Progressive Loading**: Metadata loads first, then full instructions, then additional resources on-demand
- **Executable Code**: Skills can include Python scripts and other tools for deterministic operations
- **Context Efficient**: Only installed and enabled skills consume context tokens

## Installation

### Quick Start

```bash
# 1. Add the marketplace (registers the catalog, installs nothing)
/plugin marketplace add MOlechowski/claude-skills

# 2. Install individual skills
/plugin install go-expert@claude-skills
/plugin install cli-jq@claude-skills

# 3. Or browse interactively
/plugin
# → Discover tab → browse by category → install what you need
```

### Managing Installed Skills

```bash
/plugin disable go-expert@claude-skills    # Temporarily disable (keeps installed)
/plugin enable go-expert@claude-skills     # Re-enable
/plugin uninstall go-expert@claude-skills  # Fully remove

# Check what's consuming context tokens
/context
```

### Manual Installation

```bash
# Clone and copy a specific skill directly
git clone https://github.com/MOlechowski/claude-skills.git
cp -r claude-skills/plugins/aws-cli/skills/aws-cli ~/.claude/skills/
```

### Migrating from Global Skills

If you previously installed all skills via `install.sh`:

```bash
# Remove old global skills (they load ~16k tokens at startup)
rm -rf ~/.claude/skills/*

# Add the marketplace and install only what you need
/plugin marketplace add MOlechowski/claude-skills
/plugin install go-expert@claude-skills
```

## Repository Structure

```
claude-skills/
├── .claude-plugin/
│   └── marketplace.json          # Marketplace catalog (94 plugins)
├── plugins/
│   ├── aws-cli/
│   │   ├── .claude-plugin/
│   │   │   └── plugin.json       # Plugin metadata
│   │   └── skills/
│   │       └── aws-cli/
│   │           ├── SKILL.md      # Main skill definition
│   │           └── references/   # Optional supporting files
│   ├── aws-expert/
│   │   └── ...
│   └── ... (94 plugins total)
├── scripts/                      # Build/migration scripts
├── AGENTS.md                     # Agent instructions
├── CLAUDE.md                     # Repository guidance
├── CHANGELOG.md                  # Version history
├── LICENSE                       # MIT license
└── README.md                     # This file
```

## Available Skills (94 total)

All skills use domain prefixes for discoverability. Each skill is its own plugin.

### aws- (AWS + LocalStack)
| Skill | Description |
|-------|-------------|
| **aws-cli** | AWS CLI v2 expertise: authentication, 20+ service commands, output formatting, multi-account patterns |
| **aws-expert** | AWS architecture expertise: Well-Architected Framework, service selection, security, cost optimization |
| **aws-local** | Thin wrapper around AWS CLI for LocalStack |
| **aws-localstack** | LocalStack CLI for managing local AWS emulation containers |
| **aws-localstack-expert** | LocalStack architecture expertise: testing strategies, CI/CD integration, service parity |

### cf- (Cloudflare)
| Skill | Description |
|-------|-------------|
| **cf-ctl** | Cloudflare infrastructure CLI for DNS, firewall, zone management |
| **cf-expert** | Cloudflare infrastructure expertise: Zero Trust, security, Workers AI, MCP servers |
| **cf-tunnel** | Cloudflare Tunnel CLI for exposing local services |
| **cf-wrangler** | Cloudflare Workers CLI for serverless development |

### cli- (CLI Tool Wrappers)
| Skill | Description |
|-------|-------------|
| **cli-ast-grep** | Semantic code search using ASTs: structural matching, refactoring |
| **cli-fastmod** | Large-scale refactoring with interactive review |
| **cli-fzf** | Interactive fuzzy finder for files, history, lists |
| **cli-jq** | JSON processing and transformation |
| **cli-parallel** | Execute shell jobs in parallel using GNU parallel |
| **cli-ripgrep** | Fast recursive code search with smart defaults |
| **cli-tmux** | Terminal multiplexer for session management |
| **cli-tree** | Directory tree visualization |
| **cli-yq** | YAML/JSON/XML processor with jq-like syntax |

### dev- (Dev Workflow & Review)
| Skill | Description |
|-------|-------------|
| **dev-backlog** | Markdown-native task manager and Kanban board |
| **dev-compress** | Optimize token usage in markdown content |
| **dev-learn** | Capture learnings into documentation |
| **dev-review** | Code review orchestrator: auto-detects context and routes |
| **dev-review-file** | Deep code review of files and directories |
| **dev-review-pr** | Review git diffs, staged changes, and GitHub PRs |
| **dev-rlm** | Repository Language Model context management |
| **dev-skill-create** | Create new skills following best practices |
| **dev-swarm** | Parallelize tasks using Claude agents |

### doc- (Documentation & Notes)
| Skill | Description |
|-------|-------------|
| **doc-claude-md** | Create and maintain CLAUDE.md and AGENTS.md documentation |
| **doc-confluence** | Create and update Confluence Data Center pages from Markdown |
| **doc-mermaid** | Mermaid diagramming for code visualization and documentation |
| **doc-mermaid-render** | Render Mermaid diagrams to themed SVG or ASCII/Unicode art |
| **doc-notesmd** | NotesMD CLI for Obsidian vault operations from the terminal |
| **doc-obsidian** | Obsidian vault management combining search and CRUD |
| **doc-pandoc** | Universal document conversion with Pandoc |
| **doc-qmd** | Local on-device search engine for markdown knowledge bases |
| **doc-readme** | Create, update, and validate README.md files |

### git- (Git & Version Control)
| Skill | Description |
|-------|-------------|
| **git-commit** | Generate Conventional Commits messages |
| **git-land** | Commit changes and create PR in one flow |
| **git-pr-create** | Create GitHub PRs with structured title and body |
| **git-pr-manage** | Autonomous PR lifecycle management |
| **git-repo** | Create GitHub repositories via OpenTofu |
| **git-ship** | Commit, create PR, and merge with CI skipped |
| **git-worktree** | Work on multiple branches simultaneously |

### go- (Go Ecosystem)
| Skill | Description |
|-------|-------------|
| **go-delve** | Debugger: breakpoints, stepping, variable inspection, goroutines |
| **go-expert** | Language expertise: idiomatic patterns, project structure, best practices |
| **go-lefthook** | Git hooks manager for Go projects |
| **go-lint** | Linter aggregator: 100+ linters (staticcheck, gosec, errcheck) |
| **go-mockery** | Mock generation for interfaces using testify |
| **go-pprof** | Profiler: CPU profiling, memory allocation, goroutine analysis |
| **go-release** | Release automation: cross-compilation, archives, checksums |
| **go-task** | Task runner (taskfile.dev) for Go projects |

### iac- (Infrastructure as Code)
| Skill | Description |
|-------|-------------|
| **iac-expert** | IaC architecture: tool selection, module design, state management |
| **iac-hcloud** | Hetzner Cloud CLI for server lifecycle, networking, storage |
| **iac-opa** | Open Policy Agent for policy-as-code evaluation |
| **iac-terraform** | HashiCorp Terraform for infrastructure provisioning |
| **iac-tofu** | OpenTofu (open-source Terraform fork) |

### net- (Network & HTTP)
| Skill | Description |
|-------|-------------|
| **net-httpx** | Fast HTTP toolkit for probing and technology detection |
| **net-mitmproxy** | Interactive HTTPS proxy for traffic interception |
| **net-nmap** | Network scanner for port discovery and service detection |
| **net-tcpdump** | Command-line packet analyzer |
| **net-wireshark** | Network protocol analyzer (tshark CLI) |

### oci- (Container & OCI Images)
| Skill | Description |
|-------|-------------|
| **oci-crane** | Container image manipulation: push, pull, copy, mutate, inspect |
| **oci-dive** | Docker image layer explorer for analyzing contents and finding bloat |
| **oci-skopeo** | Daemon-less container operations and image signing |
| **oci-syft** | SBOM generation for containers and filesystems |

### re- (Reverse Engineering)
| Skill | Description |
|-------|-------------|
| **re-expert** | Security analysis methodology and tool selection guidance |
| **re-binwalk** | Firmware analysis: signature scanning, entropy, file extraction |
| **re-docker-expert** | Container forensics: layer analysis, secret extraction, build reconstruction |
| **re-dtrace** | DTrace dynamic tracing for macOS/BSD |
| **re-frida** | Dynamic instrumentation: hooking, tracing, mobile analysis |
| **re-gdb** | GDB debugger: breakpoints, memory examination, runtime patching |
| **re-ghidra** | Ghidra reverse engineering: scripting, headless analysis, decompiler |
| **re-lldb** | LLDB debugger for macOS/iOS reverse engineering |
| **re-objcopy** | Binary manipulation: sections, symbols, format conversion |
| **re-patchelf** | ELF binary modification: RPATH, interpreter, dependencies |
| **re-pwntools** | Exploit development: ROP chains, shellcode, CTF utilities |
| **re-python-expert** | Python reverse engineering: bytecode, decompilation, obfuscation |
| **re-radare2** | radare2/rizin framework: disassembly, patching, debugging |
| **re-strace** | Linux system call tracing with strace/ltrace |
| **re-xxd** | Hex dump and binary patching |

### res- (Research)
| Skill | Description |
|-------|-------------|
| **res-deep** | Iterative multi-round deep research with structured analysis |
| **res-trends** | Multi-source trend analysis with hybrid search |
| **res-web** | Web research and analysis |

### sec- (Security Scanning)
| Skill | Description |
|-------|-------------|
| **sec-bandit** | Python security linter for common security issues |
| **sec-grype** | Fast vulnerability scanner for container images and filesystems |
| **sec-nuclei** | Template-based vulnerability scanner for CVEs, misconfigurations |
| **sec-pip-audit** | Python dependency vulnerability scanner |
| **sec-semgrep** | Multi-language SAST tool for security patterns |
| **sec-trivy** | Comprehensive vulnerability scanner for containers, filesystems, Git repos |

### speckit- (Spec-Driven Development)
| Skill | Description |
|-------|-------------|
| **speckit-audit** | Audit specifications for completeness and quality |
| **speckit-flow** | Manage spec-driven development flow |
| **speckit-loop** | Autonomous spec-driven development loop |
| **speckit-retro** | Retrospective analysis of spec implementations |
| **speckit-verify** | Verify implementations against specifications |

## Usage

Once installed via the plugin marketplace, skills activate automatically based on context. Claude recognizes when to use skills from your requests — no manual invocation needed.

## Per-Repo Plugin Configuration

Control which skills are active per repository by committing `.claude/settings.json`. This is the recommended way to manage skills across teams and projects.

### Settings Scopes

| Scope | File | Committed? | Who sees it |
|-------|------|-----------|------------|
| **User** | `~/.claude/settings.json` | N/A | Only you, all repos |
| **Project** | `.claude/settings.json` | Yes | All team members |
| **Local** | `.claude/settings.local.json` | No (gitignored) | Only you, this repo |

Precedence: Local > Project > User. A project can disable plugins the user has enabled globally, and local settings can override both.

### Team Setup

Commit this to your repo's `.claude/settings.json` so every developer gets the right skills:

```json
{
  "extraKnownMarketplaces": {
    "claude-skills": {
      "source": {
        "source": "github",
        "repo": "MOlechowski/claude-skills"
      }
    }
  },
  "enabledPlugins": {
    "go-expert@claude-skills": true,
    "go-lint@claude-skills": true,
    "go-task@claude-skills": true,
    "git-commit@claude-skills": true,
    "dev-review-pr@claude-skills": true
  }
}
```

When a developer clones and trusts the repo, Claude Code prompts them to install the marketplace and pre-configures the listed plugins.

### Suggested Plugin Sets by Project Type

| Project Type | Recommended Plugins |
|-------------|-------------------|
| **Go service** | `go-expert`, `go-lint`, `go-task`, `go-delve`, `git-commit` |
| **Python** | `sec-bandit`, `sec-pip-audit`, `cli-jq`, `dev-review-pr` |
| **Infrastructure** | `iac-expert`, `iac-tofu`, `aws-expert`, `cf-expert` |
| **Security audit** | `sec-trivy`, `sec-semgrep`, `sec-nuclei`, `re-expert` |
| **Documentation** | `doc-readme`, `doc-mermaid`, `doc-confluence`, `doc-pandoc` |

### Personal Overrides

Developers can add personal plugins in `.claude/settings.local.json` (gitignored) without affecting team config:

```json
{
  "enabledPlugins": {
    "res-deep@claude-skills": true,
    "cli-fzf@claude-skills": true
  }
}
```

### Enterprise Lockdown

Organizations can restrict which marketplaces are allowed via managed settings at `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS) or `/etc/claude-code/managed-settings.json` (Linux):

```json
{
  "strictKnownMarketplaces": [
    { "source": "github", "repo": "acme-corp/approved-plugins" }
  ]
}
```

### Known Limitations

- `extraKnownMarketplaces` only triggers during interactive trust dialogs, not in CI/headless mode. Use `claude plugin marketplace add` explicitly in CI.
- Installing a plugin doesn't always auto-add it to `enabledPlugins`. If a plugin appears installed but inactive, manually add it to `settings.json`.
- No `defaultEnabled` flag in `marketplace.json` yet — commit `enabledPlugins` in project settings as a workaround.

## Skills vs Agents

| Feature | Skills | Agents |
|---------|--------|--------|
| **Location** | `~/.claude/skills/` | `~/.claude/agents/` |
| **Structure** | Directory with SKILL.md | Single .md file |
| **Resources** | Multiple files in directory | Embedded in single file |
| **Code Execution** | Bundled scripts | Via Bash tool |
| **Progressive Loading** | Yes (3 levels) | Partial |
| **Status** | Production (since October 16, 2025) | Fully supported |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your skill as a plugin in `plugins/<skill-name>/`
4. Follow the structure: `.claude-plugin/plugin.json` + `skills/<name>/SKILL.md`
5. Test thoroughly
6. Submit a pull request

## Related Projects

- [claude-agents](https://github.com/MOlechowski/claude-agents) - Custom agent definitions for Claude Code

## Resources

- [Anthropic: Equipping Agents for the Real World with Agent Skills](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [Claude Code Plugins](https://code.claude.com/docs/en/plugins)
- [Claude Code Plugin Marketplaces](https://code.claude.com/docs/en/plugin-marketplaces)

## License

MIT License - see [LICENSE](LICENSE) file for details.
