# Claude Skills

A curated collection of Claude Skills following Anthropic's [Agent Skills framework](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills) for use with Claude Code, Claude.ai, and the Claude Agent SDK.

## What are Claude Skills?

Skills are organized directories containing instructions, scripts, and resources that enable Claude to perform specialized tasks. They use **progressive disclosure** - loading information only when needed - to maximize efficiency and capability.

### Key Features

- **Modular Design**: Each skill is self-contained in its own directory
- **Progressive Loading**: Metadata loads first, then full instructions, then additional resources on-demand
- **Executable Code**: Skills can include Python scripts and other tools for deterministic operations
- **Context Efficient**: Unbounded resources accessed via filesystem without bloating context
- **Composable**: Package and share domain expertise across teams and projects

## Repository Structure

```
claude-skills/
├── .claude/
│   ├── skills/                # Skill directories
│   │   ├── example-skill/    # Each skill in its own directory
│   │   │   ├── SKILL.md      # Main skill definition with YAML frontmatter
│   │   │   ├── forms.md      # Optional: Additional reference files
│   │   │   └── script.py     # Optional: Executable code
│   └── settings.local.json    # Local permissions configuration
├── install.sh                 # Installation script
├── CLAUDE.md                  # Repository guidance for Claude
├── CHANGELOG.md               # Version history
├── LICENSE                    # MIT license
└── README.md                  # This file
```

## Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/MOlechowski/claude-skills.git
cd claude-skills

# Run the installation script
./install.sh
```

The installation script will:
- Create `~/.claude/skills/` directory if it doesn't exist
- Copy all skill directories to your user directory
- Prompt for confirmation before overwriting existing skills
- Provide a summary of installed skills

### Manual Installation

```bash
# Copy skills to Claude's configuration directory
cp -r .claude/skills/* ~/.claude/skills/
```

## Creating Skills

### Skill Structure

Each skill follows Anthropic's specification with a `SKILL.md` file containing YAML frontmatter:

```markdown
---
name: skill-name
description: Clear description of what this skill does and when to use it
---

# Skill Instructions

Detailed instructions for Claude on how to use this skill...
```

### Required Frontmatter

- **name**: Unique identifier for the skill
- **description**: Concise explanation of the skill's purpose and usage

### Optional Components

Skills can include additional files in their directory:
- Reference documents (`.md` files)
- Python scripts (`.py` files)
- Configuration files
- Data files

### Progressive Disclosure Pattern

1. **Level 1 (Startup)**: Name and description load into system prompt
2. **Level 2 (Activation)**: Full `SKILL.md` loads when skill is relevant
3. **Level 3+ (On-Demand)**: Additional files load as needed

## Available Skills (93 total)

All skills use domain prefixes for discoverability. See [AGENTS.md](AGENTS.md) for the full naming convention.

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

Once installed, skills automatically become available to Claude Code. Claude will:
1. See skill metadata at startup
2. Activate appropriate skills based on context
3. Load additional resources on-demand as needed

### With Claude Code

```bash
# Skills work automatically in Claude Code sessions
claude

# Claude will recognize when to use skills based on your requests
```

### With Claude Agent SDK

```typescript
import { ClaudeAgent } from '@anthropic-ai/claude-agent-sdk';

// Skills are automatically discovered from ~/.claude/skills/
const agent = new ClaudeAgent({
  // ... configuration
});
```

## Skills vs Agents

| Feature | Skills | Agents |
|---------|--------|--------|
| **Location** | `~/.claude/skills/` | `~/.claude/agents/` |
| **Structure** | Directory with SKILL.md | Single .md file |
| **Resources** | Multiple files in directory | Embedded in single file |
| **Code Execution** | Bundled scripts | Via Bash tool |
| **Progressive Loading** | Yes (3 levels) | Partial |
| **Status** | Production (since October 16, 2025) | Fully supported |

## Compatibility

**Supported Platforms:**
- Claude.ai (web interface)
- Claude Code (CLI tool)
- Claude Agent SDK (programmatic access)
- Claude Developer Platform (API)

**Current Status:** Skills are fully supported in Claude Code 1.0+ (production-ready since October 16, 2025). This repository provides curated, reusable skills for common development workflows.

## Development

### Creating a New Skill

1. Create a directory in `.claude/skills/` with your skill name
2. Add a `SKILL.md` file with YAML frontmatter
3. Include any additional files needed
4. Test the skill locally
5. Submit a pull request

### Skill Guidelines

- **Single Responsibility**: Each skill should focus on one domain
- **Clear Description**: Make it obvious when the skill applies
- **Self-Contained**: Bundle all necessary resources
- **Documentation**: Include examples in the skill description
- **Testing**: Verify the skill works as intended

### Example Skill Template

```markdown
---
name: example-skill
description: |
  This skill helps with [specific task]. Use it when you need to [scenario].

  Examples:
  - "I need to [use case 1]" → Activate this skill
  - "Help me with [use case 2]" → Activate this skill
---

# Example Skill Instructions

You are an expert in [domain]. Your role is to [primary function].

## Core Capabilities

1. **Capability 1**: Description
2. **Capability 2**: Description
3. **Capability 3**: Description

## Usage Guidelines

- When to use this skill: [conditions]
- Key techniques: [approaches]
- Output format: [expectations]

## Additional Resources

You can reference additional files in this skill directory:
- `reference.md` - Additional documentation
- `script.py` - Executable code for deterministic operations
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add your skill following the guidelines
4. Test thoroughly
5. Submit a pull request with clear description

## Related Projects

- [claude-agents](https://github.com/MOlechowski/claude-agents) - Custom agent definitions for Claude Code

## Resources

- [Anthropic: Equipping Agents for the Real World with Agent Skills](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [Claude Code Documentation](https://docs.claude.com/en/docs/claude-code)
- [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

This repository follows Anthropic's Agent Skills framework and is designed to complement Claude Code's capability system.
