#!/usr/bin/env python3
"""
Rename skill directories and update all references.

Performs:
1. Rename directories under .claude/skills/
2. Update name: field in SKILL.md frontmatter
3. Update cross-references in all SKILL.md files
4. Print a summary report
"""

import os
import re
import shutil
from pathlib import Path

# Complete rename mapping: old_name -> new_name
RENAME_MAP = {
    # git- (Git/GitHub/VCS)
    "commit": "git-commit",
    "commit-pr": "git-land",
    "commit-pr-ci-merge": "git-ship",
    # git-worktree: no change
    "github-repo": "git-repo",
    "pr-create": "git-pr-create",
    "pr-manage": "git-pr-manage",

    # go- (Go ecosystem)
    "go-golangci-lint": "go-lint",
    "go-goreleaser": "go-release",
    "go-lang-expert": "go-expert",
    # go-delve, go-lefthook, go-mockery, go-pprof, go-task: no change

    # re- (Reverse Engineering) — all 15 unchanged

    # speckit- (Spec-Driven Dev)
    "spec-driven": "speckit-loop",
    # speckit-audit, speckit-flow, speckit-retro, speckit-verify: no change

    # aws- (AWS + LocalStack)
    "awslocal": "aws-local",
    "localstack": "aws-localstack",
    "localstack-expert": "aws-localstack-expert",
    # aws-cli, aws-expert: no change

    # cf- (Cloudflare)
    "cloudflare-expert": "cf-expert",
    "cloudflared": "cf-tunnel",
    "flarectl": "cf-ctl",
    "wrangler": "cf-wrangler",

    # sec- (Security Scanning)
    "bandit": "sec-bandit",
    "grype": "sec-grype",
    "nuclei": "sec-nuclei",
    "pip-audit": "sec-pip-audit",
    "semgrep": "sec-semgrep",
    "trivy": "sec-trivy",

    # net- (Network & HTTP)
    "httpx": "net-httpx",
    "mitmproxy": "net-mitmproxy",
    "nmap": "net-nmap",
    "tcpdump": "net-tcpdump",
    "wireshark": "net-wireshark",

    # oci- (Container/OCI Images)
    "crane": "oci-crane",
    "dive": "oci-dive",
    "skopeo": "oci-skopeo",
    "syft": "oci-syft",

    # iac- (Infrastructure as Code)
    "hcloud": "iac-hcloud",
    "opa": "iac-opa",
    "platform-architect": "iac-expert",
    "terraform": "iac-terraform",
    "tofu": "iac-tofu",

    # cli- (CLI Tool Wrappers)
    "ast-grep": "cli-ast-grep",
    "fastmod": "cli-fastmod",
    "fzf": "cli-fzf",
    "jq": "cli-jq",
    "parallel": "cli-parallel",
    "ripgrep": "cli-ripgrep",
    "tmux": "cli-tmux",
    "tree": "cli-tree",
    "yq": "cli-yq",

    # dev- (Dev Workflow & Methodology)
    "backlog-md": "dev-backlog",
    "parallel-flow": "dev-swarm",
    "rlm": "dev-rlm",
    "self-improvement": "dev-learn",
    "skill-creator": "dev-skill-create",
    "token-optimize": "dev-compress",

    # doc- (Documentation & Notes)
    "beautiful-mermaid": "doc-mermaid-render",
    "claude-md": "doc-claude-md",
    "confluence-writer": "doc-confluence",
    "mermaid": "doc-mermaid",
    "notesmd-cli": "doc-notesmd",
    "obsidian-vault": "doc-obsidian",
    "qmd": "doc-qmd",
    "readme": "doc-readme",

    # res- (Research)
    "deep-research": "res-deep",
    "trends-research": "res-trends",
    "web-research": "res-web",

    # dev- (Code Review — merged into dev-)
    "review": "dev-review",
    "review-file": "dev-review-file",
    "review-pr": "dev-review-pr",
}


def get_repo_root() -> Path:
    """Get repository root (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def rename_directories(skills_dir: Path) -> list[str]:
    """Rename skill directories. Returns list of actions taken."""
    actions = []
    for old_name, new_name in sorted(RENAME_MAP.items()):
        old_path = skills_dir / old_name
        new_path = skills_dir / new_name
        if old_path.is_dir():
            if new_path.exists():
                actions.append(f"SKIP {old_name} -> {new_name} (target exists)")
                continue
            old_path.rename(new_path)
            actions.append(f"RENAME {old_name} -> {new_name}")
        else:
            actions.append(f"MISSING {old_name} (directory not found)")
    return actions


def update_frontmatter(skills_dir: Path) -> list[str]:
    """Update name: field in SKILL.md frontmatter for renamed skills."""
    actions = []
    for old_name, new_name in sorted(RENAME_MAP.items()):
        skill_md = skills_dir / new_name / "SKILL.md"
        if not skill_md.exists():
            continue

        content = skill_md.read_text()
        # Match name: field in YAML frontmatter (between --- delimiters)
        # Handle both quoted and unquoted values
        updated = re.sub(
            r'^(name:\s*)(["\']?)' + re.escape(old_name) + r'(["\']?)\s*$',
            rf'\g<1>\g<2>{new_name}\g<3>',
            content,
            count=1,
            flags=re.MULTILINE
        )
        if updated != content:
            skill_md.write_text(updated)
            actions.append(f"FRONTMATTER {new_name}/SKILL.md")
    return actions


def build_reference_patterns() -> list[tuple[re.Pattern, str]]:
    """Build regex patterns for cross-reference replacement.

    Sort by old name length descending to avoid partial matches
    (e.g., replace 'commit-pr-ci-merge' before 'commit-pr' before 'commit').
    """
    patterns = []
    for old_name, new_name in sorted(RENAME_MAP.items(), key=lambda x: -len(x[0])):
        # Match /old-name (slash command references) — most common pattern
        patterns.append((
            re.compile(r'/' + re.escape(old_name) + r'(?=[\s,.:;)\]|}"\']|$)', re.MULTILINE),
            f'/{new_name}'
        ))
        # Match `old-name` (backtick-quoted references)
        patterns.append((
            re.compile(r'`' + re.escape(old_name) + r'`'),
            f'`{new_name}`'
        ))
        # Match **old-name** (bold references)
        patterns.append((
            re.compile(r'\*\*' + re.escape(old_name) + r'\*\*'),
            f'**{new_name}**'
        ))
        # Match "old-name skill" or "old-name Skill" (prose references)
        patterns.append((
            re.compile(r'\b' + re.escape(old_name) + r'(?= skill\b)', re.IGNORECASE),
            new_name
        ))
        # Match "the old-name" (with article, in prose)
        patterns.append((
            re.compile(r'(?<=the )' + re.escape(old_name) + r'(?=[\s,.])', re.MULTILINE),
            new_name
        ))
        # Match "use old-name" (verb + skill name)
        patterns.append((
            re.compile(r'(?<=use )' + re.escape(old_name) + r'(?=[\s,.])', re.MULTILINE),
            new_name
        ))
    return patterns


def update_cross_references(skills_dir: Path) -> list[str]:
    """Update cross-references in all SKILL.md files and other .md files."""
    actions = []
    patterns = build_reference_patterns()

    # Collect all markdown files in skill directories
    md_files = list(skills_dir.rglob("*.md"))

    for md_file in md_files:
        content = md_file.read_text()
        original = content

        for pattern, replacement in patterns:
            content = pattern.sub(replacement, content)

        if content != original:
            md_file.write_text(content)
            rel_path = md_file.relative_to(skills_dir)
            actions.append(f"XREF {rel_path}")

    return actions


def update_commands(commands_dir: Path) -> list[str]:
    """Update skill references in .claude/commands/ files."""
    actions = []
    if not commands_dir.is_dir():
        return actions

    patterns = build_reference_patterns()
    for md_file in commands_dir.glob("*.md"):
        content = md_file.read_text()
        original = content

        for pattern, replacement in patterns:
            content = pattern.sub(replacement, content)

        if content != original:
            md_file.write_text(content)
            actions.append(f"COMMAND {md_file.name}")

    return actions


def main():
    repo_root = get_repo_root()
    skills_dir = repo_root / ".claude" / "skills"
    commands_dir = repo_root / ".claude" / "commands"

    if not skills_dir.is_dir():
        print(f"ERROR: Skills directory not found: {skills_dir}")
        return 1

    print(f"Skills directory: {skills_dir}")
    print(f"Rename mapping: {len(RENAME_MAP)} skills to rename\n")

    # Phase 1: Rename directories
    print("=" * 60)
    print("Phase 1: Rename directories")
    print("=" * 60)
    dir_actions = rename_directories(skills_dir)
    for action in dir_actions:
        print(f"  {action}")
    print()

    # Phase 2: Update frontmatter
    print("=" * 60)
    print("Phase 2: Update SKILL.md frontmatter")
    print("=" * 60)
    fm_actions = update_frontmatter(skills_dir)
    for action in fm_actions:
        print(f"  {action}")
    print()

    # Phase 3: Update cross-references
    print("=" * 60)
    print("Phase 3: Update cross-references in skill files")
    print("=" * 60)
    xref_actions = update_cross_references(skills_dir)
    for action in xref_actions:
        print(f"  {action}")
    print()

    # Phase 4: Update commands
    print("=" * 60)
    print("Phase 4: Update .claude/commands/ references")
    print("=" * 60)
    cmd_actions = update_commands(commands_dir)
    for action in cmd_actions:
        print(f"  {action}")
    if not cmd_actions:
        print("  (no changes needed)")
    print()

    # Summary
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    renames = [a for a in dir_actions if a.startswith("RENAME")]
    missing = [a for a in dir_actions if a.startswith("MISSING")]
    skipped = [a for a in dir_actions if a.startswith("SKIP")]
    print(f"  Directories renamed: {len(renames)}")
    print(f"  Directories missing: {len(missing)}")
    print(f"  Directories skipped: {len(skipped)}")
    print(f"  Frontmatter updated: {len(fm_actions)}")
    print(f"  Cross-refs updated:  {len(xref_actions)} files")
    print(f"  Commands updated:    {len(cmd_actions)} files")

    if missing:
        print("\nWARNING: Missing directories:")
        for m in missing:
            print(f"  {m}")

    return 0


if __name__ == "__main__":
    exit(main())
