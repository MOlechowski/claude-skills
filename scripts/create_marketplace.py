#!/usr/bin/env python3
"""
Migrate .claude/skills/* to plugin marketplace structure.

Each skill becomes its own plugin:
  plugins/<skill>/.claude-plugin/plugin.json
  plugins/<skill>/skills/<skill>/SKILL.md (+ supporting files)

Root marketplace catalog:
  .claude-plugin/marketplace.json
"""

import json
import re
import shutil
import sys
from pathlib import Path

# Prefix -> category mapping
PREFIX_CATEGORY = {
    "aws": "aws",
    "cf": "cloudflare",
    "cli": "cli",
    "dev": "dev",
    "doc": "documentation",
    "git": "git",
    "go": "go",
    "iac": "iac",
    "net": "network",
    "oci": "containers",
    "re": "reverse-engineering",
    "res": "research",
    "sec": "security",
    "speckit": "speckit",
}


def get_category(skill_name: str) -> str:
    """Extract category from skill name prefix."""
    for prefix, category in PREFIX_CATEGORY.items():
        if skill_name.startswith(prefix + "-"):
            return category
    return "general"



def parse_frontmatter(skill_md_path: Path) -> dict:
    """Extract YAML frontmatter fields from SKILL.md."""
    content = skill_md_path.read_text()

    match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return {}

    frontmatter = {}
    for line in match.group(1).splitlines():
        # Parse simple key: value or key: "value"
        kv = re.match(r'^(\w+):\s*"?(.*?)"?\s*$', line)
        if kv:
            frontmatter[kv.group(1)] = kv.group(2)

    return frontmatter


def create_plugin_json(skill_name: str, frontmatter: dict) -> dict:
    """Create plugin.json for a single skill."""
    return {
        "name": skill_name,
        "version": "1.0.0",
        "description": frontmatter.get("description", ""),
    }


def create_marketplace_entry(skill_name: str, frontmatter: dict) -> dict:
    """Create a marketplace.json entry for one plugin."""
    category = get_category(skill_name)

    return {
        "name": skill_name,
        "description": frontmatter.get("description", ""),
        "source": f"./plugins/{skill_name}",
        "category": category,
        "version": "1.0.0",
    }


def migrate(repo_root: Path, dry_run: bool = False) -> None:
    """Run the full migration."""
    skills_dir = repo_root / ".claude" / "skills"
    plugins_dir = repo_root / "plugins"
    marketplace_dir = repo_root / ".claude-plugin"

    if not skills_dir.is_dir():
        print(f"Error: {skills_dir} not found")
        sys.exit(1)

    # Collect all skill directories
    skill_dirs = sorted(
        [d for d in skills_dir.iterdir() if d.is_dir() and (d / "SKILL.md").exists()]
    )
    print(f"Found {len(skill_dirs)} skills to migrate")

    if dry_run:
        print("\n[DRY RUN] Would create:")

    marketplace_entries = []

    for skill_dir in skill_dirs:
        skill_name = skill_dir.name
        frontmatter = parse_frontmatter(skill_dir / "SKILL.md")

        if not frontmatter.get("name"):
            print(f"  Warning: {skill_name}/SKILL.md missing 'name' in frontmatter")
            frontmatter["name"] = skill_name

        # Plugin paths
        plugin_dir = plugins_dir / skill_name
        plugin_meta_dir = plugin_dir / ".claude-plugin"
        plugin_skills_dir = plugin_dir / "skills" / skill_name

        if dry_run:
            file_count = sum(1 for _ in skill_dir.rglob("*") if _.is_file())
            print(f"  plugins/{skill_name}/ ({file_count} files)")
            marketplace_entries.append(
                create_marketplace_entry(skill_name, frontmatter)
            )
            continue

        # Create plugin directory structure
        plugin_meta_dir.mkdir(parents=True, exist_ok=True)
        plugin_skills_dir.mkdir(parents=True, exist_ok=True)

        # Copy all skill files into plugins/<skill>/skills/<skill>/
        for item in skill_dir.iterdir():
            dest = plugin_skills_dir / item.name
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)

        # Write plugin.json
        plugin_json = create_plugin_json(skill_name, frontmatter)
        (plugin_meta_dir / "plugin.json").write_text(
            json.dumps(plugin_json, indent=2) + "\n"
        )

        # Collect marketplace entry
        marketplace_entries.append(
            create_marketplace_entry(skill_name, frontmatter)
        )

        print(f"  ✓ {skill_name}")

    # Write marketplace.json
    marketplace = {
        "name": "claude-skills",
        "version": "1.0.0",
        "description": "Curated collection of 90+ Claude Code skills for DevOps, security, reverse engineering, and development workflows",
        "owner": {
            "name": "MOlechowski",
            "email": "michal@olechowski.cloud",
        },
        "plugins": marketplace_entries,
    }

    if dry_run:
        print(f"\n  .claude-plugin/marketplace.json ({len(marketplace_entries)} plugins)")
        print("\n[DRY RUN] No changes made.")
        return

    marketplace_dir.mkdir(parents=True, exist_ok=True)
    (marketplace_dir / "marketplace.json").write_text(
        json.dumps(marketplace, indent=2) + "\n"
    )
    print(f"\n✓ Created .claude-plugin/marketplace.json ({len(marketplace_entries)} plugins)")

    # Remove original .claude/skills/ directory
    shutil.rmtree(skills_dir)
    print(f"✓ Removed {skills_dir}")

    print(f"\nMigration complete: {len(marketplace_entries)} plugins in plugins/")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Migrate skills to plugin marketplace")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview changes without writing"
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root (auto-detected if omitted)",
    )
    args = parser.parse_args()

    if args.repo_root:
        repo_root = args.repo_root.resolve()
    else:
        # Auto-detect from script location
        repo_root = Path(__file__).resolve().parent.parent

    print(f"Repo root: {repo_root}")
    migrate(repo_root, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
