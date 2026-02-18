#!/bin/bash

# Claude Skills Installation Script
# Copies skill directories from this repo to ~/.claude/skills/

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse flags
ALL=false
for arg in "$@"; do
    case "$arg" in
        --all) ALL=true ;;
    esac
done

# Source and destination directories
SOURCE_DIR="$(dirname "$0")/.claude/skills"
DEST_DIR="$HOME/.claude/skills"

echo "Installing Claude skills..."

# Create destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

# Check if source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo -e "${RED}Error: Source directory $SOURCE_DIR not found${NC}"
    exit 1
fi

# Check for skill directories
shopt -s nullglob
skill_dirs=("$SOURCE_DIR"/*)
shopt -u nullglob

if [ ${#skill_dirs[@]} -eq 0 ]; then
    echo -e "${RED}Error: No skill directories found in $SOURCE_DIR${NC}"
    exit 1
fi

# Copy each skill directory with confirmation for overwrites
copied=0
skipped=0

for skill_dir in "${skill_dirs[@]}"; do
    if [ ! -d "$skill_dir" ]; then
        continue
    fi

    skill_name=$(basename "$skill_dir")
    dest_path="$DEST_DIR/$skill_name"

    # Check if skill directory already exists
    if [ -d "$dest_path" ]; then
        if [ "$ALL" = false ]; then
            echo -e "${YELLOW}⚠ Skill '$skill_name' already exists${NC}"
            read -p "  Overwrite? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "  Skipped $skill_name"
                ((skipped++))
                continue
            fi
        fi
        # Remove existing directory
        rm -rf "$dest_path"
    fi

    # Copy skill directory
    cp -r "$skill_dir" "$dest_path"
    echo -e "${GREEN}✓${NC} Installed $skill_name"
    ((copied++))
done

# Summary
echo ""
echo -e "${GREEN}✓ Installation complete${NC}"
echo "  Installed: $copied skill(s)"
echo "  Skipped: $skipped skill(s)"
echo ""
echo "Installed skills in $DEST_DIR:"
for skill_dir in "$DEST_DIR"/*; do
    if [ -d "$skill_dir" ] && [ -f "$skill_dir/SKILL.md" ]; then
        skill_name=$(basename "$skill_dir")
        echo "  - $skill_name"
    fi
done
echo ""
echo "Skills are now available in Claude Code. They will activate automatically based on context."
echo ""
echo -e "${GREEN}Note:${NC} Skills are production-ready in Claude Code 1.0+ (since October 16, 2025)."
echo "Visit https://github.com/anthropics/skills for official examples."
