#!/usr/bin/env python3
"""
Quick binary triage before Ghidra analysis.

Usage:
    python3 analyze_binary.py ./binary
    python3 analyze_binary.py ./binary --json
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd, timeout=30):
    """Run command and return output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except FileNotFoundError:
        return "[command not found]"
    except Exception as e:
        return f"[error: {e}]"


def analyze(binary_path):
    """Perform triage analysis."""
    info = {
        "path": str(binary_path),
        "exists": os.path.exists(binary_path),
    }

    if not info["exists"]:
        return info

    # File type
    info["file_type"] = run_cmd(["file", "-b", binary_path])

    # Size
    info["size"] = os.path.getsize(binary_path)

    # Check if ELF
    is_elf = "ELF" in info["file_type"]
    is_pe = "PE" in info["file_type"] or "executable" in info["file_type"].lower()

    if is_elf:
        info["format"] = "ELF"

        # ELF header
        header = run_cmd(["readelf", "-h", binary_path])
        if "Entry point" in header:
            for line in header.split("\n"):
                if "Entry point" in line:
                    info["entry_point"] = line.split(":")[1].strip()
                if "Type:" in line:
                    info["elf_type"] = line.split(":")[1].strip()
                if "Machine:" in line:
                    info["architecture"] = line.split(":")[1].strip()

        # Check if stripped
        nm_out = run_cmd(["nm", binary_path])
        info["stripped"] = "no symbols" in nm_out.lower() or nm_out.startswith("[")

        # Security features
        stack_info = run_cmd(["readelf", "-l", binary_path])
        info["nx_enabled"] = "GNU_STACK" in stack_info and "RWE" not in stack_info

        # Dynamic libraries
        ldd_out = run_cmd(["ldd", binary_path])
        if not ldd_out.startswith("["):
            info["libraries"] = [
                line.split()[0] for line in ldd_out.split("\n")
                if "=>" in line or line.strip().startswith("/")
            ][:10]

    elif is_pe:
        info["format"] = "PE"

    # Interesting strings
    strings_out = run_cmd(["strings", "-n", "6", binary_path])
    keywords = ["password", "flag", "secret", "key", "admin", "root",
                "http://", "https://", "/bin/", "system", "exec"]

    interesting = []
    for line in strings_out.split("\n")[:1000]:
        for kw in keywords:
            if kw.lower() in line.lower():
                interesting.append(line[:80])
                break

    info["interesting_strings"] = interesting[:20]

    # String count
    info["total_strings"] = len(strings_out.split("\n"))

    return info


def main():
    parser = argparse.ArgumentParser(description="Binary triage for Ghidra")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    info = analyze(args.binary)

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"File: {info['path']}")
        if not info.get("exists"):
            print("ERROR: File not found")
            sys.exit(1)

        print(f"Type: {info.get('file_type', 'unknown')}")
        print(f"Size: {info.get('size', 0):,} bytes")

        if info.get("format"):
            print(f"Format: {info['format']}")

        if info.get("architecture"):
            print(f"Architecture: {info['architecture']}")

        if info.get("entry_point"):
            print(f"Entry Point: {info['entry_point']}")

        if "stripped" in info:
            print(f"Stripped: {'Yes' if info['stripped'] else 'No'}")

        if "nx_enabled" in info:
            print(f"NX Enabled: {'Yes' if info['nx_enabled'] else 'No'}")

        if info.get("libraries"):
            print(f"\nLibraries ({len(info['libraries'])}):")
            for lib in info["libraries"][:5]:
                print(f"  {lib}")

        if info.get("interesting_strings"):
            print(f"\nInteresting Strings ({len(info['interesting_strings'])}):")
            for s in info["interesting_strings"][:10]:
                print(f"  {s}")

        print(f"\nTotal strings: {info.get('total_strings', 0)}")


if __name__ == "__main__":
    main()
