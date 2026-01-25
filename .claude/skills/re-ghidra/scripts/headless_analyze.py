#!/usr/bin/env python3
"""
Ghidra headless analysis wrapper.

Usage:
    python3 headless_analyze.py ./binary
    python3 headless_analyze.py ./binary --script ExportFunctions.py
    python3 headless_analyze.py ./binary --script MyScript.py --script-args "arg1" "arg2"
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def find_ghidra():
    """Find Ghidra installation."""
    # Check environment variable
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home and os.path.exists(ghidra_home):
        return ghidra_home

    # Common locations
    locations = [
        "/opt/ghidra",
        "/usr/local/ghidra",
        os.path.expanduser("~/ghidra"),
        "/Applications/ghidra",
        # Version-specific
        "/opt/ghidra_10.4_PUBLIC",
        "/opt/ghidra_11.0_PUBLIC",
    ]

    # Also check for versioned directories
    for base in ["/opt", "/usr/local", os.path.expanduser("~")]:
        if os.path.exists(base):
            for item in os.listdir(base):
                if item.startswith("ghidra"):
                    locations.append(os.path.join(base, item))

    for loc in locations:
        headless = os.path.join(loc, "support", "analyzeHeadless")
        if os.path.exists(headless):
            return loc

    return None


def run_headless(binary, project_dir=None, scripts=None, script_args=None,
                 script_path=None, no_analysis=False, overwrite=True,
                 timeout=None, log_file=None):
    """Run Ghidra headless analysis."""
    ghidra_home = find_ghidra()
    if not ghidra_home:
        print("ERROR: Ghidra not found. Set GHIDRA_HOME environment variable.")
        return 1

    headless = os.path.join(ghidra_home, "support", "analyzeHeadless")

    # Project directory
    if not project_dir:
        project_dir = tempfile.mkdtemp(prefix="ghidra_")

    binary_name = os.path.basename(binary)
    project_name = f"project_{binary_name.replace('.', '_')}"

    cmd = [headless, project_dir, project_name, "-import", binary]

    if overwrite:
        cmd.append("-overwrite")

    if no_analysis:
        cmd.append("-noanalysis")

    if scripts:
        for script in scripts:
            cmd.extend(["-postScript", script])
            if script_args:
                cmd.extend(script_args)

    if script_path:
        cmd.extend(["-scriptPath", script_path])

    if timeout:
        cmd.extend(["-analysisTimeoutPerFile", str(timeout)])

    if log_file:
        cmd.extend(["-log", log_file])

    print(f"Running: {' '.join(cmd[:6])}...")
    print(f"Project: {project_dir}/{project_name}")

    try:
        result = subprocess.run(cmd, timeout=timeout or 600)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("ERROR: Analysis timed out")
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted")
        return 130


def main():
    parser = argparse.ArgumentParser(
        description="Ghidra headless analysis wrapper"
    )
    parser.add_argument("binary", help="Binary to analyze")
    parser.add_argument(
        "--project-dir", "-p",
        help="Project directory (default: temp)"
    )
    parser.add_argument(
        "--script", "-s", action="append", dest="scripts",
        help="Post-analysis script (can repeat)"
    )
    parser.add_argument(
        "--script-args", "-a", nargs="*",
        help="Arguments for scripts"
    )
    parser.add_argument(
        "--script-path", "-S",
        help="Additional script search path"
    )
    parser.add_argument(
        "--no-analysis", action="store_true",
        help="Skip auto-analysis"
    )
    parser.add_argument(
        "--timeout", "-t", type=int,
        help="Analysis timeout in seconds"
    )
    parser.add_argument(
        "--log", "-l",
        help="Log file path"
    )
    parser.add_argument(
        "--keep", "-k", action="store_true",
        help="Keep project (don't use temp dir)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"ERROR: Binary not found: {args.binary}")
        sys.exit(1)

    project_dir = args.project_dir
    if not project_dir and args.keep:
        project_dir = os.path.dirname(os.path.abspath(args.binary)) or "."

    exit_code = run_headless(
        args.binary,
        project_dir=project_dir,
        scripts=args.scripts,
        script_args=args.script_args,
        script_path=args.script_path,
        no_analysis=args.no_analysis,
        timeout=args.timeout,
        log_file=args.log
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
