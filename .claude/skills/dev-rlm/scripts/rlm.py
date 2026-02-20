#!/usr/bin/env python3
"""
RLM Context Engine - Query large codebases without loading into memory.

Streaming filesystem query engine aligned with the RLM paradigm:
"Context is an external resource, not a local variable."

Based on: Recursive Language Models (arXiv:2512.24601)
Original skill: https://github.com/BowTiedSwan/rlm-skill
"""

import argparse
import itertools
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterator, List, Optional


SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".eggs",
    "*.egg-info",
}

EXTENSION_MAP = {
    "py": ".py",
    "python": ".py",
    "go": ".go",
    "golang": ".go",
    "js": ".js",
    "javascript": ".js",
    "ts": ".ts",
    "typescript": ".ts",
    "tsx": ".tsx",
    "jsx": ".jsx",
    "rs": ".rs",
    "rust": ".rs",
    "rb": ".rb",
    "ruby": ".rb",
    "java": ".java",
    "c": ".c",
    "cpp": ".cpp",
    "h": ".h",
    "md": ".md",
    "markdown": ".md",
    "json": ".json",
    "yaml": ".yaml",
    "yml": ".yml",
    "toml": ".toml",
    "sh": ".sh",
    "bash": ".sh",
    "sql": ".sql",
    "html": ".html",
    "css": ".css",
}


class RLMEngine:
    """Streaming filesystem query engine. Never loads all files into memory."""

    def __init__(self, root_dir: str = "."):
        self.root = Path(root_dir).resolve()

    def _walk_files(
        self, pattern: Optional[str] = None, file_type: Optional[str] = None
    ) -> Iterator[Path]:
        """Yield matching file paths without reading content."""
        ext = EXTENSION_MAP.get(file_type, f".{file_type}") if file_type else None

        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [
                d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")
            ]
            for fname in sorted(filenames):
                path = Path(dirpath) / fname
                if ext and path.suffix != ext:
                    continue
                if pattern and not path.match(pattern):
                    continue
                if path.is_file():
                    yield path

    def _is_text_file(self, path: Path) -> bool:
        """Quick check if file is likely text (not binary)."""
        try:
            with open(path, "rb") as f:
                chunk = f.read(1024)
                return b"\x00" not in chunk
        except (OSError, PermissionError):
            return False

    def stats(self, file_type: Optional[str] = None) -> Dict:
        """Codebase overview without reading file content."""
        by_ext: Dict[str, int] = {}
        top_dirs: Dict[str, int] = {}
        total = 0

        for path in self._walk_files(file_type=file_type):
            total += 1
            ext = path.suffix or "(no ext)"
            by_ext[ext] = by_ext.get(ext, 0) + 1

            rel = path.relative_to(self.root)
            top_dir = rel.parts[0] if len(rel.parts) > 1 else "."
            top_dirs[top_dir] = top_dirs.get(top_dir, 0) + 1

        sorted_ext = dict(sorted(by_ext.items(), key=lambda x: -x[1]))
        sorted_dirs = dict(sorted(top_dirs.items(), key=lambda x: -x[1]))

        tree_lines = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [
                d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")
            ]
            rel = Path(dirpath).relative_to(self.root)
            depth = len(rel.parts)
            if depth > 2:
                dirnames.clear()
                continue
            indent = "  " * depth
            name = rel.name or str(self.root.name)
            tree_lines.append(f"{indent}{name}/")

        return {
            "root": str(self.root),
            "total_files": total,
            "by_extension": sorted_ext,
            "top_dirs": sorted_dirs,
            "tree_depth_2": "\n".join(tree_lines[:50]),
        }

    def grep(
        self,
        pattern: str,
        file_type: Optional[str] = None,
        max_results: int = 50,
    ) -> List[Dict]:
        """Regex search across files. Streams one file at a time."""
        regex = re.compile(pattern)
        results = []

        for path in self._walk_files(file_type=file_type):
            if not self._is_text_file(path):
                continue
            try:
                with open(path, errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        if regex.search(line):
                            results.append(
                                {
                                    "file": str(path.relative_to(self.root)),
                                    "line": line_num,
                                    "match": line.rstrip()[:200],
                                }
                            )
                            if len(results) >= max_results:
                                return results
            except (OSError, PermissionError):
                continue
        return results

    def peek(
        self,
        query: str,
        context_window: int = 200,
        file_type: Optional[str] = None,
        max_results: int = 20,
    ) -> List[Dict]:
        """Substring search with surrounding context. Snaps to line boundaries."""
        results = []

        for path in self._walk_files(file_type=file_type):
            if not self._is_text_file(path):
                continue
            try:
                content = path.read_text(errors="ignore")
            except (OSError, PermissionError):
                continue

            start = 0
            while True:
                idx = content.find(query, start)
                if idx == -1:
                    break

                snippet_start = max(0, idx - context_window)
                snippet_end = min(len(content), idx + len(query) + context_window)

                # Snap to line boundaries
                while snippet_start > 0 and content[snippet_start - 1] != "\n":
                    snippet_start -= 1
                while snippet_end < len(content) and content[snippet_end] != "\n":
                    snippet_end += 1

                results.append(
                    {
                        "file": str(path.relative_to(self.root)),
                        "offset": idx,
                        "snippet": content[snippet_start:snippet_end],
                    }
                )
                if len(results) >= max_results:
                    return results
                start = idx + 1

        return results

    def read(self, file_path: str, lines: Optional[str] = None) -> str:
        """Read a single file, optionally a line range (e.g., '50-100')."""
        path = self.root / file_path
        if not path.is_file():
            return f"Error: {file_path} not found"

        with open(path, errors="ignore") as f:
            if lines:
                parts = lines.split("-")
                start = int(parts[0])
                end = int(parts[1]) if len(parts) > 1 else start
                selected = list(itertools.islice(f, start - 1, end))
                return "".join(selected)
            return f.read()

    def chunk(
        self,
        pattern: Optional[str] = None,
        file_type: Optional[str] = None,
        size: int = 15,
    ) -> List[Dict]:
        """Partition file paths into groups for agent distribution. Never reads content."""
        files = list(self._walk_files(pattern=pattern, file_type=file_type))
        partitions = []

        for i in range(0, len(files), size):
            batch = files[i : i + size]
            partitions.append(
                {
                    "partition_id": len(partitions),
                    "files": [str(f.relative_to(self.root)) for f in batch],
                    "count": len(batch),
                }
            )

        return partitions


def _output_result(result, output_path: Optional[str] = None):
    """Write result to file or stdout."""
    if isinstance(result, str):
        text = result
    else:
        text = json.dumps(result, indent=2)

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(text)
        print(f"Written to {output_path}")
    else:
        print(text)


def main():
    parser = argparse.ArgumentParser(
        description="RLM Context Engine - streaming filesystem queries"
    )
    subparsers = parser.add_subparsers(dest="command")

    # stats
    p_stats = subparsers.add_parser("stats", help="Codebase overview (no file reads)")
    p_stats.add_argument("--type", dest="file_type", help="Filter by file type (py, go, js...)")
    p_stats.add_argument("--output", help="Write result to file")
    p_stats.add_argument("--path", default=".", help="Root path")

    # grep
    p_grep = subparsers.add_parser("grep", help="Regex search across files (streaming)")
    p_grep.add_argument("pattern", help="Regex pattern")
    p_grep.add_argument("--type", dest="file_type", help="Filter by file type")
    p_grep.add_argument("--max", dest="max_results", type=int, default=50, help="Max results")
    p_grep.add_argument("--output", help="Write result to file")
    p_grep.add_argument("--path", default=".", help="Root path")

    # peek
    p_peek = subparsers.add_parser("peek", help="Substring search with context")
    p_peek.add_argument("query", help="Search term")
    p_peek.add_argument("--context", type=int, default=200, help="Context window chars")
    p_peek.add_argument("--type", dest="file_type", help="Filter by file type")
    p_peek.add_argument("--max", dest="max_results", type=int, default=20, help="Max results")
    p_peek.add_argument("--output", help="Write result to file")
    p_peek.add_argument("--path", default=".", help="Root path")

    # read
    p_read = subparsers.add_parser("read", help="Read a single file or line range")
    p_read.add_argument("file", help="File path (relative to root)")
    p_read.add_argument("--lines", help="Line range, e.g. '50-100'")
    p_read.add_argument("--output", help="Write result to file")
    p_read.add_argument("--path", default=".", help="Root path")

    # chunk
    p_chunk = subparsers.add_parser("chunk", help="Partition files for agent distribution")
    p_chunk.add_argument("--pattern", help="Glob pattern filter (e.g. '*.py')")
    p_chunk.add_argument("--type", dest="file_type", help="Filter by file type")
    p_chunk.add_argument("--size", type=int, default=15, help="Files per partition")
    p_chunk.add_argument("--output", help="Write result to file")
    p_chunk.add_argument("--path", default=".", help="Root path")

    # scan (deprecated)
    subparsers.add_parser("scan", help="[DEPRECATED] Use 'stats' instead")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        print("DEPRECATED: 'scan' loads all files into memory.")
        print("Use 'stats' instead for a streaming codebase overview.")
        print("\nExample: python3 rlm.py stats --type py")
        sys.exit(0)

    engine = RLMEngine(getattr(args, "path", "."))
    output = getattr(args, "output", None)

    if args.command == "stats":
        result = engine.stats(file_type=args.file_type)
        _output_result(result, output)
    elif args.command == "grep":
        result = engine.grep(args.pattern, file_type=args.file_type, max_results=args.max_results)
        _output_result(result, output)
    elif args.command == "peek":
        result = engine.peek(
            args.query,
            context_window=args.context,
            file_type=args.file_type,
            max_results=args.max_results,
        )
        _output_result(result, output)
    elif args.command == "read":
        result = engine.read(args.file, lines=args.lines)
        _output_result(result, output)
    elif args.command == "chunk":
        result = engine.chunk(
            pattern=args.pattern, file_type=args.file_type, size=args.size
        )
        _output_result(result, output)


if __name__ == "__main__":
    main()
