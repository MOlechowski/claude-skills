#!/usr/bin/env python3
"""
RLM Context Engine - Process large codebases efficiently.

Based on the Recursive Language Modeling paradigm.
Original: https://github.com/BowTiedSwan/rlm-skill
"""

import os
import glob
import json
import math
from pathlib import Path
from typing import List, Dict, Any


class RLMContext:
    """Context manager for large codebase analysis."""

    def __init__(self, root_dir: str = "."):
        self.root = Path(root_dir)
        self.index: Dict[str, str] = {}
        self.chunk_size = 5000

    def load_context(self, pattern: str = "**/*", recursive: bool = True) -> str:
        """Load files matching pattern into the index."""
        files = glob.glob(str(self.root / pattern), recursive=recursive)
        loaded_count = 0

        # Directories to skip
        skip_dirs = ['.git', '__pycache__', 'node_modules', '.venv', 'venv', 'dist', 'build']

        for f in files:
            path = Path(f)
            if path.is_file() and not any(p in str(path) for p in skip_dirs):
                try:
                    self.index[str(path)] = path.read_text(errors='ignore')
                    loaded_count += 1
                except Exception:
                    pass

        total_size = sum(len(c) for c in self.index.values())
        return f"RLM: Loaded {loaded_count} files into hidden context. Total size: {total_size} chars."

    def peek(self, query: str, context_window: int = 200) -> List[str]:
        """Search for query and return matches with surrounding context."""
        results = []

        for path, content in self.index.items():
            if query in content:
                start = 0
                while True:
                    idx = content.find(query, start)
                    if idx == -1:
                        break

                    snippet_start = max(0, idx - context_window)
                    snippet_end = min(len(content), idx + len(query) + context_window)
                    snippet = content[snippet_start:snippet_end]
                    results.append(f"[{path}]: ...{snippet}...")
                    start = idx + 1

        return results[:20]  # Limit results

    def get_chunks(self, file_pattern: str = None) -> List[Dict[str, Any]]:
        """Split indexed files into processable chunks."""
        chunks = []
        targets = [f for f in self.index.keys() if (not file_pattern or file_pattern in f)]

        for path in targets:
            content = self.index[path]
            total_chunks = math.ceil(len(content) / self.chunk_size)

            for i in range(total_chunks):
                start = i * self.chunk_size
                end = min((i + 1) * self.chunk_size, len(content))
                chunks.append({
                    "source": path,
                    "chunk_id": i,
                    "content": content[start:end]
                })

        return chunks


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RLM Context Engine")
    subparsers = parser.add_subparsers(dest="command")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan and index files")
    scan_parser.add_argument("--path", default=".", help="Root path to scan")
    scan_parser.add_argument("--pattern", default="**/*", help="Glob pattern")

    # Peek command
    peek_parser = subparsers.add_parser("peek", help="Search with context")
    peek_parser.add_argument("query", help="Search term")
    peek_parser.add_argument("--context", type=int, default=200, help="Context window size")

    # Chunk command
    chunk_parser = subparsers.add_parser("chunk", help="Get file chunks")
    chunk_parser.add_argument("--pattern", default=None, help="File pattern filter")

    args = parser.parse_args()

    ctx = RLMContext()

    if args.command == "scan":
        result = ctx.load_context(args.pattern)
        print(result)
    elif args.command == "peek":
        ctx.load_context()
        results = ctx.peek(args.query, args.context)
        print(json.dumps(results, indent=2))
    elif args.command == "chunk":
        ctx.load_context()
        chunks = ctx.get_chunks(args.pattern)
        print(json.dumps(chunks, indent=2))
    else:
        parser.print_help()
