#!/usr/bin/env python3
"""
xAI Search Script for trends-research skill

Performs Web Search, X Search, and Reddit Search using xAI API.
Reads API key securely from macOS Keychain.

Usage:
    python3 xai_search.py web "search query"
    python3 xai_search.py x "search query"
    python3 xai_search.py reddit "search query"
    python3 xai_search.py all "search query"
    python3 xai_search.py all "search query" --quick
    python3 xai_search.py all "search query" --deep

Depth Control:
    --quick: Fast overview (8-12 sources per platform)
    (default): Balanced research (20-30 sources)
    --deep: Comprehensive analysis (50-70 sources)

Requirements:
    pip install openai
"""

import subprocess
import sys
import os
import argparse
from datetime import datetime, timedelta


# Depth configurations
DEPTH_CONFIG = {
    "quick": {
        "description": "Fast overview",
        "max_results": "8-12 sources per platform",
        "instruction": "Provide a quick overview with the top 8-12 most relevant results."
    },
    "default": {
        "description": "Balanced research",
        "max_results": "20-30 sources per platform",
        "instruction": "Provide comprehensive results with 20-30 relevant sources."
    },
    "deep": {
        "description": "Comprehensive analysis",
        "max_results": "50-70 sources per platform",
        "instruction": "Provide exhaustive results with 50-70 sources. Include niche discussions and lesser-known perspectives."
    }
}


def get_api_key() -> str:
    """Retrieve xAI API key from macOS Keychain."""
    keychain_path = os.path.expanduser("~/Library/Keychains/claude-keys.keychain-db")

    try:
        result = subprocess.run(
            [
                "security", "find-generic-password",
                "-s", "xai-api",
                "-w",
                keychain_path
            ],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if "could not be found" in e.stderr:
            print("Error: xAI API key not found in keychain.")
            print("\nSetup instructions:")
            print("1. security create-keychain -p 'YourPassword' ~/Library/Keychains/claude-keys.keychain-db")
            print("2. security list-keychains -s ~/Library/Keychains/claude-keys.keychain-db ~/Library/Keychains/login.keychain-db")
            print("3. echo -n 'Enter xAI API key: ' && read -s key && security add-generic-password -s 'xai-api' -a \"$USER\" -w \"$key\" ~/Library/Keychains/claude-keys.keychain-db && unset key")
            sys.exit(1)
        elif "User interaction is not allowed" in e.stderr:
            print("Error: Keychain is locked.")
            print("\nUnlock with:")
            print("security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db")
            sys.exit(1)
        else:
            print(f"Error accessing keychain: {e.stderr}")
            sys.exit(1)


def get_openai_client(api_key: str):
    """Get OpenAI client configured for xAI."""
    try:
        from openai import OpenAI
    except ImportError:
        print("Error: openai package required. Install with: pip install openai")
        sys.exit(1)

    return OpenAI(
        api_key=api_key,
        base_url="https://api.x.ai/v1"
    )


def web_search(query: str, api_key: str, depth: str = "default") -> dict:
    """Perform web search using xAI API."""
    client = get_openai_client(api_key)
    depth_instruction = DEPTH_CONFIG[depth]["instruction"]

    response = client.chat.completions.create(
        model="grok-3-latest",
        messages=[
            {
                "role": "system",
                "content": f"You are a research assistant. Search the web and provide comprehensive, factual results with source citations. Include engagement metrics where available. {depth_instruction}"
            },
            {
                "role": "user",
                "content": f"Search the web for: {query}"
            }
        ],
        tools=[{"type": "web_search"}]
    )

    return {
        "type": "web",
        "query": query,
        "depth": depth,
        "content": response.choices[0].message.content,
        "citations": getattr(response, 'citations', [])
    }


def reddit_search(query: str, api_key: str, depth: str = "default") -> dict:
    """Perform Reddit search using xAI Web Search with site filter."""
    client = get_openai_client(api_key)
    depth_instruction = DEPTH_CONFIG[depth]["instruction"]

    response = client.chat.completions.create(
        model="grok-3-latest",
        messages=[
            {
                "role": "system",
                "content": f"You are a research assistant. Search Reddit for discussions, recommendations, and community opinions. Include upvote counts and engagement where visible. Prioritize highly-upvoted threads. {depth_instruction}"
            },
            {
                "role": "user",
                "content": f"Search Reddit (site:reddit.com) for discussions about: {query}"
            }
        ],
        tools=[{"type": "web_search"}]
    )

    return {
        "type": "reddit",
        "query": query,
        "depth": depth,
        "content": response.choices[0].message.content,
        "citations": getattr(response, 'citations', [])
    }


def x_search(query: str, api_key: str, days_back: int = 30, depth: str = "default") -> dict:
    """Perform X/Twitter search using xAI API."""
    client = get_openai_client(api_key)
    depth_instruction = DEPTH_CONFIG[depth]["instruction"]

    from_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

    response = client.chat.completions.create(
        model="grok-3-latest",
        messages=[
            {
                "role": "system",
                "content": f"You are a research assistant. Search X/Twitter and provide comprehensive results about trending discussions. Include engagement metrics (likes, retweets, replies) where available. {depth_instruction}"
            },
            {
                "role": "user",
                "content": f"Search X/Twitter for posts and discussions about: {query} (from {from_date} to today)"
            }
        ],
        tools=[{"type": "x_search"}]
    )

    return {
        "type": "x",
        "query": query,
        "from_date": from_date,
        "depth": depth,
        "content": response.choices[0].message.content,
        "citations": getattr(response, 'citations', [])
    }


def print_results(results: dict):
    """Print search results in a readable format."""
    type_names = {
        "web": "WEB",
        "x": "X/TWITTER",
        "reddit": "REDDIT"
    }

    print(f"\n{'='*60}")
    print(f"Search Type: {type_names.get(results['type'], results['type'].upper())}")
    print(f"Query: {results['query']}")
    if 'from_date' in results:
        print(f"Date Range: {results['from_date']} to today")
    if 'depth' in results:
        print(f"Depth: {results['depth']} ({DEPTH_CONFIG[results['depth']]['max_results']})")
    print(f"{'='*60}\n")

    print(results['content'])

    if results.get('citations'):
        print(f"\n{'='*60}")
        print("Sources:")
        for i, citation in enumerate(results['citations'], 1):
            print(f"  {i}. {citation}")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="xAI Search Script for trends-research skill",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 xai_search.py web 'AI trends 2025'
  python3 xai_search.py x 'what people are saying about Python'
  python3 xai_search.py reddit 'best Python frameworks'
  python3 xai_search.py all 'machine learning trends'
  python3 xai_search.py all 'machine learning trends' --quick
  python3 xai_search.py all 'machine learning trends' --deep
        """
    )

    parser.add_argument("type", choices=["web", "x", "reddit", "all"],
                        help="Search type: web, x, reddit, or all")
    parser.add_argument("query", nargs="+", help="Search query")

    depth_group = parser.add_mutually_exclusive_group()
    depth_group.add_argument("--quick", action="store_true",
                             help="Fast overview (8-12 sources)")
    depth_group.add_argument("--deep", action="store_true",
                             help="Comprehensive analysis (50-70 sources)")

    return parser.parse_args()


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 xai_search.py <type> <query> [--quick|--deep]")
        print("  type: web, x, reddit, or all")
        print("  query: your search query")
        print("\nDepth Control:")
        print("  --quick: Fast overview (8-12 sources)")
        print("  (default): Balanced research (20-30 sources)")
        print("  --deep: Comprehensive analysis (50-70 sources)")
        print("\nExamples:")
        print("  python3 xai_search.py web 'AI trends 2025'")
        print("  python3 xai_search.py all 'machine learning' --quick")
        print("  python3 xai_search.py all 'machine learning' --deep")
        sys.exit(1)

    args = parse_args()
    query = " ".join(args.query)

    # Determine depth
    if args.quick:
        depth = "quick"
    elif args.deep:
        depth = "deep"
    else:
        depth = "default"

    # Get API key from keychain
    api_key = get_api_key()

    print(f"Searching for: {query}")
    print(f"Depth: {depth} ({DEPTH_CONFIG[depth]['description']})")

    try:
        if args.type == "web":
            results = web_search(query, api_key, depth)
            print_results(results)

        elif args.type == "x":
            results = x_search(query, api_key, depth=depth)
            print_results(results)

        elif args.type == "reddit":
            results = reddit_search(query, api_key, depth)
            print_results(results)

        elif args.type == "all":
            print("\n" + "="*60)
            print(f"MULTI-SOURCE RESEARCH ({depth.upper()})")
            print("="*60)

            print("\n--- Reddit Discussions ---")
            reddit_results = reddit_search(query, api_key, depth)
            print_results(reddit_results)

            print("\n--- X/Twitter Posts ---")
            x_results = x_search(query, api_key, depth=depth)
            print_results(x_results)

            print("\n--- Web Articles ---")
            web_results = web_search(query, api_key, depth)
            print_results(web_results)

            print("\n" + "="*60)
            print("RESEARCH COMPLETE - Ready for synthesis")
            print("="*60)

    except Exception as e:
        print(f"Error during search: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
