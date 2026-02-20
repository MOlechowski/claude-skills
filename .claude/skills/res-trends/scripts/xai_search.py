#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "httpx>=0.25.0",
# ]
# ///
"""
xAI Search Script for trends-research skill

Performs Web Search, X Search, and Reddit Search using xAI Responses API.
Reads API key securely from macOS Keychain.

Usage:
    uv run xai_search.py web "search query"
    uv run xai_search.py x "search query"
    uv run xai_search.py reddit "search query"
    uv run xai_search.py all "search query"
    uv run xai_search.py all "search query" --quick
    uv run xai_search.py all "search query" --deep

Depth Control:
    --quick: Fast overview (8-12 sources per platform)
    (default): Balanced research (20-30 sources)
    --deep: Comprehensive analysis (50-70 sources)

Dependencies are managed automatically via uv (PEP 723).
"""

import subprocess
import sys
import os
import argparse
import json
import re
from datetime import datetime, timedelta

import httpx


# xAI Responses API endpoint
XAI_RESPONSES_URL = "https://api.x.ai/v1/responses"
XAI_MODEL = "grok-4-1-fast-reasoning"

# Depth configurations: (min, max) items to request
DEPTH_CONFIG = {
    "quick": {
        "description": "Fast overview",
        "range": (8, 12),
    },
    "default": {
        "description": "Balanced research",
        "range": (20, 30),
    },
    "deep": {
        "description": "Comprehensive analysis",
        "range": (50, 70),
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


def call_xai_responses(api_key: str, prompt: str, tools: list, timeout: int = 120) -> dict:
    """Call xAI Responses API with specified tools."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": XAI_MODEL,
        "tools": tools,
        "input": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
    }

    with httpx.Client(timeout=timeout) as client:
        response = client.post(XAI_RESPONSES_URL, json=payload, headers=headers)
        return response.json()


def extract_output_text(response: dict) -> str:
    """Extract text content from xAI Responses API response."""
    output_text = ""

    if "error" in response and response["error"]:
        error = response["error"]
        err_msg = error.get("message", str(error)) if isinstance(error, dict) else str(error)
        print(f"API Error: {err_msg}", file=sys.stderr)
        return ""

    if "output" in response:
        output = response["output"]
        if isinstance(output, str):
            output_text = output
        elif isinstance(output, list):
            for item in output:
                if isinstance(item, dict):
                    if item.get("type") == "message":
                        content = item.get("content", [])
                        for c in content:
                            if isinstance(c, dict) and c.get("type") == "output_text":
                                output_text = c.get("text", "")
                                break
                    elif "text" in item:
                        output_text = item["text"]
                elif isinstance(item, str):
                    output_text = item
                if output_text:
                    break

    # Fallback: check for choices (older format)
    if not output_text and "choices" in response:
        for choice in response["choices"]:
            if "message" in choice:
                output_text = choice["message"].get("content", "")
                break

    return output_text


def web_search(query: str, api_key: str, depth: str = "default") -> dict:
    """Perform web search using xAI Responses API."""
    min_items, max_items = DEPTH_CONFIG[depth]["range"]

    prompt = f"""Search the web for: {query}

Find {min_items}-{max_items} high-quality, relevant results.

Return comprehensive results with:
- Source URLs
- Key findings and quotes
- Publication dates when available
- Engagement metrics if visible

Focus on authoritative sources, news articles, and documentation."""

    tools = [{"type": "web_search"}]
    response = call_xai_responses(api_key, prompt, tools, timeout=90 if depth == "quick" else 120)

    return {
        "type": "web",
        "query": query,
        "depth": depth,
        "content": extract_output_text(response),
        "raw_response": response,
    }


def reddit_search(query: str, api_key: str, depth: str = "default") -> dict:
    """Perform Reddit search using xAI Responses API with web_search."""
    min_items, max_items = DEPTH_CONFIG[depth]["range"]

    prompt = f"""Search Reddit for discussions about: {query}

Use these search strategies:
1. "site:reddit.com {query}"
2. "reddit {query}"

Find {min_items}-{max_items} relevant Reddit threads.

For each thread, include:
- Thread title
- Subreddit (r/name)
- URL (must contain reddit.com/r/ and /comments/)
- Upvote count if visible
- Key discussion points
- Top comments/opinions

Prioritize highly-upvoted threads with substantive discussions.
Exclude: developers.reddit.com, business.reddit.com"""

    tools = [{"type": "web_search"}]
    response = call_xai_responses(api_key, prompt, tools, timeout=90 if depth == "quick" else 120)

    return {
        "type": "reddit",
        "query": query,
        "depth": depth,
        "content": extract_output_text(response),
        "raw_response": response,
    }


def x_search(query: str, api_key: str, days_back: int = 30, depth: str = "default") -> dict:
    """Perform X/Twitter search using xAI Responses API."""
    min_items, max_items = DEPTH_CONFIG[depth]["range"]
    from_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
    to_date = datetime.now().strftime("%Y-%m-%d")

    prompt = f"""Search X/Twitter for posts about: {query}

Focus on posts from {from_date} to {to_date}.
Find {min_items}-{max_items} high-quality, relevant posts.

For each post, include:
- Post text content
- Author handle (@username)
- URL (https://x.com/user/status/...)
- Date (YYYY-MM-DD)
- Engagement: likes, reposts, replies
- Why it's relevant

Prioritize:
- Posts with substantive content (not just links)
- High engagement posts
- Diverse voices and perspectives
- Expert opinions and debates"""

    tools = [{"type": "x_search"}]
    response = call_xai_responses(api_key, prompt, tools, timeout=90 if depth == "quick" else 150)

    return {
        "type": "x",
        "query": query,
        "from_date": from_date,
        "depth": depth,
        "content": extract_output_text(response),
        "raw_response": response,
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
        print(f"Depth: {results['depth']} ({DEPTH_CONFIG[results['depth']]['description']})")
    print(f"{'='*60}\n")

    if results['content']:
        print(results['content'])
    else:
        print("No results found or API error occurred.")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="xAI Search Script for trends-research skill",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uv run xai_search.py web 'AI trends 2025'
  uv run xai_search.py x 'what people are saying about Python'
  uv run xai_search.py reddit 'best Python frameworks'
  uv run xai_search.py all 'machine learning trends'
  uv run xai_search.py all 'machine learning trends' --quick
  uv run xai_search.py all 'machine learning trends' --deep
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
        print("Usage: uv run xai_search.py <type> <query> [--quick|--deep]")
        print("  type: web, x, reddit, or all")
        print("  query: your search query")
        print("\nDepth Control:")
        print("  --quick: Fast overview (8-12 sources)")
        print("  (default): Balanced research (20-30 sources)")
        print("  --deep: Comprehensive analysis (50-70 sources)")
        print("\nExamples:")
        print("  uv run xai_search.py web 'AI trends 2025'")
        print("  uv run xai_search.py all 'machine learning' --quick")
        print("  uv run xai_search.py all 'machine learning' --deep")
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

    except httpx.HTTPStatusError as e:
        print(f"HTTP Error: {e.response.status_code} - {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"Error during search: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
