#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "httpx>=0.25.0",
# ]
# ///
"""
xAI Search Script for deep-research skill

Performs Web, X, Reddit, GitHub, and Hacker News searches using xAI Responses API.
Reads API key securely from macOS Keychain.

Usage:
    uv run xai_search.py web "search query"
    uv run xai_search.py x "search query"
    uv run xai_search.py reddit "search query"
    uv run xai_search.py github "search query"
    uv run xai_search.py hn "search query"
    uv run xai_search.py all "search query"
    uv run xai_search.py all "search query" --quick
    uv run xai_search.py all "search query" --deep
    uv run xai_search.py web "search query" --json

Depth Control:
    --quick: Fast overview (8-12 sources per platform)
    (default): Balanced research (20-30 sources)
    --deep: Comprehensive analysis (50-70 sources)

Output:
    (default): Human-readable formatted text
    --json: Structured JSON for programmatic consumption

Dependencies are managed automatically via uv (PEP 723).
"""

import subprocess
import sys
import os
import argparse
import json
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
            print("Error: xAI API key not found in keychain.", file=sys.stderr)
            print("\nSetup instructions:", file=sys.stderr)
            print("1. security create-keychain -p 'YourPassword' ~/Library/Keychains/claude-keys.keychain-db", file=sys.stderr)
            print("2. security list-keychains -s ~/Library/Keychains/claude-keys.keychain-db ~/Library/Keychains/login.keychain-db", file=sys.stderr)
            print("3. echo -n 'Enter xAI API key: ' && read -s key && security add-generic-password -s 'xai-api' -a \"$USER\" -w \"$key\" ~/Library/Keychains/claude-keys.keychain-db && unset key", file=sys.stderr)
            sys.exit(1)
        elif "User interaction is not allowed" in e.stderr:
            print("Error: Keychain is locked.", file=sys.stderr)
            print("\nUnlock with:", file=sys.stderr)
            print("security unlock-keychain ~/Library/Keychains/claude-keys.keychain-db", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Error accessing keychain: {e.stderr}", file=sys.stderr)
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


def github_search(query: str, api_key: str, depth: str = "default") -> dict:
    """Perform GitHub search using xAI Responses API with web_search."""
    min_items, max_items = DEPTH_CONFIG[depth]["range"]

    prompt = f"""Search GitHub for repositories and projects related to: {query}

Use these search strategies:
1. "site:github.com {query}"
2. "github {query} repository"
3. "awesome {query} site:github.com" (for curated lists)

Find {min_items}-{max_items} relevant GitHub repositories or resources.

For each result, include:
- Repository name (owner/repo)
- URL (https://github.com/owner/repo)
- Description
- Stars count if visible
- Last activity / recent commits if visible
- Primary language
- Why it's relevant to the query

Prioritize:
- Actively maintained repositories (recent commits)
- High star count (community validation)
- Good documentation
- Relevant to the specific query topic"""

    tools = [{"type": "web_search"}]
    response = call_xai_responses(api_key, prompt, tools, timeout=90 if depth == "quick" else 120)

    return {
        "type": "github",
        "query": query,
        "depth": depth,
        "content": extract_output_text(response),
        "raw_response": response,
    }


def hn_search(query: str, api_key: str, depth: str = "default") -> dict:
    """Perform Hacker News search using xAI Responses API with web_search."""
    min_items, max_items = DEPTH_CONFIG[depth]["range"]

    prompt = f"""Search Hacker News for discussions about: {query}

Use these search strategies:
1. "site:news.ycombinator.com {query}"
2. "hacker news {query}"
3. "ycombinator {query}"

Find {min_items}-{max_items} relevant Hacker News threads.

For each thread, include:
- Thread title
- URL (news.ycombinator.com/item?id=...)
- Points/upvotes if visible
- Number of comments if visible
- Key discussion points and notable comments
- Whether it's a "Show HN", "Ask HN", or regular submission

Prioritize:
- High-point threads (100+ points)
- Substantive technical discussions
- Recent threads when possible
- "Show HN" posts for project launches
- "Ask HN" posts for community opinions"""

    tools = [{"type": "web_search"}]
    response = call_xai_responses(api_key, prompt, tools, timeout=90 if depth == "quick" else 120)

    return {
        "type": "hn",
        "query": query,
        "depth": depth,
        "content": extract_output_text(response),
        "raw_response": response,
    }


def print_results(results: dict, json_output: bool = False):
    """Print search results in readable or JSON format."""
    if json_output:
        output = {
            "type": results["type"],
            "query": results["query"],
            "depth": results.get("depth", "default"),
            "content": results["content"],
            "timestamp": datetime.now().isoformat(),
        }
        if "from_date" in results:
            output["from_date"] = results["from_date"]
        print(json.dumps(output, indent=2))
        return

    type_names = {
        "web": "WEB",
        "x": "X/TWITTER",
        "reddit": "REDDIT",
        "github": "GITHUB",
        "hn": "HACKER NEWS",
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
        description="xAI Search Script for deep-research skill",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uv run xai_search.py web 'AI trends 2026'
  uv run xai_search.py x 'what people are saying about Python'
  uv run xai_search.py reddit 'best Python frameworks'
  uv run xai_search.py github 'machine learning framework'
  uv run xai_search.py hn 'new programming languages'
  uv run xai_search.py all 'machine learning trends'
  uv run xai_search.py all 'machine learning trends' --quick
  uv run xai_search.py all 'machine learning trends' --deep
  uv run xai_search.py web 'AI agents' --json
        """
    )

    parser.add_argument("type", choices=["web", "x", "reddit", "github", "hn", "all"],
                        help="Search type: web, x, reddit, github, hn, or all")
    parser.add_argument("query", nargs="+", help="Search query")

    depth_group = parser.add_mutually_exclusive_group()
    depth_group.add_argument("--quick", action="store_true",
                             help="Fast overview (8-12 sources)")
    depth_group.add_argument("--deep", action="store_true",
                             help="Comprehensive analysis (50-70 sources)")

    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="Output structured JSON instead of formatted text")

    return parser.parse_args()


def main():
    if len(sys.argv) < 3:
        print("Usage: uv run xai_search.py <type> <query> [--quick|--deep] [--json]")
        print("  type: web, x, reddit, github, hn, or all")
        print("  query: your search query")
        print("\nDepth Control:")
        print("  --quick: Fast overview (8-12 sources)")
        print("  (default): Balanced research (20-30 sources)")
        print("  --deep: Comprehensive analysis (50-70 sources)")
        print("\nOutput:")
        print("  (default): Human-readable formatted text")
        print("  --json: Structured JSON for programmatic consumption")
        print("\nExamples:")
        print("  uv run xai_search.py web 'AI trends 2026'")
        print("  uv run xai_search.py github 'machine learning framework'")
        print("  uv run xai_search.py hn 'new programming languages'")
        print("  uv run xai_search.py all 'machine learning' --quick")
        print("  uv run xai_search.py all 'machine learning' --deep --json")
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

    json_output = args.json_output

    # Get API key from keychain
    api_key = get_api_key()

    if not json_output:
        print(f"Searching for: {query}")
        print(f"Depth: {depth} ({DEPTH_CONFIG[depth]['description']})")

    search_functions = {
        "web": lambda: web_search(query, api_key, depth),
        "x": lambda: x_search(query, api_key, depth=depth),
        "reddit": lambda: reddit_search(query, api_key, depth),
        "github": lambda: github_search(query, api_key, depth),
        "hn": lambda: hn_search(query, api_key, depth),
    }

    try:
        if args.type == "all":
            if json_output:
                all_results = {}
                for search_type in ["reddit", "x", "github", "hn", "web"]:
                    results = search_functions[search_type]()
                    all_results[search_type] = {
                        "query": results["query"],
                        "depth": results.get("depth", "default"),
                        "content": results["content"],
                    }
                    if "from_date" in results:
                        all_results[search_type]["from_date"] = results["from_date"]
                output = {
                    "type": "all",
                    "query": query,
                    "depth": depth,
                    "timestamp": datetime.now().isoformat(),
                    "results": all_results,
                }
                print(json.dumps(output, indent=2))
            else:
                print("\n" + "="*60)
                print(f"MULTI-SOURCE RESEARCH ({depth.upper()})")
                print("="*60)

                print("\n--- Reddit Discussions ---")
                reddit_results = search_functions["reddit"]()
                print_results(reddit_results)

                print("\n--- X/Twitter Posts ---")
                x_results = search_functions["x"]()
                print_results(x_results)

                print("\n--- GitHub Repositories ---")
                github_results = search_functions["github"]()
                print_results(github_results)

                print("\n--- Hacker News Discussions ---")
                hn_results = search_functions["hn"]()
                print_results(hn_results)

                print("\n--- Web Articles ---")
                web_results = search_functions["web"]()
                print_results(web_results)

                print("\n" + "="*60)
                print("RESEARCH COMPLETE - Ready for synthesis")
                print("="*60)
        else:
            results = search_functions[args.type]()
            print_results(results, json_output)

    except httpx.HTTPStatusError as e:
        print(f"HTTP Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error during search: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
