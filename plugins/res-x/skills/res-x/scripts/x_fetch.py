#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "httpx>=0.25.0",
# ]
# ///
"""
X/Twitter content fetcher and search tool.

Fetches tweets, articles, and other X content by URL, or searches X
using xAI Responses API. Reads API key from macOS Keychain.

Usage:
    uv run x_fetch.py fetch "https://x.com/user/status/123"
    uv run x_fetch.py fetch "https://x.com/i/article/456"
    uv run x_fetch.py fetch "url1" "url2" "url3"
    uv run x_fetch.py fetch "url1" "url2" --single
    uv run x_fetch.py search "query terms"
    uv run x_fetch.py search "query terms" --quick
    uv run x_fetch.py fetch "url" --json
    uv run x_fetch.py search "query" --json

Dependencies are managed automatically via uv (PEP 723).
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta

import httpx

XAI_RESPONSES_URL = "https://api.x.ai/v1/responses"
XAI_MODEL = "grok-4-1-fast-reasoning"
CHUNK_SIZE = 3

TWEET_PATTERN = re.compile(
    r"https?://(?:x\.com|twitter\.com)/(\w+)/status/(\d+)"
)
ARTICLE_PATTERN = re.compile(
    r"https?://(?:x\.com|twitter\.com)/i/article/([\w\-]+)"
)


def get_api_key() -> str:
    """Retrieve xAI API key from macOS Keychain."""
    keychain_path = os.path.expanduser(
        "~/Library/Keychains/claude-keys.keychain-db"
    )

    try:
        result = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-s",
                "xai-api",
                "-w",
                keychain_path,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if "could not be found" in e.stderr:
            print("Error: xAI API key not found in keychain.", file=sys.stderr)
            print("\nSetup instructions:", file=sys.stderr)
            print(
                "1. security create-keychain -p 'YourPassword' "
                "~/Library/Keychains/claude-keys.keychain-db",
                file=sys.stderr,
            )
            print(
                "2. security list-keychains -s "
                "~/Library/Keychains/claude-keys.keychain-db "
                "~/Library/Keychains/login.keychain-db",
                file=sys.stderr,
            )
            print(
                '3. echo -n "Enter xAI API key: " && read -s key && '
                "security add-generic-password -s 'xai-api' -a \"$USER\" "
                '-w "$key" ~/Library/Keychains/claude-keys.keychain-db '
                "&& unset key",
                file=sys.stderr,
            )
            sys.exit(1)
        elif "User interaction is not allowed" in e.stderr:
            print("Error: Keychain is locked.", file=sys.stderr)
            print(
                "\nUnlock with: security unlock-keychain "
                "~/Library/Keychains/claude-keys.keychain-db",
                file=sys.stderr,
            )
            sys.exit(1)
        else:
            print(f"Error accessing keychain: {e.stderr}", file=sys.stderr)
            sys.exit(1)


def call_xai_responses(
    api_key: str, prompt: str, tools: list, timeout: int = 120
) -> dict:
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
        response = client.post(
            XAI_RESPONSES_URL, json=payload, headers=headers
        )
        return response.json()


def extract_output_text(response: dict) -> str:
    """Extract text content from xAI Responses API response."""
    output_text = ""

    if "error" in response and response["error"]:
        error = response["error"]
        err_msg = (
            error.get("message", str(error))
            if isinstance(error, dict)
            else str(error)
        )
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
                            if (
                                isinstance(c, dict)
                                and c.get("type") == "output_text"
                            ):
                                output_text = c.get("text", "")
                                break
                    elif "text" in item:
                        output_text = item["text"]
                elif isinstance(item, str):
                    output_text = item
                if output_text:
                    break

    if not output_text and "choices" in response:
        for choice in response["choices"]:
            if "message" in choice:
                output_text = choice["message"].get("content", "")
                break

    return output_text


def normalize_url(url: str) -> str:
    """Normalize X/Twitter URL to canonical form."""
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    url = url.replace("twitter.com", "x.com")
    tweet_match = TWEET_PATTERN.search(url)
    if tweet_match:
        username, tweet_id = tweet_match.groups()
        return f"https://x.com/{username}/status/{tweet_id}"
    article_match = ARTICLE_PATTERN.search(url)
    if article_match:
        article_id = article_match.group(1)
        return f"https://x.com/i/article/{article_id}"
    return url


def parse_urls(args: list) -> list:
    """Extract and validate X/Twitter URLs from arguments."""
    parsed = []
    skipped = []
    for arg in args:
        tweet_match = TWEET_PATTERN.search(arg)
        if tweet_match:
            username, tweet_id = tweet_match.groups()
            parsed.append(
                {
                    "url": normalize_url(arg),
                    "type": "tweet",
                    "username": username,
                    "tweet_id": tweet_id,
                }
            )
            continue
        article_match = ARTICLE_PATTERN.search(arg)
        if article_match:
            article_id = article_match.group(1)
            parsed.append(
                {
                    "url": normalize_url(arg),
                    "type": "article",
                    "article_id": article_id,
                }
            )
            continue
        skipped.append(arg)

    if skipped:
        print(
            f"Skipped {len(skipped)} invalid URL(s): {', '.join(skipped)}",
            file=sys.stderr,
        )

    return parsed


def chunk_urls(urls: list, size: int = CHUNK_SIZE) -> list:
    """Split URL list into chunks."""
    return [urls[i : i + size] for i in range(0, len(urls), size)]


def build_single_tweet_prompt(url: str) -> str:
    """Build prompt for fetching a single tweet."""
    return f"""Retrieve the full content of this specific tweet: {url}

Include ALL of the following:
1. Full tweet text (complete, not truncated)
2. Author display name and handle (@username)
3. Date and time posted
4. Engagement metrics: likes, reposts, replies, views
5. Any media: describe images, note videos/links
6. If this is a reply: include the parent tweet's author, handle, and text
7. If this quotes another tweet: include the quoted tweet's author, handle, and text
8. If this is part of a thread: note thread position and include preceding tweets

Format the output clearly with labeled sections."""


def build_multi_tweet_prompt(url_list: str) -> str:
    """Build prompt for fetching multiple tweets."""
    return f"""Retrieve the full content of each of these tweets:

{url_list}

For EACH tweet, include ALL of the following:
1. The tweet URL (as a header to separate tweets)
2. Full tweet text (complete, not truncated)
3. Author display name and handle (@username)
4. Date and time posted
5. Engagement metrics: likes, reposts, replies, views
6. Any media: describe images, note videos/links
7. If reply: parent tweet author and text
8. If quote tweet: quoted tweet author and text

Separate each tweet clearly with a divider. Process every URL."""


def build_single_article_prompt(url: str) -> str:
    """Build prompt for fetching a single X article."""
    return f"""Find the full content of the X/Twitter article at: {url}

Follow these steps IN ORDER:

STEP 1 — Identify the article (use x_search):
Search X for the tweet that shared this article URL. Look for tweets
containing "{url}" or the article ID. This gives you the author handle,
topic, and any preview text.

STEP 2 — Find full content (use web_search):
Using the author name, article title/topic, and key phrases from Step 1,
search the web for the full article text. Check blogs, newsletters,
Reddit, Hacker News, and other sites that reposted or discussed it.

STEP 3 — Report everything you found:
1. Article title
2. Author display name and handle (@username)
3. Publication date
4. Full article text — as much as you can reconstruct
5. Engagement metrics: likes, reposts, replies, views
6. Key quotes from the article
7. Related links or citations

Format the output clearly with labeled sections."""


def build_multi_article_prompt(url_list: str) -> str:
    """Build prompt for fetching multiple X articles."""
    return f"""Find the full content of each of these X/Twitter articles:

{url_list}

For EACH article, follow these steps IN ORDER:

STEP 1 — Identify the article (use x_search):
Search X for the tweet that shared this article URL. This gives you
the author handle, topic, and preview text.

STEP 2 — Find full content (use web_search):
Using the author name, article title/topic, and key phrases from Step 1,
search the web for the full text. Check blogs, newsletters, Reddit, HN.

STEP 3 — Report:
1. Article URL (as header)
2. Article title
3. Author display name and handle
4. Publication date
5. Full article text — as much as you can reconstruct
6. Key quotes
7. Engagement metrics if available

Separate each article clearly with a divider."""


def _build_prompt_for_chunk(chunk: list) -> str:
    """Build the appropriate prompt for a chunk of URLs based on type."""
    types = {u["type"] for u in chunk}
    urls_str = "\n".join(f"- {u['url']}" for u in chunk)

    if len(chunk) == 1:
        url = chunk[0]["url"]
        if chunk[0]["type"] == "article":
            return build_single_article_prompt(url)
        return build_single_tweet_prompt(url)

    if types == {"article"}:
        return build_multi_article_prompt(urls_str)
    if types == {"tweet"}:
        return build_multi_tweet_prompt(urls_str)

    return f"""Retrieve the full content of each of these X/Twitter items:

{urls_str}

For EACH item, include ALL of the following:
1. The URL (as a header to separate items)
2. Full content text (complete, not truncated)
3. Author display name and handle (@username)
4. Date posted/published
5. Engagement metrics: likes, reposts, replies, views
6. Any media: describe images, note videos/links
7. For tweets: thread/reply/quote context if applicable
8. For articles: title and any citations/links within

Separate each item clearly with a divider. Process every URL."""


def _tool_for_chunk(chunk: list) -> list:
    """Select API tools based on URL types in the chunk.

    Articles get both x_search (to identify author/topic) and
    web_search (to find full text externally). Tweets only need
    x_search.
    """
    types = {u["type"] for u in chunk}
    if types == {"tweet"}:
        return [{"type": "x_search"}]
    # Articles or mixed: provide both tools
    return [{"type": "x_search"}, {"type": "web_search"}]


def fetch_urls(
    urls: list, api_key: str, single: bool = False
) -> list:
    """Fetch X content by URL(s).

    Tweets use x_search, articles use web_search (x_search cannot
    read X article bodies).
    """
    chunk_size = 1 if single else CHUNK_SIZE

    # Separate by type so each chunk gets the right tool
    tweets = [u for u in urls if u["type"] == "tweet"]
    articles = [u for u in urls if u["type"] == "article"]

    results = []

    for group in (tweets, articles):
        if not group:
            continue
        chunks = chunk_urls(group, chunk_size)
        for chunk in chunks:
            prompt = _build_prompt_for_chunk(chunk)
            tools = _tool_for_chunk(chunk)

            response = call_xai_responses(
                api_key, prompt, tools, timeout=150
            )
            content = extract_output_text(response)

            results.append(
                {
                    "urls": [u["url"] for u in chunk],
                    "content": content,
                    "raw_response": response,
                }
            )

    return results


def search_x(
    query: str, api_key: str, quick: bool = False
) -> dict:
    """Search X for posts matching query."""
    if quick:
        count_range = "8-12"
        timeout = 90
    else:
        count_range = "20-30"
        timeout = 150

    from_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

    prompt = f"""Search X/Twitter for posts about: {query}

Focus on posts from {from_date} to today.
Find {count_range} high-quality, relevant posts.

For each post, include:
- Post text content
- Author handle (@username)
- URL (https://x.com/user/status/...)
- Date
- Engagement: likes, reposts, replies
- Why it's relevant

Prioritize:
- Posts with substantive content (not just links)
- High engagement posts
- Expert opinions"""

    response = call_xai_responses(
        api_key, prompt, [{"type": "x_search"}], timeout=timeout
    )

    return {
        "type": "search",
        "query": query,
        "quick": quick,
        "from_date": from_date,
        "content": extract_output_text(response),
        "raw_response": response,
    }


def print_fetch_results(results: list, json_output: bool = False):
    """Print fetch results."""
    if json_output:
        output = {
            "type": "fetch",
            "items": [],
            "timestamp": datetime.now().isoformat(),
        }
        for r in results:
            output["items"].append(
                {
                    "urls": r["urls"],
                    "content": r["content"],
                }
            )
        print(json.dumps(output, indent=2))
        return

    total = sum(len(r["urls"]) for r in results)
    print(f"\n{'=' * 60}")
    print(f"Fetched {total} item(s)")
    print(f"{'=' * 60}\n")

    for r in results:
        if r["content"]:
            print(r["content"])
        else:
            for url in r["urls"]:
                print(f"Failed to fetch: {url}")
        print()


def print_search_results(results: dict, json_output: bool = False):
    """Print search results."""
    if json_output:
        output = {
            "type": "search",
            "query": results["query"],
            "quick": results["quick"],
            "from_date": results["from_date"],
            "content": results["content"],
            "timestamp": datetime.now().isoformat(),
        }
        print(json.dumps(output, indent=2))
        return

    print(f"\n{'=' * 60}")
    print(f"X Search: {results['query']}")
    print(f"Date Range: {results['from_date']} to today")
    mode = "Quick" if results["quick"] else "Default"
    print(f"Mode: {mode}")
    print(f"{'=' * 60}\n")

    if results["content"]:
        print(results["content"])
    else:
        print("No results found or API error occurred.")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Fetch X/Twitter content by URL or search X posts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uv run x_fetch.py fetch "https://x.com/user/status/123"
  uv run x_fetch.py fetch "https://x.com/i/article/456"
  uv run x_fetch.py fetch "url1" "url2" "url3"
  uv run x_fetch.py fetch "url1" --single
  uv run x_fetch.py search "AI agents"
  uv run x_fetch.py search "AI agents" --quick
  uv run x_fetch.py fetch "url" --json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch_parser = subparsers.add_parser(
        "fetch", help="Fetch tweet/article content by URL"
    )
    fetch_parser.add_argument(
        "urls", nargs="+", help="One or more X/Twitter URLs (tweets or articles)"
    )
    fetch_parser.add_argument(
        "--single",
        action="store_true",
        help="One API call per URL (max fidelity, higher cost)",
    )
    fetch_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output structured JSON",
    )

    search_parser = subparsers.add_parser(
        "search", help="Search X for posts"
    )
    search_parser.add_argument(
        "query", nargs="+", help="Search query"
    )
    search_parser.add_argument(
        "--quick",
        action="store_true",
        help="Fast overview (8-12 results)",
    )
    search_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output structured JSON",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    api_key = get_api_key()

    if args.command == "fetch":
        parsed = parse_urls(args.urls)
        if not parsed:
            print(
                "Error: No valid X/Twitter URLs found.",
                file=sys.stderr,
            )
            print(
                "Expected formats:\n"
                "  https://x.com/user/status/123456\n"
                "  https://x.com/i/article/789",
                file=sys.stderr,
            )
            sys.exit(1)

        if not args.json_output:
            print(f"Fetching {len(parsed)} item(s)...")

        results = fetch_urls(parsed, api_key, single=args.single)
        print_fetch_results(results, args.json_output)

    elif args.command == "search":
        query = " ".join(args.query)

        if not args.json_output:
            print(f"Searching X for: {query}")

        results = search_x(query, api_key, quick=args.quick)
        print_search_results(results, args.json_output)


if __name__ == "__main__":
    main()
