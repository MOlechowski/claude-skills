#!/usr/bin/env python3
"""Analyze YouTube videos using Gemini API's native video understanding."""

import json
import os
import subprocess
import sys


def get_api_key():
    """Get Gemini API key from macOS keychain."""
    keychain = os.path.expanduser("~/Library/Keychains/claude-keys.keychain-db")
    result = subprocess.run(
        ["security", "find-generic-password", "-s", "gemini-api", "-w", keychain],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("ERROR: Gemini API key not found in keychain.", file=sys.stderr)
        print(
            "Add one with: security add-generic-password -s gemini-api -a gemini -w YOUR_KEY "
            "~/Library/Keychains/claude-keys.keychain-db",
            file=sys.stderr,
        )
        sys.exit(1)
    return result.stdout.strip()


DEFAULT_PROMPT = """Analyze this YouTube video thoroughly. Return structured markdown:

## Video Metadata
- **Title**: exact video title
- **Channel**: channel name
- **Duration**: video length

## Key Topics
Bulleted list of all major topics covered in the video.

## Summary
300-500 word comprehensive summary of the video content, arguments, and conclusions.

## Key Takeaways
5-8 actionable or notable takeaways, each as a bullet point.

## Notable Quotes
3-5 memorable or important quotes from the video. Include approximate timestamps if possible.
"""


def analyze(url, prompt=None, model="gemini-2.5-flash", output_format="markdown"):
    """Analyze a YouTube video via Gemini API."""
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=get_api_key())

    response = client.models.generate_content(
        model=model,
        contents=types.Content(
            parts=[
                types.Part.from_uri(file_uri=url, mime_type="video/*"),
                types.Part(text=prompt or DEFAULT_PROMPT),
            ]
        ),
    )

    if output_format == "json":
        return json.dumps(
            {"url": url, "model": model, "content": response.text}, indent=2
        )
    return response.text


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Analyze YouTube videos via Gemini API")
    parser.add_argument("url", help="YouTube video URL")
    parser.add_argument("-p", "--prompt", help="Custom analysis prompt (overrides default)")
    parser.add_argument(
        "-m", "--model", default="gemini-2.5-flash", help="Gemini model (default: gemini-2.5-flash)"
    )
    parser.add_argument(
        "-f", "--format", choices=["markdown", "json"], default="markdown", help="Output format"
    )
    args = parser.parse_args()

    result = analyze(args.url, prompt=args.prompt, model=args.model, output_format=args.format)
    print(result)


if __name__ == "__main__":
    main()
