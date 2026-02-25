---
name: res-youtube
description: "Analyze YouTube videos using Gemini API's native video understanding. Extract title, channel, topics, summary, takeaways, and quotes from any YouTube URL. Use for: (1) summarizing YouTube videos, (2) extracting key points from video content, (3) processing YouTube links in daily notes, (4) creating structured notes from video content. Triggers: youtube, video summary, analyze video, youtube link, watch video, video notes."
---

# YouTube Video Analysis

Analyze YouTube videos via Gemini 2.5 Flash API with native video understanding. Returns structured markdown.

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Gemini API key | Free tier, no credit card. Stored in macOS keychain |
| google-genai SDK | Installed on-the-fly via `uv run --with` |
| uv | Python package runner |

### API Key Setup

Check if key exists:

```bash
security find-generic-password -s "gemini-api" -w ~/Library/Keychains/claude-keys.keychain-db 2>/dev/null && echo "OK" || echo "MISSING"
```

If missing, user must get a free key from [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) and store it:

```bash
security add-generic-password -s "gemini-api" -a "gemini" -w "YOUR_KEY" ~/Library/Keychains/claude-keys.keychain-db
```

## Usage

### Single Video Analysis

```bash
uv run --with "google-genai" python3 ~/.claude/skills/res-youtube/scripts/youtube_analyze.py "https://www.youtube.com/watch?v=VIDEO_ID"
```

### Custom Prompt

```bash
uv run --with "google-genai" python3 ~/.claude/skills/res-youtube/scripts/youtube_analyze.py "URL" -p "Extract all code examples and tools mentioned in this video"
```

### JSON Output

```bash
uv run --with "google-genai" python3 ~/.claude/skills/res-youtube/scripts/youtube_analyze.py "URL" -f json
```

### Model Override

```bash
uv run --with "google-genai" python3 ~/.claude/skills/res-youtube/scripts/youtube_analyze.py "URL" -m gemini-2.5-pro
```

## Workflow

1. **Verify API key** — check keychain, prompt user to set up if missing
2. **Run script** — pass YouTube URL, capture output
3. **Use output** — the script returns structured markdown with metadata, topics, summary, takeaways, and quotes
4. **Create note** — if integrated with doc-daily-digest or doc-vault-save, use the output to create an Obsidian note

## Integration with doc-daily-digest

When processing YouTube URLs in daily notes, use this skill instead of WebFetch (which cannot access YouTube). The output structure maps directly to the daily digest note format:

```
notesmd-cli create "NOTE_NAME" --content "---
tags: [web, video, youtube]
source: YOUTUBE_URL
author: CHANNEL_NAME
date: DATE
---

{script output here}"
```

## Constraints

**DO:**
- Always check API key exists before running
- Use `uv run --with "google-genai"` — never install globally
- Default to `gemini-2.5-flash` (fast, free tier friendly)
- Pass the full YouTube URL as-is to the script

**DON'T:**
- Attempt WebFetch or scrapling on YouTube URLs — they return empty shells
- Use Gemini CLI (`gemini -p`) for video analysis — its system prompt blocks non-coding tasks
- Hardcode API keys in commands — always read from keychain
