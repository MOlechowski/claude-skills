---
name: doc-mermaid-render
description: "Render Mermaid diagrams to themed SVG or ASCII/Unicode art using beautiful-mermaid. Zero DOM, pure TypeScript, 15 built-in editor themes, mono mode (2 colors). Use for: (1) rendering flowcharts, sequence, class, state, ER diagrams to SVG files, (2) rendering diagrams as ASCII/Unicode for terminal output, (3) themed diagram generation matching editor color schemes. Triggers: beautiful-mermaid, render mermaid, mermaid svg, mermaid ascii, themed diagram, diagram to image."
---

# beautiful-mermaid

Render Mermaid diagrams to SVG or ASCII using the `doc-mermaid-render` npm package. Zero DOM dependencies, 15 built-in themes, works in Node.js/Bun without a browser.

## Prerequisites

```bash
npm install beautiful-mermaid
# or
bun add beautiful-mermaid
```

## Quick Render

Use the bundled render script for one-shot rendering:

```bash
# SVG output (default)
node ~/.claude/skills/beautiful-mermaid/scripts/render.mjs diagram.mmd -o diagram.svg

# ASCII output
node ~/.claude/skills/beautiful-mermaid/scripts/render.mjs diagram.mmd --ascii

# With theme
node ~/.claude/skills/beautiful-mermaid/scripts/render.mjs diagram.mmd -o diagram.svg --theme tokyo-night

# From inline text
node ~/.claude/skills/beautiful-mermaid/scripts/render.mjs --inline "graph LR; A --> B --> C" --ascii

# From stdin
echo "graph TD; A --> B" | node ~/.claude/skills/beautiful-mermaid/scripts/render.mjs --ascii
```

## Programmatic API

### SVG Rendering (async)

```typescript
import { renderMermaid, THEMES } from 'beautiful-mermaid'

// Default (white bg, dark fg)
const svg = await renderMermaid('graph TD\n  A --> B')

// With theme
const svg = await renderMermaid(diagram, THEMES['tokyo-night'])

// Custom colors (mono mode — just 2 colors)
const svg = await renderMermaid(diagram, { bg: '#1a1b26', fg: '#a9b1d6' })

// Enriched colors
const svg = await renderMermaid(diagram, {
  bg: '#1a1b26', fg: '#a9b1d6',
  line: '#3d59a1', accent: '#7aa2f7', muted: '#565f89',
})
```

### ASCII Rendering (sync)

```typescript
import { renderMermaidAscii } from 'beautiful-mermaid'

// Unicode box-drawing (default)
const text = renderMermaidAscii('graph LR\n  A --> B --> C')
// ┌───┐     ┌───┐     ┌───┐
// │ A │────►│ B │────►│ C │
// └───┘     └───┘     └───┘

// Pure ASCII
const text = renderMermaidAscii('graph LR\n  A --> B', { useAscii: true })
// +---+     +---+
// | A |---->| B |
// +---+     +---+
```

## Supported Diagram Types

5 types (use the existing `doc-mermaid` skill's syntax references for full syntax):

| Type | Header | SVG | ASCII |
|------|--------|-----|-------|
| Flowchart | `graph TD` / `flowchart LR` | Yes | Yes |
| State | `stateDiagram-v2` | Yes | Yes |
| Sequence | `sequenceDiagram` | Yes | Yes |
| Class | `classDiagram` | Yes | Yes |
| ER | `erDiagram` | Yes | Yes |

For C4, Gantt, timeline, user journey, mindmap, pie, git graph — use the `doc-mermaid` skill with `mmdc` instead.

## Theming

See `references/themes.md` for the full theme catalog.

### Mono Mode (2 colors)

Provide just `bg` and `fg`. All other colors auto-derive via `color-mix()`:

- Text: fg at 100%
- Secondary text: fg at 60%
- Edge labels: fg at 40%
- Connectors: fg at 30%
- Arrow heads: fg at 50%
- Node fill: fg at 3%
- Node stroke: fg at 20%

### Built-in Themes

```typescript
import { THEMES } from 'beautiful-mermaid'
// THEMES['tokyo-night'], THEMES['dracula'], THEMES['github-dark'], etc.
```

15 themes: `zinc-light`, `zinc-dark`, `tokyo-night`, `tokyo-night-storm`, `tokyo-night-light`, `catppuccin-mocha`, `catppuccin-latte`, `nord`, `nord-light`, `dracula`, `github-light`, `github-dark`, `solarized-light`, `solarized-dark`, `one-dark`

### Shiki VS Code Theme

```typescript
import { fromShikiTheme } from 'beautiful-mermaid'
const colors = fromShikiTheme(shikiHighlighter.getTheme('vitesse-dark'))
```

## RenderOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `bg` | string | `#FFFFFF` | Background color |
| `fg` | string | `#27272A` | Foreground/text color |
| `line` | string? | derived | Edge/connector color |
| `accent` | string? | derived | Arrow heads, highlights |
| `muted` | string? | derived | Secondary text, labels |
| `surface` | string? | derived | Node fill tint |
| `border` | string? | derived | Node stroke |
| `font` | string | `Inter` | Font family |
| `padding` | number | `40` | Canvas padding (px) |
| `nodeSpacing` | number | `24` | Horizontal node spacing |
| `layerSpacing` | number | `40` | Vertical layer spacing |
| `transparent` | boolean | `false` | Transparent background |

## AsciiRenderOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `useAscii` | boolean | `false` | ASCII chars vs Unicode box-drawing |
| `paddingX` | number | `5` | Horizontal node spacing |
| `paddingY` | number | `5` | Vertical node spacing |
| `boxBorderPadding` | number | `1` | Padding inside node boxes |

## When to Use This vs `doc-mermaid` Skill

| Need | Use |
|------|-----|
| SVG/ASCII for flowchart, sequence, class, state, ER | `doc-mermaid-render` |
| C4, Gantt, timeline, journey, mindmap, pie, git graph | `doc-mermaid` (mmdc) |
| Terminal/ASCII output | `doc-mermaid-render` |
| Editor-themed diagrams (tokyo-night, dracula, etc.) | `doc-mermaid-render` |
| Server-side rendering without Puppeteer | `doc-mermaid-render` |
| Full Mermaid syntax compatibility | `doc-mermaid` (mmdc) |
