# Theme Catalog

## Built-in Themes (15)

### Dark Themes

| Theme | bg | fg | line | accent | muted |
|-------|----|----|------|--------|-------|
| `zinc-dark` | `#18181B` | `#FAFAFA` | derived | derived | derived |
| `tokyo-night` | `#1a1b26` | `#a9b1d6` | `#3d59a1` | `#7aa2f7` | `#565f89` |
| `tokyo-night-storm` | `#24283b` | `#a9b1d6` | `#3d59a1` | `#7aa2f7` | `#565f89` |
| `catppuccin-mocha` | `#1e1e2e` | `#cdd6f4` | `#585b70` | `#cba6f7` | `#6c7086` |
| `nord` | `#2e3440` | `#d8dee9` | `#4c566a` | `#88c0d0` | `#616e88` |
| `dracula` | `#282a36` | `#f8f8f2` | `#6272a4` | `#bd93f9` | `#6272a4` |
| `github-dark` | `#0d1117` | `#e6edf3` | `#3d444d` | `#4493f8` | `#9198a1` |
| `solarized-dark` | `#002b36` | `#839496` | `#586e75` | `#268bd2` | `#586e75` |
| `one-dark` | `#282c34` | `#abb2bf` | `#4b5263` | `#c678dd` | `#5c6370` |

### Light Themes

| Theme | bg | fg | line | accent | muted |
|-------|----|----|------|--------|-------|
| `zinc-light` | `#FFFFFF` | `#27272A` | derived | derived | derived |
| `tokyo-night-light` | `#d5d6db` | `#343b58` | `#34548a` | `#34548a` | `#9699a3` |
| `catppuccin-latte` | `#eff1f5` | `#4c4f69` | `#9ca0b0` | `#8839ef` | `#9ca0b0` |
| `nord-light` | `#eceff4` | `#2e3440` | `#aab1c0` | `#5e81ac` | `#7b88a1` |
| `github-light` | `#ffffff` | `#1f2328` | `#d1d9e0` | `#0969da` | `#59636e` |
| `solarized-light` | `#fdf6e3` | `#657b83` | `#93a1a1` | `#268bd2` | `#93a1a1` |

## Mono Mode

Provide only `bg` + `fg`. All other colors auto-derive via CSS `color-mix()`:

```
Text:           fg at 100%
Secondary text: fg at 60% into bg
Edge labels:    fg at 40% into bg
Faint text:     fg at 25% into bg
Connectors:     fg at 30% into bg
Arrow heads:    fg at 50% into bg
Node fill:      fg at 3% into bg
Node stroke:    fg at 20% into bg
Group header:   fg at 5% into bg
Inner dividers: fg at 12% into bg
```

## Enrichment Colors

Override any derived value with optional enrichment:

| Variable | CSS Prop | Purpose |
|----------|----------|---------|
| `line` | `--line` | Edge/connector color |
| `accent` | `--accent` | Arrow heads, highlights |
| `muted` | `--muted` | Secondary text, edge labels |
| `surface` | `--surface` | Node fill tint |
| `border` | `--border` | Node/group stroke |

## Custom Themes

```typescript
// Minimal (mono mode)
const myTheme = { bg: '#0f0f0f', fg: '#e0e0e0' }

// With enrichment
const myRichTheme = {
  bg: '#0f0f0f', fg: '#e0e0e0',
  accent: '#ff6b6b', muted: '#666666',
}

const svg = await renderMermaid(diagram, myTheme)
```

## Shiki Theme Extraction

```typescript
import { fromShikiTheme } from 'beautiful-mermaid'

// Maps VS Code editor colors to diagram roles:
// editor.background         → bg
// editor.foreground         → fg
// editorLineNumber.fg       → line
// focusBorder / keyword     → accent
// comment token             → muted
// editor.selectionBackground→ surface
// editorWidget.border       → border
```

## Live Theme Switching

SVG uses CSS custom properties — switch themes without re-rendering:

```javascript
svgElement.style.setProperty('--bg', '#282a36')
svgElement.style.setProperty('--fg', '#f8f8f2')
// Diagram updates immediately
```
