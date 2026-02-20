#!/usr/bin/env node

// Render Mermaid diagrams using beautiful-mermaid.
// Outputs SVG (default) or ASCII/Unicode to stdout or file.
//
// Usage:
//   node render.mjs diagram.mmd -o diagram.svg
//   node render.mjs diagram.mmd --ascii
//   node render.mjs --inline "graph LR; A --> B" --ascii
//   echo "graph TD; A --> B" | node render.mjs --ascii
//   node render.mjs diagram.mmd -o diagram.svg --theme tokyo-night
//   node render.mjs diagram.mmd -o diagram.svg --bg "#1a1b26" --fg "#a9b1d6"

import { readFileSync, writeFileSync } from 'node:fs'

function parseArgs(argv) {
  const args = {
    input: null,
    output: null,
    ascii: false,
    useAsciiChars: false,
    theme: null,
    bg: null,
    fg: null,
    inline: null,
    transparent: false,
    help: false,
  }

  let i = 2
  while (i < argv.length) {
    const arg = argv[i]
    switch (arg) {
      case '-o':
      case '--output':
        args.output = argv[++i]
        break
      case '--ascii':
        args.ascii = true
        break
      case '--pure-ascii':
        args.ascii = true
        args.useAsciiChars = true
        break
      case '--theme':
        args.theme = argv[++i]
        break
      case '--bg':
        args.bg = argv[++i]
        break
      case '--fg':
        args.fg = argv[++i]
        break
      case '--inline':
        args.inline = argv[++i]
        break
      case '--transparent':
        args.transparent = true
        break
      case '-h':
      case '--help':
        args.help = true
        break
      default:
        if (!arg.startsWith('-')) args.input = arg
        break
    }
    i++
  }
  return args
}

function printHelp() {
  console.log(`Usage: node render.mjs [options] [input.mmd]

Render Mermaid diagrams to SVG or ASCII using beautiful-mermaid.

Input (one of):
  <file>              Read Mermaid text from file (.mmd or .md)
  --inline <text>     Pass Mermaid text directly
  (stdin)             Pipe Mermaid text via stdin

Output:
  -o, --output <file> Write to file (default: stdout)
  --ascii             Render as Unicode box-drawing art
  --pure-ascii        Render as pure ASCII (no Unicode)

Theming:
  --theme <name>      Use built-in theme (e.g. tokyo-night, dracula)
  --bg <color>        Background color (hex)
  --fg <color>        Foreground color (hex)
  --transparent       Transparent SVG background

Themes: zinc-light, zinc-dark, tokyo-night, tokyo-night-storm,
  tokyo-night-light, catppuccin-mocha, catppuccin-latte, nord,
  nord-light, dracula, github-light, github-dark, solarized-light,
  solarized-dark, one-dark`)
}

async function main() {
  const args = parseArgs(process.argv)

  if (args.help) {
    printHelp()
    process.exit(0)
  }

  // Import beautiful-mermaid (try local, then global npm)
  let bm
  try {
    bm = await import('beautiful-mermaid')
  } catch {
    try {
      const { execSync } = await import('node:child_process')
      const globalRoot = execSync('npm root -g', { encoding: 'utf-8' }).trim()
      bm = await import(`${globalRoot}/beautiful-mermaid/dist/index.js`)
    } catch {
      console.error('Error: beautiful-mermaid not found. Install it:')
      console.error('  npm install beautiful-mermaid')
      console.error('  # or: npm install -g beautiful-mermaid')
      process.exit(1)
    }
  }

  // Read input
  let text
  if (args.inline) {
    text = args.inline
  } else if (args.input) {
    text = readFileSync(args.input, 'utf-8')
  } else if (!process.stdin.isTTY) {
    text = readFileSync(0, 'utf-8')
  } else {
    console.error('Error: No input. Provide a file, --inline text, or pipe stdin.')
    console.error('Run with --help for usage.')
    process.exit(1)
  }

  // Build options
  let options = {}
  if (args.theme) {
    const theme = bm.THEMES[args.theme]
    if (!theme) {
      console.error(`Error: Unknown theme "${args.theme}".`)
      console.error(`Available: ${Object.keys(bm.THEMES).join(', ')}`)
      process.exit(1)
    }
    options = { ...theme }
  }
  if (args.bg) options.bg = args.bg
  if (args.fg) options.fg = args.fg
  if (args.transparent) options.transparent = true

  // Render
  let result
  if (args.ascii) {
    result = bm.renderMermaidAscii(text, { useAscii: args.useAsciiChars })
  } else {
    result = await bm.renderMermaid(text, options)
  }

  // Output
  if (args.output) {
    writeFileSync(args.output, result, 'utf-8')
    console.error(`Written to ${args.output}`)
  } else {
    process.stdout.write(result)
    if (args.ascii && !result.endsWith('\n')) process.stdout.write('\n')
  }
}

main().catch(err => {
  console.error(`Error: ${err.message}`)
  process.exit(1)
})
