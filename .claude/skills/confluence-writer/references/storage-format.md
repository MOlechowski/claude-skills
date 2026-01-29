# Confluence Storage Format Reference

Quick reference for Confluence XHTML storage format macros and elements.

## Code Blocks

```xml
<ac:structured-macro ac:name="code">
  <ac:parameter ac:name="language">python</ac:parameter>
  <ac:parameter ac:name="title">Example</ac:parameter>
  <ac:parameter ac:name="linenumbers">true</ac:parameter>
  <ac:parameter ac:name="collapse">false</ac:parameter>
  <ac:plain-text-body><![CDATA[print("hello")]]></ac:plain-text-body>
</ac:structured-macro>
```

**Supported languages**: python, javascript, java, bash, sql, xml, html, css, yaml, ruby, go, rust, c, cpp, csharp, php, scala, kotlin, swift, r, perl, groovy, powershell

## Panels

**Info panel**:
```xml
<ac:structured-macro ac:name="info">
  <ac:parameter ac:name="title">Note</ac:parameter>
  <ac:rich-text-body><p>Content here</p></ac:rich-text-body>
</ac:structured-macro>
```

**Warning panel**:
```xml
<ac:structured-macro ac:name="warning">
  <ac:rich-text-body><p>Warning content</p></ac:rich-text-body>
</ac:structured-macro>
```

**Note panel**:
```xml
<ac:structured-macro ac:name="note">
  <ac:rich-text-body><p>Note content</p></ac:rich-text-body>
</ac:structured-macro>
```

**Tip panel**:
```xml
<ac:structured-macro ac:name="tip">
  <ac:rich-text-body><p>Tip content</p></ac:rich-text-body>
</ac:structured-macro>
```

## Draw.io Diagrams

```xml
<ac:structured-macro ac:name="drawio">
  <ac:parameter ac:name="diagramName">architecture.drawio</ac:parameter>
  <ac:parameter ac:name="width">800</ac:parameter>
  <ac:parameter ac:name="height">600</ac:parameter>
  <ac:parameter ac:name="border">true</ac:parameter>
</ac:structured-macro>
```

The diagram file must be uploaded as a page attachment first.

## Images

**Attached image**:
```xml
<ac:image>
  <ri:attachment ri:filename="screenshot.png" />
</ac:image>
```

**External image**:
```xml
<ac:image>
  <ri:url ri:value="https://example.com/image.png" />
</ac:image>
```

**With dimensions**:
```xml
<ac:image ac:width="400" ac:height="300">
  <ri:attachment ri:filename="diagram.png" />
</ac:image>
```

## Tables

```xml
<table>
  <tbody>
    <tr>
      <th>Header 1</th>
      <th>Header 2</th>
    </tr>
    <tr>
      <td>Cell 1</td>
      <td>Cell 2</td>
    </tr>
  </tbody>
</table>
```

## Links

**External link**:
```xml
<a href="https://example.com">Link text</a>
```

**Page link**:
```xml
<ac:link>
  <ri:page ri:content-title="Page Title" />
  <ac:plain-text-link-body><![CDATA[Link text]]></ac:plain-text-link-body>
</ac:link>
```

**Anchor link**:
```xml
<ac:link ac:anchor="section-name">
  <ac:plain-text-link-body><![CDATA[Link text]]></ac:plain-text-link-body>
</ac:link>
```

## Text Formatting

- Bold: `<strong>text</strong>`
- Italic: `<em>text</em>`
- Inline code: `<code>text</code>`
- Strikethrough: `<span style="text-decoration: line-through;">text</span>`

## Block Elements

- Paragraph: `<p>text</p>`
- Headings: `<h1>` through `<h6>`
- Horizontal rule: `<hr />`
- Line break: `<br />`

## Lists

**Unordered**:
```xml
<ul>
  <li>Item 1</li>
  <li>Item 2</li>
</ul>
```

**Ordered**:
```xml
<ol>
  <li>First</li>
  <li>Second</li>
</ol>
```

## Blockquote

```xml
<ac:structured-macro ac:name="quote">
  <ac:rich-text-body><p>Quoted text</p></ac:rich-text-body>
</ac:structured-macro>
```

## Expand/Collapse

```xml
<ac:structured-macro ac:name="expand">
  <ac:parameter ac:name="title">Click to expand</ac:parameter>
  <ac:rich-text-body><p>Hidden content</p></ac:rich-text-body>
</ac:structured-macro>
```

## Table of Contents

```xml
<ac:structured-macro ac:name="toc">
  <ac:parameter ac:name="printable">true</ac:parameter>
  <ac:parameter ac:name="style">disc</ac:parameter>
  <ac:parameter ac:name="maxLevel">3</ac:parameter>
  <ac:parameter ac:name="minLevel">1</ac:parameter>
</ac:structured-macro>
```

## Status Macro

```xml
<ac:structured-macro ac:name="status">
  <ac:parameter ac:name="title">DONE</ac:parameter>
  <ac:parameter ac:name="colour">Green</ac:parameter>
</ac:structured-macro>
```

Colors: Green, Yellow, Red, Blue, Grey

## CDATA Escaping

When content contains `]]>`, escape it:
```xml
<![CDATA[code with ]]]]><![CDATA[> inside]]>
```
