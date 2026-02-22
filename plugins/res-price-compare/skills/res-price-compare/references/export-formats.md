# Export Formats

Loaded on demand (Level 3), when the user requests export to a file.

## Markdown (Default Output)

Use Markdown tables in conversation. No export needed — this is the primary response format.

## TXT — Text File

Generate using the `Write` tool. Fixed-width column format:

### File Structure

```
{PRODUCT} — Availability and Prices in Poland
===============================================
Research date: {DATE}
Research rounds: 5
Sources searched: {N}+

SUMMARY: Price, shipping, manufacturer warranty, availability
=============================================================

# | Shop               | Gross Price | Shipping (cheapest) | Price+Shipping | Mfr. Warranty     | Availability
--+--------------------+-------------+---------------------+----------------+-------------------+------------------
1  | ...                | ...         | ...                 | ...            | ...               | ...

Legend:
  YES  = confirmed manufacturer warranty
  NO   = seller's own warranty (not manufacturer)
  ?    = not verified at source
  n/a  = no data


TOP 3 — with confirmed manufacturer warranty
=============================================

[top 3 table]


WARRANTY — key findings
========================

[warranty section]


OFFICIAL DISTRIBUTORS IN POLAND
================================

[distributors table]


PRODUCT SPECIFICATIONS
=======================

[specs table]


PURCHASE RECOMMENDATION
========================

[B2C/B2B recommendations]
```

## XLSX — Excel Spreadsheet

Generate using `uv run --with openpyxl python3 -c "..."`.

### Sheets

| Sheet | Content |
|-------|---------|
| Shop Comparison | Main table with prices, shipping, warranty |
| Allegro | Allegro offers (seller, price, warranty, link) |
| Warranty B2B | Warranty and statutory warranty analysis |
| Service & Distributors | Official distributors and service |
| Specifications | Product technical specifications |

### Conditional Coloring

| Color | Meaning | Column |
|-------|---------|--------|
| Green (#C6EFCE) | Manufacturer warranty (YES) | Mfr. Warranty |
| Red (#FFC7CE) | Seller warranty (NO) | Mfr. Warranty |
| Yellow (#FFEB9C) | Not verified (?) | Mfr. Warranty |
| Blue (#BDD7EE) | TOP offers (best) | Entire row |
| Green (#C6EFCE) | Free shipping | Shipping |

### Generation Code

```python
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

wb = openpyxl.Workbook()

# Colors
GREEN = PatternFill("solid", fgColor="C6EFCE")
RED = PatternFill("solid", fgColor="FFC7CE")
YELLOW = PatternFill("solid", fgColor="FFEB9C")
BLUE = PatternFill("solid", fgColor="BDD7EE")
HEADER = PatternFill("solid", fgColor="4472C4")
HEADER_FONT = Font(bold=True, color="FFFFFF", size=11)
THIN_BORDER = Border(
    left=Side(style="thin"), right=Side(style="thin"),
    top=Side(style="thin"), bottom=Side(style="thin")
)

# Sheet 1: Shop Comparison
ws1 = wb.active
ws1.title = "Shop Comparison"
headers = ["#", "Shop", "Gross Price", "Shipping (cheapest)", "Price+Shipping",
           "Mfr. Warranty", "Availability"]
# ... populate with data, apply coloring

# Freeze header
ws1.freeze_panes = "A2"

# Auto-filter
ws1.auto_filter.ref = ws1.dimensions

# Column widths
for i, h in enumerate(headers, 1):
    ws1.column_dimensions[get_column_letter(i)].width = max(len(h) + 4, 15)

wb.save("{filename}.xlsx")
```

## HTML — Web Page

Generate standalone HTML with embedded CSS and JS. No external files needed.

### HTML Template

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{PRODUCT} — Price Comparison</title>
    <style>
        /* Dark theme */
        :root {
            --bg: #1a1a2e;
            --card: #16213e;
            --text: #e0e0e0;
            --accent: #0f3460;
            --highlight: #e94560;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }

        /* Tabs */
        .tabs { display: flex; gap: 4px; margin-bottom: 20px; flex-wrap: wrap; }
        .tab {
            padding: 10px 20px;
            background: var(--accent);
            border: none;
            color: var(--text);
            cursor: pointer;
            border-radius: 8px 8px 0 0;
            font-size: 14px;
        }
        .tab.active { background: var(--highlight); font-weight: bold; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            background: var(--card);
            border-radius: 8px;
            overflow: hidden;
        }
        th {
            background: var(--accent);
            padding: 12px 16px;
            text-align: left;
            font-weight: 600;
        }
        td { padding: 10px 16px; border-bottom: 1px solid #2a2a4a; }
        tr:hover { background: rgba(233,69,96,0.1); }

        /* Badges */
        .badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-yes { background: #2d6a4f; color: #b7e4c7; }
        .badge-no { background: #6a2d2d; color: #e4b7b7; }
        .badge-unknown { background: #6a5a2d; color: #e4dab7; }
        .badge-free { background: #2d4a6a; color: #b7d4e4; }

        /* Cards */
        .card {
            background: var(--card);
            border-radius: 12px;
            padding: 20px;
            margin: 16px 0;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <h1>{PRODUCT} — Price Comparison in Poland</h1>
    <p>Research date: {DATE} | Shops: {N} | Rounds: 5</p>

    <div class="summary-grid">
        <!-- Summary cards -->
    </div>

    <div class="tabs">
        <button class="tab active" onclick="showTab('comparison')">Comparison</button>
        <button class="tab" onclick="showTab('allegro')">Allegro</button>
        <button class="tab" onclick="showTab('warranty')">Warranty</button>
        <button class="tab" onclick="showTab('distributors')">Distributors</button>
        <button class="tab" onclick="showTab('specs')">Specifications</button>
    </div>

    <div id="comparison" class="tab-content active">
        <!-- Comparison table -->
    </div>
    <div id="allegro" class="tab-content">
        <!-- Allegro offers -->
    </div>
    <div id="warranty" class="tab-content">
        <!-- Warranty analysis -->
    </div>
    <div id="distributors" class="tab-content">
        <!-- Distributors -->
    </div>
    <div id="specs" class="tab-content">
        <!-- Specifications -->
    </div>

    <script>
        function showTab(id) {
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
```

### Warranty Badges

```html
<span class="badge badge-yes">YES</span>    <!-- manufacturer warranty -->
<span class="badge badge-no">NO</span>      <!-- seller warranty -->
<span class="badge badge-unknown">?</span>   <!-- not verified -->
<span class="badge badge-free">FREE</span>   <!-- free shipping -->
```
