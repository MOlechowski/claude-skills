---
name: res-price-compare
description: "Polish market product price comparison: 20+ shops, shipping costs, manufacturer vs seller warranty, B2B/statutory warranty analysis, stock status, distribution chain. Export TXT/XLSX/HTML. Use when: looking for a product to buy, price comparison, where to buy cheapest. Triggers: cena, porównaj, gdzie kupić, najtaniej, sklep, price compare, best price, kup, ile kosztuje."
---

# Price Comparison — Polish Market

Iterative 5-round product price research on the Polish e-commerce market with warranty verification, shipping costs, and B2B analysis.

**IMPORTANT:** Load `references/polish-market.md` at startup — it contains the shop database, price comparators, and search patterns.

## Architecture

| Tool | Purpose | Cost |
|------|---------|------|
| `WebSearch` | Search for shops, prices, offers | Free |
| `WebFetch` | Verify prices on shop pages | Free |

No xAI — price comparison doesn't need X/Twitter.

## Requirements

No external dependencies. Skill runs exclusively on built-in Claude Code tools.

Optionally for XLSX export:
- `uv` — to run `uv run --with openpyxl python3 -c "..."`

## Workflow Overview

| Step | Action | Purpose |
|------|--------|---------|
| 1 | Parse query | PRODUCT, BUYER_TYPE, CATEGORY |
| 2 | Round 1: Discovery | Ceneo, Allegro, Amazon.pl, general and specialist shops |
| 3 | Gap analysis | Missing shops, unverified prices, missing data |
| 4 | Round 2: WebFetch shops | Confirm prices, stock levels, shipping |
| 5 | Round 3: Warranty and shipping | Verify warranty type, delivery costs |
| 6 | Round 4: B2B and distributors | B2B portals, official distributors, statutory warranty |
| 7 | Round 5: Final verification | Re-check cheapest, stock, coupons |
| 8 | Synthesis | Comparison table, recommendation, summary |
| 9 | Export | TXT, XLSX, HTML on request |
| 10 | Expert mode | Answers from cache, no new searches |

## Step 1: Parse Query

Extract from user query:

### 1a. PRODUCT

Product name to search. Include model, variant, part number.

### 1b. BUYER_TYPE

| Type | Detection | Consequences |
|------|-----------|-------------|
| B2C | "for home", "personal", no indication | Statutory warranty 24 mo. + voluntary warranty |
| B2B | "for company", "VAT invoice", "business", "B2B" | Statutory warranty may be excluded, manufacturer warranty is critical |

**Default:** B2B (safer assumption — triggers more analysis)

### 1c. CATEGORY

Auto-detect based on product name. Load the appropriate specialist shop list from `references/polish-market.md`:

| Category | Detection Patterns | Examples |
|----------|-------------------|----------|
| VoIP/Telephony | Yealink, Grandstream, Fanvil, SIP, DECT, VoIP | Yealink W76P |
| IT/Networking | MikroTik, Ubiquiti, switch, router, AP, firewall | MikroTik hAP ax3 |
| Electronics | monitor, laptop, computer, printer, tablet | Dell U2723QE |
| Office | chair, desk, shredder, projector | Ergohuman Elite |
| General | (no match) | Nespresso Vertuo |

## Step 2: Round 1 — Discovery

### Query Generation

Generate 6-8 parallel queries:

1. **Ceneo:** `site:ceneo.pl "{PRODUCT}"`
2. **Allegro:** `site:allegro.pl "{PRODUCT}"`
3. **Amazon.pl:** `site:amazon.pl "{PRODUCT}"`
4. **General prices:** `"{PRODUCT}" cena kupić`
5. **Specialist shops:** `"{PRODUCT}" sklep` (from category list)
6. **Price comparator:** `"{PRODUCT}" porównanie cen`
7. **Reviews:** `"{PRODUCT}" opinie recenzje`
8. **B2B:** `"{PRODUCT}" dystrybutor hurtownia` (if BUYER_TYPE = B2B)

### Parallel Execution

Run **all WebSearch queries simultaneously** (parallel tool calls).

### Internal Notes After Round 1

Record (internally, NOT in output):

```
SHOPS_FOUND: [list of shops with prices]
SHOPS_MISSING: [from references/polish-market.md, not found]
PRICES_TO_VERIFY: [prices from snippets — need WebFetch]
WARRANTY_TO_CHECK: [shops without warranty type info]
LEADS: [URLs worth checking via WebFetch in Round 2]
```

## Step 3: Gap Analysis

After Round 1, perform gap analysis:

| Gap | Check | Action |
|-----|-------|--------|
| No comparator data | Do we have Ceneo data? | If not → WebFetch ceneo.pl |
| No specialist shops | How many shops from category in polish-market.md? | Search for missing ones |
| Prices from snippets only | Any price confirmed via WebFetch? | Plan WebFetch for top 10 |
| No warranty data | How many shops have warranty type info? | Plan verification |
| No shipping data | How many shops have delivery costs? | Plan WebFetch of shipping pages |
| No marketplace data | Were Allegro / Amazon checked? | Additional queries |

### Plan Round 2

Select top 8-12 URLs for WebFetch verification. Priority:
1. Cheapest offers (price verification)
2. Ceneo (lists many shops at once)
3. Specialist shops without price
4. Pages with warranty information

## Step 4: Round 2 — WebFetch Shops

### Rules

1. **Never repeat queries from Round 1**
2. **WebFetch specific product pages** — not homepages
3. **In parallel** — run 4-6 WebFetch simultaneously
4. **Maximum 8-12 WebFetch** in this round

### Execution

For each URL from the list:

```
WebFetch(url, "Podaj: 1) dokładną cenę brutto, 2) dostępność/stan magazynowy,
  3) koszty wysyłki, 4) informacje o gwarancji (producenta czy sprzedawcy)")
```

If Ceneo is available, WebFetch the Ceneo page **first** — it provides a list of many shops at once.

### Confidence Update

| Source | Price Confidence |
|--------|-----------------|
| WebSearch snippet | LOW — price may be outdated |
| Ceneo listing | MEDIUM — aggregator, but delays |
| WebFetch of shop page | HIGH — directly confirmed |

## Step 5: Round 3 — Warranty and Shipping

### Goal

For each shop, establish:
1. **Warranty type:** manufacturer / distributor / seller / unknown
2. **Shipping costs:** courier, Paczkomat, free shipping (threshold)
3. **Delivery time:** 24h, 48h, on order

### Where to Look for Warranty

1. **Product page** — "Gwarancja" (Warranty) or "Informacje dodatkowe" (Additional info) section
2. **Shop terms of service** — search for "gwarancja", "gwarant", "rękojmia"
3. **Warranty card** — PDF or description in specs
4. **WebSearch:** `site:{shop} gwarancja` or `site:{shop} regulamin`

### Warranty Classification

| Indicator | Type |
|----------|------|
| "gwarancja producenta", "producent: [brand]" | MANUFACTURER |
| "gwarancja dystrybutora", distributor name as guarantor | DISTRIBUTOR |
| "gwarantem jest [shop name]", "gwarancja [shop]" | SELLER |
| No information | UNKNOWN |

Load `references/warranty-guide.md` if deeper B2B or statutory warranty analysis is needed.

### Shipping Costs

WebFetch the "Dostawa" (Delivery) or "Wysyłka" (Shipping) page for top 10 shops:

```
WebFetch(shipping_url, "Podaj wszystkie opcje dostawy z cenami:
  kurier, Paczkomat, Poczta Polska, odbiór osobisty, darmowa wysyłka (od jakiej kwoty)")
```

## Step 6: Round 4 — B2B and Distributors

### Goal

1. **Identify official distributors** of the brand in Poland
2. **B2B portals** — wholesale prices, business terms
3. **B2B statutory warranty** — do shops exclude statutory warranty for businesses

### Queries

```
WebSearch: "{BRAND} dystrybutor Polska"
WebSearch: "{BRAND} importer Polska"
WebSearch: "{BRAND} autoryzowany sprzedawca"
WebSearch: "{PRODUCT}" site:ab.pl OR site:action.pl OR site:also.pl
```

### B2B Statutory Warranty Verification

For top 5 cheapest shops:

```
WebFetch(terms_url, "Czy regulamin wyłącza rękojmię dla przedsiębiorców?
  Szukaj: Art. 558 KC, wyłączenie rękojmi, przedsiębiorca, firma")
```

### Distribution Chain

Establish the chain: **Manufacturer → PL Importer → Distributor → Reseller → Customer**

For each distributor record:
- Company name
- Role (importer / distributor / authorized reseller)
- Website
- Service contact details (if available)

## Step 7: Round 5 — Final Verification

### Goal

Final verification before synthesis. **Verification only, no discovering new shops.**

### Checklist

1. **Re-check top 3 cheapest** — WebFetch again, price may have changed
2. **Stock** — is the product in stock (not "on order")
3. **Coupons/promotions** — `"{PRODUCT}" kupon zniżka promocja`
4. **Alternative offers** on Allegro — check 2-3 offers from different sellers
5. **Compare Allegro vs direct shop** — price, warranty, safety

### Budget

Maximum 6-8 WebFetch in this round.

## Step 8: Synthesis

### Main Table

Sort by total price (price + cheapest shipping):

```
# | Shop               | Gross Price | Shipping (cheapest) | Price+Shipping | Mfr. Warranty     | Availability
--+--------------------+-------------+---------------------+----------------+-------------------+------------------
1 | shop.pl            | 489.00 PLN  | InPost courier 12   | 501.00 PLN     | YES — service.pl  | Yes (1987 pcs)
2 | morele.net         | 496.30 PLN  | FREE from 399 PLN   | 496.30 PLN     | YES — "Manufacturer" | Yes (11 pcs)
```

### Warranty Legend

```
YES  = confirmed manufacturer warranty (verification source)
NO   = seller's own warranty (not manufacturer)
?    = not verified at source
n/a  = no data
```

### Report Sections

1. **TOP 3 — with confirmed manufacturer warranty**
   - Table: Shop, Price incl. shipping, Warranty, Notes

2. **Full comparison table**
   - All found shops, sorted by price+shipping

3. **Allegro — offers**
   - Seller, Price, Manufacturer warranty, Link

4. **Warranty — key findings**
   - Manufacturer policy (global)
   - PL Distributor (extended warranty?)
   - Service center in Poland
   - Manufacturer vs seller warranty (shop list)
   - B2B: statutory warranty and its exclusion

5. **Official distributors in Poland**
   - Table: Company, Role, Website

6. **Product specifications**
   - Key technical parameters

7. **Purchase recommendation**
   - For B2C: top 3 with price, warranty, reasoning
   - For B2B: top 3 considering statutory warranty and manufacturer warranty
   - What to avoid and why

### Confidence Indicators

Label each piece of information:

| Confidence | When |
|-----------|------|
| [HIGH] | Confirmed via WebFetch from shop page |
| [MEDIUM] | From Ceneo/comparator or single source |
| [LOW] | From WebSearch snippets only |

## Step 9: Export

Generate files on user request:

### TXT

Fixed-width column file, same format as synthesis tables.

### XLSX

Load `references/export-formats.md` and generate an Excel spreadsheet with:
- Conditional coloring (green=manufacturer warranty, red=seller)
- Filters and frozen headers
- Multiple sheets (comparison, warranty, distributors, specifications)

### HTML

Load `references/export-formats.md` and generate standalone HTML with:
- Dark theme, embedded CSS
- Tabs for report sections
- Colored badges for warranty types
- Responsive layout

## Step 10: Expert Mode

After delivering the report, switch to Expert Mode:

- Answer questions from collected data
- No new searches unless user requests
- Compare offers, advise

**New search triggers** (exit Expert Mode):
- "Search again..."
- "Find more about..."
- "Update the data..."
- "Check also..."

## Parameters

Always **deep** mode — 5 rounds, 25-40 shops, 20-30 WebFetch.

| Parameter | Value |
|-----------|-------|
| Rounds | 5 |
| Shops | 25-40 |
| WebFetch | 20-30 |

## Constraints (DO/DON'T)

**DO:**
- Always start from Ceneo.pl — best price comparator in PL
- WebFetch to verify prices — search snippets are unreliable
- Distinguish manufacturer warranty from seller warranty — this is critical
- Include shipping costs in ranking — price without shipping is incomplete
- Search for official brand distributors in Poland
- For B2B: check statutory warranty exclusion in terms of service
- Run WebSearch in parallel (parallel tool calls)
- Cite the source of each piece of information (shop URL)
- Load `references/polish-market.md` at startup

**DON'T:**
- Don't trust snippet prices without WebFetch verification
- Don't skip shipping costs in comparison
- Don't assume "24 months warranty" = manufacturer warranty
- Don't repeat queries from previous rounds
- Don't discover new shops in Round 5 — verification only
- Don't quote more than 125 characters from a single source
- Don't run queries sequentially when they can be parallel

## Error Handling

| Error | Resolution |
|-------|-----------|
| WebFetch 403/CAPTCHA | Skip shop, label "WebFetch blocked" |
| Ceneo returns no results | Search directly in shops from polish-market.md |
| Allegro blocks scraping | Use WebSearch `site:allegro.pl`, not WebFetch |
| No price on page | Label "n/a", skip in ranking |
| Conflicting prices (snippet vs WebFetch) | Always trust WebFetch |

## References

- `references/polish-market.md` — Shop and comparator database (loaded ALWAYS)
- `references/warranty-guide.md` — Statutory vs voluntary warranty, Polish law, B2B checklist
- `references/export-formats.md` — TXT/XLSX/HTML templates with generation instructions
