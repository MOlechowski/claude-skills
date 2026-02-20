#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx", "beautifulsoup4", "rich"]
# ///
"""
Fetch current Cloudflare pricing from official documentation.

Usage:
    ./fetch_prices.py [service]
    uv run fetch_prices.py [service]

Services: workers, d1, r2, kv, pages, plans, all (default)

Examples:
    ./fetch_prices.py workers
    ./fetch_prices.py all
    uv run fetch_prices.py r2
"""

import re
import sys

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

PRICING_URLS = {
    'workers': 'https://developers.cloudflare.com/workers/platform/pricing/',
    'd1': 'https://developers.cloudflare.com/d1/platform/pricing/',
    'r2': 'https://developers.cloudflare.com/r2/pricing/',
    'kv': 'https://developers.cloudflare.com/kv/platform/pricing/',
    'pages': 'https://developers.cloudflare.com/pages/platform/limits/',
    'plans': 'https://www.cloudflare.com/plans/',
}

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
}


def fetch_page(url: str) -> str | None:
    """Fetch page content."""
    try:
        with httpx.Client(follow_redirects=True, timeout=15) as client:
            response = client.get(url, headers=HEADERS)
            response.raise_for_status()
            return response.text
    except Exception as e:
        console.print(f"[red]Error fetching {url}: {e}[/red]")
        return None


def extract_tables(soup: BeautifulSoup) -> list[dict]:
    """Extract pricing tables from HTML."""
    tables = []
    for table in soup.find_all('table'):
        headers = []
        rows = []

        # Get headers
        thead = table.find('thead')
        if thead:
            headers = [th.get_text(strip=True) for th in thead.find_all(['th', 'td'])]

        # Get rows
        tbody = table.find('tbody') or table
        for tr in tbody.find_all('tr'):
            cells = [td.get_text(strip=True) for td in tr.find_all(['td', 'th'])]
            if cells and cells != headers:
                rows.append(cells)

        if headers or rows:
            tables.append({'headers': headers, 'rows': rows})

    return tables


def extract_pricing_patterns(text: str) -> dict:
    """Extract pricing patterns from text."""
    patterns = {
        'dollar_per_million': r'\$[\d.]+\s*(?:per|/)\s*(?:million|1M|M)\b',
        'dollar_per_gb': r'\$[\d.]+\s*(?:per|/)\s*GB',
        'dollar_per_month': r'\$[\d.]+\s*(?:per|/)\s*month',
        'free_tier': r'(\d+(?:,\d+)*(?:K|M|GB)?)\s*(?:free|included)',
        'requests_limit': r'(\d+(?:,\d+)*(?:K|M)?)\s*requests?',
    }

    extracted = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            extracted[name] = list(set(matches))[:5]  # Dedupe, limit to 5

    return extracted


def extract_key_sections(soup: BeautifulSoup) -> list[str]:
    """Extract key pricing sections."""
    sections = []

    # Look for pricing-related headings and their content
    for heading in soup.find_all(['h2', 'h3', 'h4']):
        text = heading.get_text(strip=True).lower()
        if any(word in text for word in ['pricing', 'price', 'cost', 'free', 'paid', 'billing', 'limit']):
            section_text = [heading.get_text(strip=True)]

            # Get following paragraphs and lists
            for sibling in heading.find_next_siblings():
                if sibling.name in ['h2', 'h3', 'h4']:
                    break
                if sibling.name in ['p', 'ul', 'ol', 'table']:
                    section_text.append(sibling.get_text(strip=True)[:300])

            sections.append('\n'.join(section_text[:5]))

    return sections[:5]  # Limit to 5 sections


def fetch_workers_pricing() -> dict:
    """Fetch Workers pricing."""
    html = fetch_page(PRICING_URLS['workers'])
    if not html:
        return {'error': 'Failed to fetch'}

    soup = BeautifulSoup(html, 'html.parser')

    return {
        'service': 'Workers',
        'url': PRICING_URLS['workers'],
        'tables': extract_tables(soup),
        'patterns': extract_pricing_patterns(soup.get_text()),
        'sections': extract_key_sections(soup),
        'summary': {
            'paid_plan': '$5/month base',
            'includes': 'Workers, Pages Functions, KV, D1, R2, Durable Objects, Hyperdrive',
            'billing': 'CPU time (not wall clock time)',
            'egress': 'Free (no egress fees)',
            'free_tier': '100,000 requests/day, 10ms CPU/invocation',
        }
    }


def fetch_d1_pricing() -> dict:
    """Fetch D1 pricing."""
    html = fetch_page(PRICING_URLS['d1'])
    if not html:
        return {'error': 'Failed to fetch'}

    soup = BeautifulSoup(html, 'html.parser')

    return {
        'service': 'D1',
        'url': PRICING_URLS['d1'],
        'tables': extract_tables(soup),
        'patterns': extract_pricing_patterns(soup.get_text()),
        'sections': extract_key_sections(soup),
        'summary': {
            'billing': 'Rows read + rows written',
            'egress': 'Free',
            'scale_to_zero': 'Yes - no queries = no charges',
            'tip': 'Use indexes to reduce rows_read',
        }
    }


def fetch_r2_pricing() -> dict:
    """Fetch R2 pricing."""
    html = fetch_page(PRICING_URLS['r2'])
    if not html:
        return {'error': 'Failed to fetch'}

    soup = BeautifulSoup(html, 'html.parser')

    return {
        'service': 'R2',
        'url': PRICING_URLS['r2'],
        'tables': extract_tables(soup),
        'patterns': extract_pricing_patterns(soup.get_text()),
        'sections': extract_key_sections(soup),
        'summary': {
            'billing': 'Storage + Class A/B operations',
            'egress': 'Free (zero egress fees)',
            'class_a': 'Mutations (PUT, POST, DELETE) - more expensive',
            'class_b': 'Reads (GET, HEAD) - cheaper',
            'free_tier': '10 GB storage, 10M Class B ops/month',
        }
    }


def fetch_kv_pricing() -> dict:
    """Fetch KV pricing."""
    html = fetch_page(PRICING_URLS['kv'])
    if not html:
        return {'error': 'Failed to fetch'}

    soup = BeautifulSoup(html, 'html.parser')

    return {
        'service': 'KV',
        'url': PRICING_URLS['kv'],
        'tables': extract_tables(soup),
        'patterns': extract_pricing_patterns(soup.get_text()),
        'sections': extract_key_sections(soup),
        'summary': {
            'billing': 'Reads + writes + deletes + storage',
            'included_in': 'Workers paid plan ($5/month)',
        }
    }


def fetch_pages_pricing() -> dict:
    """Fetch Pages limits."""
    html = fetch_page(PRICING_URLS['pages'])
    if not html:
        return {'error': 'Failed to fetch'}

    soup = BeautifulSoup(html, 'html.parser')

    return {
        'service': 'Pages',
        'url': PRICING_URLS['pages'],
        'tables': extract_tables(soup),
        'patterns': extract_pricing_patterns(soup.get_text()),
        'sections': extract_key_sections(soup),
        'summary': {
            'free_tier': '500 builds/month, unlimited bandwidth',
            'projects': '100 projects per account',
            'files': '20,000 files per site, 25 MB max file size',
        }
    }


def fetch_plans_pricing() -> dict:
    """Fetch main plans."""
    html = fetch_page(PRICING_URLS['plans'])
    if not html:
        return {'error': 'Failed to fetch'}

    soup = BeautifulSoup(html, 'html.parser')

    return {
        'service': 'Plans',
        'url': PRICING_URLS['plans'],
        'tables': extract_tables(soup),
        'patterns': extract_pricing_patterns(soup.get_text()),
        'summary': {
            'tiers': 'Free, Pro, Business, Enterprise',
            'note': 'Check website for current prices',
        }
    }


def display_pricing(pricing: dict):
    """Display pricing with rich formatting."""
    if 'error' in pricing:
        console.print(f"[red]Error: {pricing['error']}[/red]")
        return

    # Header
    console.print(Panel(
        f"[bold blue]{pricing['service']}[/bold blue]\n{pricing['url']}",
        title="Service"
    ))

    # Summary
    if pricing.get('summary'):
        table = Table(title="Summary", show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="green")
        for key, value in pricing['summary'].items():
            table.add_row(key, str(value))
        console.print(table)

    # Extracted patterns
    if pricing.get('patterns'):
        console.print("\n[bold]Extracted Pricing Patterns:[/bold]")
        for key, values in pricing['patterns'].items():
            console.print(f"  [cyan]{key}:[/cyan] {', '.join(values)}")

    # Tables from page
    if pricing.get('tables'):
        for i, tbl in enumerate(pricing['tables'][:3]):  # Limit to 3 tables
            if tbl['headers'] or tbl['rows']:
                table = Table(title=f"Table {i+1}")

                # Add columns
                num_cols = len(tbl['headers']) if tbl['headers'] else len(tbl['rows'][0]) if tbl['rows'] else 0
                for j, header in enumerate(tbl['headers'] or [f"Col {k+1}" for k in range(num_cols)]):
                    table.add_column(header)

                # Add rows (limit to 10)
                for row in tbl['rows'][:10]:
                    table.add_row(*[str(cell)[:50] for cell in row])

                console.print(table)

    console.print()


def main():
    fetchers = {
        'workers': fetch_workers_pricing,
        'd1': fetch_d1_pricing,
        'r2': fetch_r2_pricing,
        'kv': fetch_kv_pricing,
        'pages': fetch_pages_pricing,
        'plans': fetch_plans_pricing,
    }

    # Parse args
    service = sys.argv[1].lower() if len(sys.argv) > 1 else 'all'

    console.print(Panel(
        "[bold]Cloudflare Pricing Fetcher[/bold]\n"
        "Fetches live pricing from official Cloudflare documentation",
        title="cloudflare-expert"
    ))

    if service == 'all':
        for name, fetcher in fetchers.items():
            pricing = fetcher()
            display_pricing(pricing)
    elif service in fetchers:
        pricing = fetchers[service]()
        display_pricing(pricing)
    else:
        console.print(f"[red]Unknown service: {service}[/red]")
        console.print(f"Available: {', '.join(fetchers.keys())}, all")
        sys.exit(1)

    console.print(Panel(
        "[yellow]Prices change frequently. Always verify at cloudflare.com/plans[/yellow]",
        title="Note"
    ))


if __name__ == '__main__':
    main()
