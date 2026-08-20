#!/usr/bin/env python3
"""
Feed pruner
===========

Re-applies the *current* detection rules to everything already stored in
``feed/``. Detection logic evolves — whitelists grow, new foreign-market
exclusions get added — and without this the feed keeps carrying entries that
today's rules would never have accepted.

The pruner imports the scanner's own ``evaluate_domain`` rather than
re-implementing anything, so the feed can never drift from the live rules.

Files touched:
  feed/phishing_feed.json  — drop entries the rules now reject, rescore the
                             rest, and collapse www./wwNN. mirrors
  feed/stats.json          — rebuild ``all_phishing_domains`` from the feed
  feed/llm-analysis.json   — drop analyses of domains that left the feed

Usage:
    python detection/prune_feed.py --dry-run     # show what would change
    python detection/prune_feed.py               # apply
    python detection/prune_feed.py --report pruned.md
"""

import argparse
import importlib.util
import json
import os
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCANNER_PATH = os.path.join(HERE, 'bg-phishing-detector.py')

FEED_FILE = os.path.join(ROOT, 'feed', 'phishing_feed.json')
STATS_FILE = os.path.join(ROOT, 'feed', 'stats.json')
LLM_FILE = os.path.join(ROOT, 'feed', 'llm-analysis.json')


def load_scanner():
    """Import the scanner module despite its hyphenated filename."""
    spec = importlib.util.spec_from_file_location('bg_phishing_detector', SCANNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default


def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')


def prune_feed(scanner, feed: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Return (kept_entries, removed_records)."""
    kept, removed = [], []
    seen = set()

    for entry in feed:
        domain = entry.get('domain', '')
        normalized = scanner.normalize_domain(domain)

        if not normalized:
            removed.append({'domain': domain, 'reason': 'invalid',
                            'detail': 'empty hostname'})
            continue

        # Collapse www./wwNN. mirrors onto the hostname they mirror, so
        # ww25.x, ww38.x, www.x and x are one feed entry rather than four.
        if normalized in seen:
            removed.append({'domain': domain, 'reason': 'duplicate',
                            'detail': f'already in the feed as `{normalized}`'})
            continue

        is_manual = (entry.get('source') == 'manual'
                     or normalized in scanner.MANUAL_CHECK_DOMAINS)
        result = scanner.evaluate_domain(normalized, is_manual=is_manual)

        if result['verdict'] == scanner.VERDICT_PHISHING:
            seen.add(normalized)
            entry['domain'] = normalized
            entry['score'] = result['score']
            entry['details'] = result['details']
            kept.append(entry)
        else:
            removed.append({'domain': domain,
                            'reason': result['reason'],
                            'detail': result['detail']})

    kept.sort(key=lambda e: (-e['score'], e['domain']))
    return kept, removed


def build_report(removed: List[Dict], kept_count: int, original_count: int) -> str:
    by_reason = defaultdict(list)
    for r in removed:
        by_reason[r['reason']].append(r)

    lines = [
        '# Feed prune report',
        '',
        f'- Entries before: **{original_count}**',
        f'- Entries after:  **{kept_count}**',
        f'- Removed:        **{len(removed)}**',
        '',
        '## Removed by reason',
        '',
        '| Reason | Count |',
        '|--------|-------|',
    ]
    for reason, items in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
        lines.append(f'| `{reason}` | {len(items)} |')

    lines.append('')
    for reason, items in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
        lines.append(f'### `{reason}` ({len(items)})')
        lines.append('')
        for item in sorted(items, key=lambda i: i['domain']):
            lines.append(f'- `{item["domain"]}` — {item["detail"]}')
        lines.append('')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Re-apply current rules to the stored feed')
    parser.add_argument('--dry-run', action='store_true',
                        help='Report changes without writing any file')
    parser.add_argument('--report', metavar='PATH',
                        help='Write a markdown prune report to PATH')
    args = parser.parse_args()

    scanner = load_scanner()

    feed = read_json(FEED_FILE, [])
    if not feed:
        print(f'No feed found at {FEED_FILE}')
        return 0

    original_count = len(feed)
    kept, removed = prune_feed(scanner, feed)
    kept_domains = {e['domain'] for e in kept}

    print(f'Feed: {original_count} → {len(kept)} entries ({len(removed)} removed)')
    for reason, count in Counter(r['reason'] for r in removed).most_common():
        print(f'  - {reason}: {count}')

    # --- stats.json -------------------------------------------------------
    stats = read_json(STATS_FILE, {})
    stats_removed = 0
    if stats:
        previous = stats.get('all_phishing_domains', [])
        # The stats list is a mirror of the feed, so rebuild it from the feed
        # rather than only subtracting — that also picks up entries the feed
        # gained (e.g. new manual-watchlist domains).
        surviving = sorted(kept_domains)
        stats_removed = len(previous) - len(surviving)
        stats['all_phishing_domains'] = surviving
        cumulative = stats.setdefault('cumulative_stats', {})
        cumulative['total_unique_phishing_found'] = len(surviving)
        if 'total_unique_domains_scanned' in cumulative:
            cumulative['total_domains_scanned'] = cumulative.pop('total_unique_domains_scanned')
        total_scanned = cumulative.get('total_domains_scanned', 0)
        cumulative['phishing_detection_rate'] = (
            round(len(surviving) / total_scanned * 100, 2) if total_scanned else 0
        )
        print(f'Stats: all_phishing_domains {len(previous)} → {len(surviving)}')

    # --- llm-analysis.json ------------------------------------------------
    llm = read_json(LLM_FILE, {})
    llm_removed = 0
    if llm:
        domains = llm.get('domains', llm.get('analyzed_domains', []))
        surviving = [d for d in domains
                     if scanner.normalize_domain(d.get('domain', '')) in kept_domains]
        for d in surviving:
            d['domain'] = scanner.normalize_domain(d['domain'])
        llm_removed = len(domains) - len(surviving)
        llm['domains'] = surviving
        llm.pop('analyzed_domains', None)
        llm['total_analyzed'] = len(surviving)
        print(f'LLM analysis: {len(domains)} → {len(surviving)} entries')

    report = build_report(removed, len(kept), original_count)

    if args.dry_run:
        print('\n--- dry run, nothing written ---')
        print(report[:4000])
        return 0

    write_json(FEED_FILE, kept)
    if stats:
        write_json(STATS_FILE, stats)
    if llm:
        write_json(LLM_FILE, llm)
    if args.report:
        with open(args.report, 'w') as f:
            f.write(report)
        print(f'Report written to {args.report}')

    print(f'\n✅ Removed {len(removed)} feed entries and {llm_removed} LLM '
          f'analyses; stats now mirror the feed '
          f'({stats_removed:+d} domains)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
