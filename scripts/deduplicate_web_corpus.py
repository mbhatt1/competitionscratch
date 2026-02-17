#!/usr/bin/env python3
"""
Deduplicate web_corpus.json by (title, content) pairs.
Keep only unique combinations to improve fixture quality.
"""

import json
from collections import defaultdict
from pathlib import Path


def deduplicate_web_corpus():
    """Deduplicate web corpus by (title, content) pairs."""
    fixtures_dir = Path("fixtures")
    web_corpus_path = fixtures_dir / "web_corpus.json"

    with open(web_corpus_path, "r") as f:
        web_data = json.load(f)

    original_count = len(web_data["pages"])

    # Track unique (title, content) pairs
    seen_pairs = set()
    unique_pages = []
    duplicates_removed = 0

    # Also track which pages to keep for statistics
    title_counts = defaultdict(int)
    content_counts = defaultdict(int)

    for page in web_data["pages"]:
        title = page["title"]
        content = page["content"]
        pair = (title, content)

        if pair not in seen_pairs:
            seen_pairs.add(pair)
            unique_pages.append(page)
            title_counts[title] += 1
            content_counts[content] += 1
        else:
            duplicates_removed += 1

    # Update web data with unique pages only
    web_data["pages"] = unique_pages

    # Save deduplicated corpus
    with open(web_corpus_path, "w") as f:
        json.dump(web_data, f, indent=2)

    # Print statistics
    print(f"Web Corpus Deduplication Results:")
    print(f"  Original pages: {original_count}")
    print(f"  Unique pages: {len(unique_pages)}")
    print(f"  Duplicates removed: {duplicates_removed}")
    print(f"  Reduction: {duplicates_removed / original_count * 100:.1f}%")
    print()
    print(f"  Unique titles: {len(title_counts)}")
    print(f"  Unique content: {len(content_counts)}")
    print(f"  Unique (title, content) pairs: {len(seen_pairs)}")
    print()

    # Show top repeated titles (if any remain)
    top_titles = sorted(title_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    print(f"  Top 5 most common titles:")
    for title, count in top_titles:
        print(f"    - '{title[:50]}...' appears {count} time(s)")
    print()

    # Show top repeated content (if any remain)
    top_content = sorted(content_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    print(f"  Top 5 most common content strings:")
    for content, count in top_content:
        preview = content.replace("\n", " ")[:50]
        print(f"    - '{preview}...' appears {count} time(s)")


if __name__ == "__main__":
    deduplicate_web_corpus()
