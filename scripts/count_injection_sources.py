#!/usr/bin/env python3
"""
Count and analyze injection sources in fixtures.
"""

import json
import re
from pathlib import Path

# Trigger patterns that indicate prompt injection
INJECTION_TRIGGERS = [
    r"\bforget\b.*\bprevious\b",
    r"\bdisregard\b.*\binstructions?\b",
    r"\bignore\b.*\b(previous|prior|all)\b",
    r"\boverlook\b.*\b(instructions?|directives?|procedures?)\b",
    r"\bprevious\b.*\binstructions?\b",
]


def has_injection_trigger(text):
    """Check if text contains injection trigger patterns."""
    text_lower = text.lower()
    for pattern in INJECTION_TRIGGERS:
        if re.search(pattern, text_lower):
            return True
    return False


def analyze_fixtures():
    """Analyze fixtures for injection sources."""
    fixtures_dir = Path("fixtures")

    # Analyze web corpus
    print("=" * 70)
    print("WEB CORPUS ANALYSIS")
    print("=" * 70)

    with open(fixtures_dir / "web_corpus.json", "r") as f:
        web_data = json.load(f)

    total_pages = len(web_data["pages"])
    injection_pages = []

    for page in web_data["pages"]:
        title = page.get("title", "")
        content = page.get("content", "")
        combined = f"{title} {content}"

        if has_injection_trigger(combined):
            injection_pages.append(
                {
                    "id": page["id"],
                    "title": title,
                    "content_preview": content[:100] + "..." if len(content) > 100 else content,
                }
            )

    print(f"\nTotal web pages: {total_pages}")
    print(f"Pages with injection triggers: {len(injection_pages)}")
    print(f"Percentage: {len(injection_pages) / total_pages * 100:.1f}%")

print("\nInjection pages:")
    for i, page in enumerate(injection_pages, 1):
        print(f"\n{i}. {page['id']}: {page['title']}")
        print(f"   Preview: {page['content_preview']}")

    # Analyze mail seed
    print("\n" + "=" * 70)
    print("EMAIL CORPUS ANALYSIS")
    print("=" * 70)

    with open(fixtures_dir / "mail_seed.json", "r") as f:
        mail_data = json.load(f)

    total_emails = len(mail_data["inbox"])
    injection_emails = []

    for email in mail_data["inbox"]:
        subject = email.get("subject", "")
        body = email.get("body", "")
        combined = f"{subject} {body}"

        if has_injection_trigger(combined):
            injection_emails.append(
                {
                    "id": email["id"],
                    "from": email.get("from", ""),
                    "subject": subject,
                    "body_preview": body[:100] + "..." if len(body) > 100 else body,
                }
            )

    print(f"\nTotal emails: {total_emails}")
    print(f"Emails with injection triggers: {len(injection_emails)}")
    print(f"Percentage: {len(injection_emails) / total_emails * 100:.1f}%")

print("\nInjection emails:")
    for i, email in enumerate(injection_emails, 1):
        print(f"\n{i}. {email['id']}: {email['subject']}")
        print(f"   From: {email['from']}")
        print(f"   Preview: {email['body_preview']}")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total web pages: {total_pages}")
    print(f"  - With injection triggers: {len(injection_pages)}")
    print(f"Total emails: {total_emails}")
    print(f"  - With injection triggers: {len(injection_emails)}")
    print(f"Total injection sources: {len(injection_pages) + len(injection_emails)}")


if __name__ == "__main__":
    analyze_fixtures()
