#!/usr/bin/env python3
"""
ODIPA Cookie Harvester & Analyzer
==================================
Visits a target domain using a headless browser, harvests all cookies set
during a browsing session, classifies them by purpose, and outputs a
structured JSON/CSV report suitable for CCPA/GDPR cookie audits.

Usage:
    python cookie_harvester.py example.com
    python cookie_harvester.py example.com --output report.json
    python cookie_harvester.py example.com --format csv --output cookies.csv
    python cookie_harvester.py example.com --wait 5 --scroll

Requirements:
    pip install playwright requests tldextract
    playwright install chromium

License: MIT, ODIPA (odipa.org)
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

# ── Classification rules ──────────────────────────────────────────────────────
# Based on IAB TCF categories + common cookie naming patterns.
CLASSIFICATION_RULES = {
    "strictly_necessary": {
        "patterns": [
            "session", "sess", "csrf", "xsrf", "_token", "auth",
            "login", "secure", "remember", "cart", "basket",
        ],
        "domains": [],
        "label": "Strictly Necessary",
        "description": "Required for the website to function. Cannot be disabled.",
        "retention_typical": "Session or short-term",
    },
    "analytics": {
        "patterns": [
            "_ga", "_gid", "_gat", "_utm", "amplitude", "_hjid", "_hjSession",
            "mixpanel", "heap", "segment", "plausible", "_pk_id", "_pk_ses",
            "ajs_", "mp_", "optimizely", "vwo_",
        ],
        "domains": [
            "google-analytics.com", "analytics.google.com", "amplitude.com",
            "segment.io", "mixpanel.com", "heap.io",
        ],
        "label": "Analytics & Performance",
        "description": "Tracks how users interact with the site. Used to measure and improve performance.",
        "retention_typical": "Up to 2 years",
    },
    "advertising": {
        "patterns": [
            "_fbp", "_fbc", "fr", "IDE", "DSID", "NID", "1P_JAR",
            "adwords", "doubleclick", "adsense", "remarketing",
            "MUID", "ANID", "_gcl_", "ttd", "criteo",
        ],
        "domains": [
            "doubleclick.net", "googlesyndication.com", "facebook.com",
            "ads.twitter.com", "criteo.com", "taboola.com",
        ],
        "label": "Advertising & Targeting",
        "description": "Used to build a profile of your interests and serve targeted ads.",
        "retention_typical": "Up to 13 months",
    },
    "functional": {
        "patterns": [
            "lang", "locale", "currency", "timezone", "theme",
            "cookie_consent", "gdpr", "ccpa", "privacy",
        ],
        "domains": [],
        "label": "Functional",
        "description": "Enables enhanced functionality and personalization.",
        "retention_typical": "Up to 1 year",
    },
}


def classify_cookie(name: str, domain: str) -> dict:
    """Classify a cookie by name and domain using pattern matching."""
    name_lower = name.lower()
    domain_lower = domain.lower()

    for category, rules in CLASSIFICATION_RULES.items():
        for pattern in rules["patterns"]:
            if pattern.lower() in name_lower:
                return {
                    "category": category,
                    "label": rules["label"],
                    "description": rules["description"],
                    "retention_typical": rules["retention_typical"],
                    "match_type": "name_pattern",
                    "matched": pattern,
                }
        for d in rules["domains"]:
            if d in domain_lower:
                return {
                    "category": category,
                    "label": rules["label"],
                    "description": rules["description"],
                    "retention_typical": rules["retention_typical"],
                    "match_type": "domain",
                    "matched": d,
                }

    return {
        "category": "unknown",
        "label": "Unknown / Unclassified",
        "description": "Could not be classified. Manual review recommended.",
        "retention_typical": "Unknown",
        "match_type": None,
        "matched": None,
    }


def determine_party(cookie_domain: str, target_domain: str) -> Literal["first", "third"]:
    """Determine if a cookie is first-party or third-party."""
    try:
        import tldextract
        target_ext = tldextract.extract(target_domain)
        cookie_ext = tldextract.extract(cookie_domain)
        target_root = f"{target_ext.domain}.{target_ext.suffix}"
        cookie_root = f"{cookie_ext.domain}.{cookie_ext.suffix}"
        return "first" if target_root == cookie_root else "third"
    except Exception:
        # Fallback: simple string comparison
        target_root = ".".join(target_domain.lstrip(".").split(".")[-2:])
        cookie_root = ".".join(cookie_domain.lstrip(".").split(".")[-2:])
        return "first" if target_root == cookie_root else "third"


def harvest_with_playwright(url: str, wait_seconds: int = 3, scroll: bool = False) -> list[dict]:
    """Use Playwright to visit the URL and collect all cookies."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium")
        sys.exit(1)

    cookies = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        )
        page = context.new_page()
        print(f"  → Navigating to {url} …")
        page.goto(url, wait_until="networkidle", timeout=30000)

        if scroll:
            print("  → Scrolling to trigger lazy-loaded scripts …")
            for _ in range(5):
                page.evaluate("window.scrollBy(0, window.innerHeight)")
                time.sleep(0.5)

        if wait_seconds > 0:
            print(f"  → Waiting {wait_seconds}s for deferred cookies …")
            time.sleep(wait_seconds)

        raw_cookies = context.cookies()
        browser.close()

    parsed_target = urlparse(url)
    target_domain = parsed_target.netloc

    for c in raw_cookies:
        classification = classify_cookie(c["name"], c.get("domain", ""))
        party = determine_party(c.get("domain", ""), target_domain)
        cookies.append({
            "name":          c["name"],
            "domain":        c.get("domain", ""),
            "path":          c.get("path", "/"),
            "secure":        c.get("secure", False),
            "http_only":     c.get("httpOnly", False),
            "same_site":     c.get("sameSite", "None"),
            "expires":       c.get("expires", -1),
            "party":         party,
            "category":      classification["category"],
            "category_label":classification["label"],
            "category_desc": classification["description"],
            "retention":     classification["retention_typical"],
            "match_type":    classification["match_type"],
            "matched":       classification["matched"],
        })

    return cookies


def build_report(url: str, cookies: list[dict]) -> dict:
    """Build a structured audit report from raw cookie data."""
    from collections import Counter

    category_counts = Counter(c["category"] for c in cookies)
    party_counts    = Counter(c["party"]    for c in cookies)

    risk_score = 0
    risk_score += category_counts.get("advertising", 0) * 3
    risk_score += category_counts.get("analytics",   0) * 2
    risk_score += party_counts.get("third",          0) * 1
    risk_level = (
        "High"   if risk_score >= 10 else
        "Medium" if risk_score >= 4  else
        "Low"
    )

    return {
        "meta": {
            "tool":      "ODIPA Cookie Harvester & Analyzer",
            "version":   "1.0.0",
            "source":    "https://github.com/odipa/cookie-harvester",
            "scanned_url": url,
            "scanned_at":  datetime.now(timezone.utc).isoformat(),
            "total_cookies": len(cookies),
        },
        "summary": {
            "total":        len(cookies),
            "first_party":  party_counts.get("first",  0),
            "third_party":  party_counts.get("third",  0),
            "by_category":  dict(category_counts),
            "risk_score":   risk_score,
            "risk_level":   risk_level,
        },
        "cookies": cookies,
        "compliance_notes": [
            "Under GDPR, non-essential cookies require explicit prior consent.",
            "Under CCPA, advertising cookies require an opt-out mechanism.",
            f"{'⚠  Third-party advertising cookies detected, review CCPA/GDPR disclosure obligations.' if category_counts.get('advertising',0) > 0 else '✓  No advertising cookies detected.'}",
            f"{'⚠  Third-party analytics present, verify Data Processing Agreement with vendor.' if category_counts.get('analytics',0) > 0 else '✓  No third-party analytics cookies detected.'}",
        ],
    }


def output_json(report: dict, path: str | None) -> None:
    out = json.dumps(report, indent=2)
    if path:
        Path(path).write_text(out)
        print(f"\n✓ Report saved to {path}")
    else:
        print(out)


def output_csv(report: dict, path: str | None) -> None:
    fieldnames = [
        "name", "domain", "path", "secure", "http_only", "same_site",
        "party", "category", "category_label", "retention",
    ]
    rows = report["cookies"]
    if path:
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"\n✓ CSV saved to {path}")
    else:
        w = csv.DictWriter(sys.stdout, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def print_summary(report: dict) -> None:
    s = report["summary"]
    m = report["meta"]
    print(f"\n{'='*60}")
    print(f"  ODIPA Cookie Harvest Report")
    print(f"  URL: {m['scanned_url']}")
    print(f"  Scanned: {m['scanned_at']}")
    print(f"{'='*60}")
    print(f"  Total cookies:   {s['total']}")
    print(f"  First-party:     {s['first_party']}")
    print(f"  Third-party:     {s['third_party']}")
    print(f"\n  By category:")
    for cat, count in s["by_category"].items():
        label = next(
            (r["label"] for r in CLASSIFICATION_RULES.values() if r.get("label","").lower().startswith(cat)),
            cat
        )
        print(f"    {cat:<24} {count}")
    print(f"\n  Risk level:      {s['risk_level']} (score: {s['risk_score']})")
    print(f"\n  Compliance notes:")
    for note in report["compliance_notes"]:
        print(f"    {note}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ODIPA Cookie Harvester & Analyzer, CCPA/GDPR cookie audit tool"
    )
    parser.add_argument("url",              help="Target URL to scan (e.g. example.com or https://example.com)")
    parser.add_argument("--format",         choices=["json", "csv"], default="json", help="Output format (default: json)")
    parser.add_argument("--output", "-o",   help="Output file path (default: stdout)")
    parser.add_argument("--wait",   "-w",   type=int, default=3, help="Seconds to wait after page load (default: 3)")
    parser.add_argument("--scroll",         action="store_true", help="Scroll the page to trigger lazy-loaded scripts")
    parser.add_argument("--quiet",  "-q",   action="store_true", help="Suppress summary output")
    args = parser.parse_args()

    url = args.url if args.url.startswith("http") else f"https://{args.url}"

    print(f"\nODIPA Cookie Harvester, scanning {url}")
    cookies = harvest_with_playwright(url, wait_seconds=args.wait, scroll=args.scroll)
    print(f"  → {len(cookies)} cookies collected")

    report = build_report(url, cookies)

    if not args.quiet:
        print_summary(report)

    if args.format == "csv":
        output_csv(report, args.output)
    else:
        output_json(report, args.output)


if __name__ == "__main__":
    main()
