#!/usr/bin/env python3
"""
Google Safe Browsing URL Checker
Checks a list of URLs against Google Safe Browsing API v4.

Usage:
    python check_urls.py --input urls.txt --output results.csv --api-key API_KEY_HERE

Input file: one URL per line, or a CSV with a column containing URLs.
"""

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

import requests

# API limit: max 500 URLs per request
BATCH_SIZE = 500

# Threat types to check against
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
    "THREAT_TYPE_UNSPECIFIED",
]

PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]

API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def load_urls(input_path: str, url_column: str | None = None) -> list[str]:
    """Load URLs from a plain text file or CSV."""
    path = Path(input_path)
    if not path.exists():
        sys.exit(f"Error: input file '{input_path}' not found.")

    urls = []
    suffix = path.suffix.lower()

    if suffix == ".csv":
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if url_column:
                col = url_column
            else:
                # Guess the URL column: first column whose name contains 'url' or 'domain'
                cols = reader.fieldnames or []
                candidates = [c for c in cols if "url" in c.lower() or "domain" in c.lower()]
                col = candidates[0] if candidates else (cols[0] if cols else None)
                if col is None:
                    sys.exit("Error: could not detect a URL column. Use --url-column to specify one.")
                print(f"Using CSV column: '{col}'")
            for row in reader:
                raw = row.get(col, "").strip()
                if raw:
                    urls.append(raw)
    else:
        with open(path, encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith("#"):
                    urls.append(url)

    return urls


def normalise_url(url: str) -> str:
    """Ensure URL has a scheme so the API accepts it."""
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url


def check_batch(urls: list[str], api_key: str, retries: int = 3) -> list[dict]:
    """Send one batch of up to 500 URLs to the Safe Browsing API."""
    payload = {
        "client": {"clientId": "url-checker-script", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": u} for u in urls],
        },
    }

    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(
                API_ENDPOINT,
                params={"key": api_key},
                json=payload,
                timeout=30,
            )

            if resp.status_code == 200:
                data = resp.json()
                return data.get("matches", [])

            if resp.status_code == 429:
                wait = 2 ** attempt
                print(f"  Rate limited. Waiting {wait}s before retry {attempt}/{retries}...")
                time.sleep(wait)
                continue

            # Other HTTP errors
            print(f"  API error {resp.status_code}: {resp.text[:200]}")
            if attempt < retries:
                time.sleep(2 ** attempt)
            else:
                return []

        except requests.RequestException as exc:
            print(f"  Network error (attempt {attempt}/{retries}): {exc}")
            if attempt < retries:
                time.sleep(2 ** attempt)
            else:
                return []

    return []


def run(input_path: str, output_path: str, api_key: str, url_column: str | None = None, delay: float = 0.5, flagged_output: str = "flagged.csv"):
    raw_urls = load_urls(input_path, url_column)
    urls = [normalise_url(u) for u in raw_urls]
    total = len(urls)
    print(f"Loaded {total} URLs. Checking in batches of {BATCH_SIZE}...")

    # Map normalised URL -> threat info (only flagged URLs appear in API response)
    flagged: dict[str, list[dict]] = {}

    batches = [urls[i : i + BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]
    for idx, batch in enumerate(batches, start=1):
        print(f"Batch {idx}/{len(batches)} ({len(batch)} URLs)...", end=" ", flush=True)
        matches = check_batch(batch, api_key)
        for match in matches:
            url = match.get("threat", {}).get("url", "")
            if url not in flagged:
                flagged[url] = []
            flagged[url].append(match)
        print(f"{len(matches)} flagged")
        if idx < len(batches):
            time.sleep(delay)  # polite pause between batches

    # Write results
    out = Path(output_path)
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "status", "threat_type", "platform_type", "cache_duration"])
        for url in urls:
            if url in flagged:
                for match in flagged[url]:
                    writer.writerow([
                        url,
                        "FLAGGED",
                        match.get("threatType", ""),
                        match.get("platformType", ""),
                        match.get("cacheDuration", ""),
                    ])
            else:
                writer.writerow([url, "SAFE", "", "", ""])

    # Write flagged-only output
    flagged_out = Path(flagged_output)
    with open(flagged_out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "threat_type", "platform_type", "cache_duration"])
        for url in urls:
            if url in flagged:
                for match in flagged[url]:
                    writer.writerow([
                        url,
                        match.get("threatType", ""),
                        match.get("platformType", ""),
                        match.get("cacheDuration", ""),
                    ])

    flagged_count = len(flagged)
    safe_count = total - flagged_count
    print(f"\nDone. {total} URLs checked: {flagged_count} flagged, {safe_count} safe.")
    print(f"Full results:    {out.resolve()}")
    print(f"Flagged only:    {flagged_out.resolve()}")

    # Print a summary of flagged URLs to stdout
    if flagged:
        print("\nFlagged URLs:")
        for url, matches in flagged.items():
            threats = ", ".join({m.get("threatType", "?") for m in matches})
            print(f"  [{threats}] {url}")


def main():
    parser = argparse.ArgumentParser(description="Check URLs against Google Safe Browsing API v4.")
    parser.add_argument("--input", "-i", required=True, help="Input file (plain text or CSV, one URL per line/row)")
    parser.add_argument("--output", "-o", default="results.csv", help="Output CSV file (default: results.csv)")
    parser.add_argument(
        "--api-key",
        "-k",
        default=os.environ.get("SAFE_BROWSING_API_KEY"),
        help="Google Safe Browsing API key (or set SAFE_BROWSING_API_KEY env var)",
    )
    parser.add_argument("--url-column", help="CSV column name containing URLs (auto-detected if omitted)")
    parser.add_argument("--flagged-output", "-f", default="flagged.csv", help="Output CSV for flagged URLs only (default: flagged.csv)")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Seconds to wait between batches (default: 0.5)",
    )
    args = parser.parse_args()

    if not args.api_key:
        sys.exit("Error: API key required. Pass --api-key or set SAFE_BROWSING_API_KEY environment variable.")

    run(args.input, args.output, args.api_key, args.url_column, args.delay, args.flagged_output)


if __name__ == "__main__":
    main()
