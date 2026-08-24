#!/usr/bin/env python3
"""
Security headers checker: requests a URL and grades the response's
security-relevant HTTP headers. The kind of quick external check a SOC
or appsec review starts with before digging deeper.

Usage:
  python checker.py https://example.com
"""

import argparse
import sys
import urllib.request

CHECKS = [
    ("Strict-Transport-Security", "Forces HTTPS on future visits -- without it, a user's first request over HTTP can be intercepted/downgraded (SSL stripping)."),
    ("Content-Security-Policy", "Restricts what scripts/styles/frames can load -- the strongest single defense against XSS actually executing even if injected."),
    ("X-Content-Type-Options", "`nosniff` stops the browser from guessing content-type in a way that can turn a data upload into executable script."),
    ("X-Frame-Options", "Blocks the page from being framed by another site -- prevents clickjacking. (Superseded by CSP `frame-ancestors` but still widely checked.)"),
    ("Referrer-Policy", "Controls how much of the URL leaks to third parties via the Referer header on outbound links/requests."),
    ("Permissions-Policy", "Explicitly disables browser features (camera, geolocation, etc.) the page doesn't need, shrinking what an XSS could abuse."),
]


def fetch_headers(url):
    req = urllib.request.Request(url, headers={"User-Agent": "security-headers-checker/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return dict(resp.getheaders()), resp.status


def grade(headers):
    present = 0
    results = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for header, explanation in CHECKS:
        value = lower_headers.get(header.lower())
        if value:
            present += 1
            results.append((header, True, value, explanation))
        else:
            results.append((header, False, None, explanation))
    return results, present


def letter_grade(present, total):
    pct = present / total
    if pct == 1:
        return "A"
    if pct >= 0.8:
        return "B"
    if pct >= 0.6:
        return "C"
    if pct >= 0.4:
        return "D"
    return "F"


def main():
    parser = argparse.ArgumentParser(description="Security HTTP headers checker")
    parser.add_argument("url")
    args = parser.parse_args()

    url = args.url if "://" in args.url else "https://" + args.url

    try:
        headers, status = fetch_headers(url)
    except Exception as e:
        print(f"Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    results, present = grade(headers)
    grade_letter = letter_grade(present, len(CHECKS))

    print(f"\n{url}  (HTTP {status})")
    print(f"Grade: {grade_letter}  ({present}/{len(CHECKS)} security headers present)\n")

    for header, found, value, explanation in results:
        status_str = "PRESENT" if found else "MISSING"
        print(f"[{status_str:7}] {header}")
        if found:
            print(f"           value: {value}")
        else:
            print(f"           why it matters: {explanation}")


if __name__ == "__main__":
    main()
