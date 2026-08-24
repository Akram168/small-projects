#!/usr/bin/env python3
"""
Heuristic phishing-URL analyzer: scores a URL on a set of features
commonly seen in phishing links and prints a risk verdict.

This is a rule-based heuristic scorer for portfolio/educational use,
not a production phishing detector -- real systems combine this kind
of signal with domain age, reputation feeds, and ML classifiers.

Usage:
  python analyzer.py "http://paypa1-secure-login.com.verify-account.info/login"
  python analyzer.py --file urls.txt
"""

import argparse
import re
import sys
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "info", "click",
}

BRAND_KEYWORDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "bank",
    "facebook", "instagram", "outlook", "office365", "chase", "wellsfargo",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
}


def is_ip_host(host):
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host))


def has_punycode(host):
    return "xn--" in host


def analyze(url):
    score = 0
    reasons = []

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return {"url": url, "score": 100, "risk": "HIGH", "reasons": ["failed to parse as a URL"]}

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    full = url.lower()

    if not host:
        return {"url": url, "score": 100, "risk": "HIGH", "reasons": ["no hostname could be parsed"]}

    if is_ip_host(host):
        score += 30
        reasons.append("hostname is a raw IP address, not a domain name")

    if has_punycode(host):
        score += 30
        reasons.append("hostname uses punycode (xn--) -- possible homograph/lookalike attack")

    if host.count("-") >= 3:
        score += 10
        reasons.append("unusually many hyphens in hostname (common in typosquat domains)")

    if host.count(".") >= 4:
        score += 10
        reasons.append("unusually many subdomain levels")

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"uses a TLD commonly abused in phishing campaigns (.{tld})")

    if host in SHORTENERS:
        score += 15
        reasons.append("uses a URL shortener -- real destination is hidden")

    for brand in BRAND_KEYWORDS:
        if brand in host:
            labels = host.split(".")
            root_domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
            if brand not in root_domain:
                score += 25
                reasons.append(f"brand name '{brand}' appears in hostname but not in the actual root domain ({root_domain}) -- likely impersonation")
            break

    if "@" in full.split("://", 1)[-1].split("/")[0]:
        score += 25
        reasons.append("'@' in the authority part -- browsers ignore everything before it, classic bait-and-switch")

    if len(url) > 100:
        score += 10
        reasons.append("unusually long URL (obfuscation via length)")

    if re.search(r"(secure|verify|update|confirm|account|signin|login)-", host):
        score += 10
        reasons.append("hostname contains urgency/credential bait keywords")

    score = min(score, 100)
    if score >= 60:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {"url": url, "score": score, "risk": risk, "reasons": reasons}


def print_result(result):
    print(f"\nURL:  {result['url']}")
    print(f"Risk: {result['risk']}  (score {result['score']}/100)")
    if result["reasons"]:
        for reason in result["reasons"]:
            print(f"  - {reason}")
    else:
        print("  - no suspicious features detected")


def main():
    parser = argparse.ArgumentParser(description="Heuristic phishing URL analyzer")
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("--file", help="path to a file with one URL per line")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
    elif args.url:
        urls = [args.url]
    else:
        print("Provide a URL argument or --file <path>.", file=sys.stderr)
        sys.exit(1)

    for url in urls:
        print_result(analyze(url))


if __name__ == "__main__":
    main()
