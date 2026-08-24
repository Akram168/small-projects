#!/usr/bin/env python3
"""
IOC defanger/refanger: converts URLs, IPs, and domains into their
"defanged" form for safe sharing in SOC reports/tickets/Slack
(hxxp://, [.], [:]) and back again for tooling that needs the real value.

SOC analysts defang indicators of compromise before posting them
anywhere that might auto-linkify or auto-fetch them (chat tools,
ticketing systems, email) -- a defanged IOC can't accidentally be
clicked, and won't trigger link-preview bots that "helpfully" visit it.

Usage:
  python defang.py defang "http://185.220.101.7/payload.exe"
  python defang.py refang "hxxp://185[.]220[.]101[.]7/payload.exe"
  python defang.py defang --file iocs.txt
"""

import argparse
import re
import sys

DEFANG_RULES = [
    (re.compile(r"http://", re.I), "hxxp://"),
    (re.compile(r"https://", re.I), "hxxps://"),
    (re.compile(r"ftp://", re.I), "fxp://"),
    (re.compile(r"\."), "[.]"),
    (re.compile(r"@"), "[at]"),
]

REFANG_RULES = [
    (re.compile(r"hxxps://", re.I), "https://"),
    (re.compile(r"hxxp://", re.I), "http://"),
    (re.compile(r"fxp://", re.I), "ftp://"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\[at\]"), "@"),
    (re.compile(r"\[:\]"), ":"),
]


def defang(text):
    for pattern, repl in DEFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def refang(text):
    for pattern, repl in REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def main():
    parser = argparse.ArgumentParser(description="Defang/refang IOCs for safe SOC reporting")
    parser.add_argument("mode", choices=["defang", "refang"])
    parser.add_argument("text", nargs="?", help="IOC text (URL, IP, domain, email)")
    parser.add_argument("--file", help="path to a file with one IOC per line")
    args = parser.parse_args()

    transform = defang if args.mode == "defang" else refang

    if args.file:
        with open(args.file) as f:
            for line in f:
                line = line.rstrip("\n")
                if line.strip():
                    print(transform(line))
    elif args.text:
        print(transform(args.text))
    else:
        print("Provide text or --file <path>.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
