#!/usr/bin/env python3
"""
PowerShell obfuscation / LOLBin detector: scans command-line strings
(from process creation logs, EDR alerts, Sysmon Event ID 1, etc.) for
patterns commonly seen in malicious PowerShell usage -- encoded
commands, download cradles, in-memory execution, AMSI bypass attempts.

This is signature/heuristic matching over command-line TEXT, not
behavioral analysis -- it's the fast first-pass triage step, same
category of tool as a SOC analyst's saved Sigma/YARA rule for
"suspicious powershell.exe command line".

Usage:
  python detect.py "powershell -enc SQBFAFgA..."
  python detect.py --file commands.txt
"""

import argparse
import base64
import re
import sys

RULES = [
    (re.compile(r"-e(nc(odedcommand)?)?\b", re.I),
     "Encoded command flag (-enc/-EncodedCommand) -- Base64-encodes the real payload to dodge simple string/keyword matching"),
    (re.compile(r"-w(indowstyle)?\s+hidden", re.I),
     "Hidden window -- runs with no visible console, typical of non-interactive/malicious execution"),
    (re.compile(r"-nop(rofile)?\b", re.I),
     "-NoProfile -- skips loading the user's PowerShell profile, common in automated/malicious scripts (also just common in legit automation, so weak signal alone)"),
    (re.compile(r"iex\s*\(|invoke-expression", re.I),
     "IEX / Invoke-Expression -- executes a string as code, the classic 'download cradle' pattern: fetch text from the internet, then IEX it"),
    (re.compile(r"downloadstring|downloadfile|net\.webclient", re.I),
     "WebClient download -- fetching a remote payload, especially suspicious combined with IEX"),
    (re.compile(r"\[convert\]::frombase64string|frombase64string", re.I),
     "Manual Base64 decode -- a second layer of obfuscation beyond -EncodedCommand, decoding a payload at runtime"),
    (re.compile(r"amsiutils|amsiinitfailed|amsi\.dll", re.I),
     "AMSI reference -- possible AMSI (Anti-Malware Scan Interface) bypass attempt"),
    (re.compile(r"-noni\b|-noninteractive", re.I),
     "-NonInteractive -- no user interaction expected, typical of scripted/automated execution (weak signal alone, common in legit CI too)"),
    (re.compile(r"bypass\s+", re.I),
     "-ExecutionPolicy Bypass -- disables the script-execution safety prompt"),
    (re.compile(r"reflectiveloader|invoke-reflectivepeinjection|invoke-mimikatz", re.I),
     "Known offensive-tooling function name (reflective DLL/PE injection, Mimikatz) -- high-confidence malicious"),
]


def looks_like_base64(s):
    s = s.strip()
    if len(s) < 20 or len(s) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", s))


def try_decode_encoded_command(command):
    """PowerShell -enc payloads are UTF-16LE Base64. Best-effort decode
    of the longest base64-looking token in the command line."""
    tokens = re.findall(r"[A-Za-z0-9+/=]{20,}", command)
    for token in sorted(tokens, key=len, reverse=True):
        if looks_like_base64(token):
            try:
                raw = base64.b64decode(token)
                return raw.decode("utf-16le", errors="replace")
            except Exception:
                continue
    return None


def analyze(command):
    hits = [(pattern.pattern, note) for pattern, note in RULES if pattern.search(command)]
    decoded = None
    if re.search(r"-e(nc(odedcommand)?)?\b", command, re.I):
        decoded = try_decode_encoded_command(command)
    return hits, decoded


def print_result(command, hits, decoded):
    print(f"\nCommand: {command}")
    if not hits:
        print("  No suspicious patterns matched.")
    for pattern, note in hits:
        print(f"  [FLAG] {note}")
    if decoded:
        print(f"  Decoded -EncodedCommand payload:\n    {decoded}")


def main():
    parser = argparse.ArgumentParser(description="PowerShell obfuscation / LOLBin command-line detector")
    parser.add_argument("command", nargs="?", help="a full command line to analyze")
    parser.add_argument("--file", help="file with one command line per line")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            commands = [line.rstrip("\n") for line in f if line.strip()]
    elif args.command:
        commands = [args.command]
    else:
        print("Provide a command argument or --file <path>.", file=sys.stderr)
        sys.exit(1)

    for cmd in commands:
        hits, decoded = analyze(cmd)
        print_result(cmd, hits, decoded)


if __name__ == "__main__":
    main()
