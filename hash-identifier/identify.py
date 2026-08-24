#!/usr/bin/env python3
"""
Hash identifier: given a hex string found in a log, memory dump, or
credential leak, guesses which hash algorithm(s) it could be based on
length and character set. Common SOC/incident-response task: "what is
this string, and where would I even look it up?"

Usage:
  python identify.py 5f4dcc3b5aa765d61d8327deb882cf99
  python identify.py --file hashes.txt
"""

import argparse
import re
import sys

# (name, hex length, notes) -- by length, since most common hashes share
# no other distinguishing feature in their output alone.
HASH_LENGTHS = {
    32: ["MD5", "NTLM", "MD4"],
    40: ["SHA-1"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b"],
}

# A handful of prefix/format patterns that are unambiguous on their own.
PATTERN_HINTS = [
    (re.compile(r"^\$2[aby]\$\d{2}\$"), "bcrypt"),
    (re.compile(r"^\$argon2(id|i|d)\$"), "argon2"),
    (re.compile(r"^\$6\$"), "sha512crypt (Linux /etc/shadow)"),
    (re.compile(r"^\$5\$"), "sha256crypt (Linux /etc/shadow)"),
    (re.compile(r"^\$1\$"), "md5crypt (legacy Linux /etc/shadow)"),
    (re.compile(r"^\$pbkdf2"), "PBKDF2 (passlib-style encoded)"),
]


def identify(value):
    value = value.strip()

    for pattern, name in PATTERN_HINTS:
        if pattern.match(value):
            return {"input": value, "matches": [name], "reason": "distinctive prefix format"}

    if re.fullmatch(r"[a-fA-F0-9]+", value):
        candidates = HASH_LENGTHS.get(len(value))
        if candidates:
            return {"input": value, "matches": candidates, "reason": f"hex string, {len(value)} characters"}
        return {"input": value, "matches": [], "reason": f"hex string, {len(value)} characters -- no common algorithm has this exact length"}

    return {"input": value, "matches": [], "reason": "not a recognized hash format (not hex, no known prefix)"}


def print_result(result):
    print(f"\n{result['input']}")
    if result["matches"]:
        print(f"  Possible: {', '.join(result['matches'])}")
    else:
        print("  Possible: (none confidently identified)")
    print(f"  Reason:   {result['reason']}")


def main():
    parser = argparse.ArgumentParser(description="Hash type identifier")
    parser.add_argument("hash", nargs="?", help="hash string to identify")
    parser.add_argument("--file", help="file with one hash per line")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            values = [line.strip() for line in f if line.strip()]
    elif args.hash:
        values = [args.hash]
    else:
        print("Provide a hash argument or --file <path>.", file=sys.stderr)
        sys.exit(1)

    for v in values:
        print_result(identify(v))


if __name__ == "__main__":
    main()
