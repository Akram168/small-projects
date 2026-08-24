#!/usr/bin/env python3
"""
Password strength checker: entropy estimate, common-password check,
pattern detection, and a rough crack-time estimate.

Usage:
  python checker.py "correcthorsebatterystaple"
  python checker.py   (interactive prompt, input hidden)
"""

import argparse
import getpass
import math
import re
import sys

# Small illustrative list. A real check should use a proper breach corpus
# (e.g. Have I Been Pwned's Pwned Passwords list) rather than this.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "1234567", "letmein", "welcome",
    "monkey", "dragon", "iloveyou", "admin", "login", "starwars",
    "sunshine", "master", "football", "shadow", "superman", "trustno1",
}

GUESSES_PER_SECOND = 1e10  # rough offline fast-hash attacker (e.g. unsalted MD5 on a GPU)


def charset_size(password):
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33  # rough count of common symbols
    return size or 1


def shannon_entropy_bits(password):
    """Entropy assuming a uniform charset -- a ceiling estimate, not real
    per-string Shannon entropy (which would score 'aaaa' the same as
    a random string of the same length using the same charset)."""
    return len(password) * math.log2(charset_size(password))


def detect_patterns(password):
    issues = []
    if password.lower() in COMMON_PASSWORDS:
        issues.append("in the top-common-passwords list")
    if re.search(r"(.)\1{2,}", password):
        issues.append("contains a repeated character run (aaa, 111, ...)")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)", password.lower()):
        issues.append("contains a sequential run (1234, abcd, ...)")
    if re.fullmatch(r"[a-zA-Z]+", password):
        issues.append("letters only -- no digits or symbols")
    if re.fullmatch(r"[0-9]+", password):
        issues.append("digits only")
    if len(password) < 8:
        issues.append("shorter than 8 characters")
    return issues


def crack_time_human(seconds):
    units = [
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            return f"{seconds / unit_seconds:,.1f} {name}"
    return "instantly"


def rate_password(password):
    entropy = shannon_entropy_bits(password)
    issues = detect_patterns(password)

    # Common/patterned passwords collapse to a tiny effective search space
    # regardless of raw entropy -- an attacker tries dictionaries first.
    if password.lower() in COMMON_PASSWORDS:
        effective_seconds = 0.0001
    else:
        effective_seconds = (2 ** entropy) / GUESSES_PER_SECOND

    if issues or entropy < 40:
        verdict = "WEAK"
    elif entropy < 60:
        verdict = "MODERATE"
    elif entropy < 80:
        verdict = "STRONG"
    else:
        verdict = "VERY STRONG"

    return {
        "entropy_bits": round(entropy, 1),
        "verdict": verdict,
        "issues": issues,
        "estimated_crack_time": crack_time_human(effective_seconds),
    }


def main():
    parser = argparse.ArgumentParser(description="Password strength checker")
    parser.add_argument("password", nargs="?", help="password to check (omit to be prompted, hidden input)")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password to check: ")
    if not password:
        print("No password given.", file=sys.stderr)
        sys.exit(1)

    result = rate_password(password)
    print(f"\nVerdict:              {result['verdict']}")
    print(f"Entropy estimate:      {result['entropy_bits']} bits")
    print(f"Est. offline crack time (fast hash, {GUESSES_PER_SECOND:.0e} guesses/sec): {result['estimated_crack_time']}")
    if result["issues"]:
        print("Issues:")
        for issue in result["issues"]:
            print(f"  - {issue}")
    else:
        print("No obvious weak patterns detected.")


if __name__ == "__main__":
    main()
