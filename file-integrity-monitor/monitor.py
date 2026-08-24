#!/usr/bin/env python3
"""
File integrity monitor: hashes every file under a directory, saves a
baseline, and on later runs reports what was added, removed, or modified.
A minimal Tripwire/AIDE-style tool.

Usage:
  python monitor.py baseline <directory> [--out baseline.json]
  python monitor.py check <directory> [--baseline baseline.json]
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


def hash_file(path, algo="sha256", chunk_size=65536):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def scan_directory(directory):
    directory = Path(directory)
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            rel = path.relative_to(directory).as_posix()
            result[rel] = hash_file(path)
    return result


def cmd_baseline(args):
    snapshot = scan_directory(args.directory)
    out = Path(args.out)
    out.write_text(json.dumps(snapshot, indent=2))
    print(f"Baseline written: {out} ({len(snapshot)} files hashed)")


def cmd_check(args):
    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        print(f"Baseline file not found: {baseline_path}", file=sys.stderr)
        sys.exit(1)

    baseline = json.loads(baseline_path.read_text())
    current = scan_directory(args.directory)

    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    modified = sorted(f for f in (set(current) & set(baseline)) if current[f] != baseline[f])

    if not (added or removed or modified):
        print("No changes detected. Integrity OK.")
        return

    if added:
        print(f"\nADDED ({len(added)}):")
        for f in added:
            print(f"  + {f}")
    if removed:
        print(f"\nREMOVED ({len(removed)}):")
        for f in removed:
            print(f"  - {f}")
    if modified:
        print(f"\nMODIFIED ({len(modified)}):")
        for f in modified:
            print(f"  * {f}")
            print(f"      baseline: {baseline[f]}")
            print(f"      current:  {current[f]}")

    sys.exit(2)  # non-zero exit so this is scriptable/cron-friendly


def main():
    parser = argparse.ArgumentParser(description="File integrity monitor")
    sub = parser.add_subparsers(dest="command", required=True)

    p_baseline = sub.add_parser("baseline", help="hash a directory and save a baseline")
    p_baseline.add_argument("directory")
    p_baseline.add_argument("--out", default="baseline.json")
    p_baseline.set_defaults(func=cmd_baseline)

    p_check = sub.add_parser("check", help="compare a directory against a saved baseline")
    p_check.add_argument("directory")
    p_check.add_argument("--baseline", default="baseline.json")
    p_check.set_defaults(func=cmd_check)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
