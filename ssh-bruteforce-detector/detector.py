#!/usr/bin/env python3
"""
SSH brute-force detector: parses OpenSSH auth log lines and flags source
IPs with more failed login attempts than a threshold within a time
window -- the classic first-pass SOC log analysis task.

Usage:
  python detector.py auth.log
  python detector.py auth.log --threshold 5 --window-minutes 10
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Matches standard OpenSSH auth.log failed-password lines, e.g.:
# Aug 24 21:03:11 host sshd[1234]: Failed password for root from 185.220.101.7 port 51514 ssh2
# Aug 24 21:03:12 host sshd[1234]: Failed password for invalid user admin from 45.9.20.11 port 40010 ssh2
LOG_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+ ssh2"
)

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}


def parse_line(line, year):
    m = LOG_LINE.match(line)
    if not m:
        return None
    month = MONTHS.get(m["month"])
    if not month:
        return None
    ts = datetime(year, month, int(m["day"]),
                   *map(int, m["time"].split(":")))
    return {"timestamp": ts, "user": m["user"], "ip": m["ip"]}


def detect(events, threshold, window):
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    findings = []
    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda e: e["timestamp"])
        # sliding window: for each attempt, count how many attempts from
        # this IP fall within `window` after it
        for i, start in enumerate(attempts):
            count = sum(
                1 for a in attempts[i:]
                if a["timestamp"] - start["timestamp"] <= window
            )
            if count >= threshold:
                users = sorted({a["user"] for a in attempts})
                findings.append({
                    "ip": ip,
                    "attempts_in_window": count,
                    "window_start": start["timestamp"],
                    "usernames_tried": users,
                    "total_attempts": len(attempts),
                })
                break  # one finding per IP is enough
    findings.sort(key=lambda f: f["attempts_in_window"], reverse=True)
    return findings


def main():
    parser = argparse.ArgumentParser(description="SSH brute-force log detector")
    parser.add_argument("logfile")
    parser.add_argument("--threshold", type=int, default=5, help="failed attempts to trigger a flag")
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--year", type=int, default=datetime.now().year,
                         help="syslog lines have no year -- assume this one")
    args = parser.parse_args()

    window = timedelta(minutes=args.window_minutes)

    events = []
    with open(args.logfile) as f:
        for line in f:
            e = parse_line(line, args.year)
            if e:
                events.append(e)

    print(f"Parsed {len(events)} failed-login events from {args.logfile}\n")

    findings = detect(events, args.threshold, window)
    if not findings:
        print("No brute-force pattern detected at this threshold.")
        return

    for f in findings:
        print(f"[BRUTE FORCE] {f['ip']} -- {f['attempts_in_window']} attempts within "
              f"{args.window_minutes} min (starting {f['window_start']}), "
              f"{f['total_attempts']} total attempts, "
              f"usernames tried: {', '.join(f['usernames_tried'])}")

    sys.exit(2)


if __name__ == "__main__":
    main()
