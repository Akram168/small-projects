# SSH Brute-Force Detector

Parses OpenSSH `auth.log`-style failed-login lines and flags source IPs that exceed a threshold of failed attempts within a sliding time window — the standard first-pass SOC log-triage task, before anything gets escalated to a real SIEM correlation rule.

## Usage

```bash
python detector.py auth.log
python detector.py auth.log --threshold 5 --window-minutes 10
```

Exit code `2` if anything is flagged (cron/CI friendly), `0` otherwise.

## Example

Included `sample_auth.log` is synthetic test data (not from a real server) with one obvious brute-force burst mixed in with normal-looking noise:

```
$ python detector.py sample_auth.log --threshold 5 --window-minutes 10
Parsed 10 failed-login events from sample_auth.log

[BRUTE FORCE] 185.220.101.7 -- 6 attempts within 10 min (starting 2026-08-24 21:01:12), 6 total attempts, usernames tried: admin, oracle, postgres, root, test
```

Note what it *didn't* flag: `203.0.113.55` also has repeated failed logins in the sample, but spread across 22 minutes — under the 5-in-10-minutes threshold, so it's left alone. That's the point of a sliding window over a raw count: a handful of failures spread over a long time looks like a user who mistyped their password a few times, not an automated attack.

## How it works

1. Regex-parses each `Failed password for [invalid user] <user> from <ip> port <port> ssh2` line into `{timestamp, user, ip}`.
2. Groups attempts by source IP, sorts by time.
3. For each attempt, slides a window forward and counts how many attempts from that IP land within `--window-minutes` of it. If any window hits the threshold, the IP is flagged with the usernames it tried (a spray across many usernames, as in the sample, is itself a strong brute-force signal — a real user doesn't try `admin`, `oracle`, and `postgres` back to back).

## Limitations

This is single-host, single-log-file analysis with a fixed rule. A real SOC pipeline would: ingest logs centrally (syslog/Filebeat → SIEM), correlate across hosts (the same IP hitting 50 different servers is a much stronger signal than hitting one), and enrich with threat intel (is this IP already known-bad?). This tool is the "understand the underlying detection logic" building block, not a SIEM replacement.
