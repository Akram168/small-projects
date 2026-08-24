# Port Scanner

A multi-threaded TCP port scanner in Python: scans a port range concurrently, grabs service banners on open ports, and flags banners that look suspiciously outdated (worth a manual version check).

> **Only run this against hosts you own or have explicit permission to test.** Unauthorized port scanning of systems you don't control can be illegal.

## How it works

- Uses `ThreadPoolExecutor` to fan out TCP connect attempts across a port range concurrently instead of scanning serially.
- On each open port, tries to read the first bytes the service sends (banner grab) — this is how you identify *what* is running behind a port, not just that it's open.
- Cross-checks banners against a small list of known-old version strings (e.g. `OpenSSH_5.x`, `vsFTPd 2.3.4`) and flags them for a closer look. This is illustrative, not a CVE database — real vulnerability scanning needs a proper feed (e.g. Nmap NSE, Nessus, OpenVAS).

## Usage

```bash
python scanner.py <target> [-p 1-1024] [-t 200] [--timeout 0.5]
```

- `target` — hostname or IP
- `-p / --ports` — port or range, e.g. `1-1024` or `22,80,443`
- `-t / --threads` — concurrent worker threads (default 200)
- `--timeout` — per-connection timeout in seconds (default 0.5)

## Example

```
$ python scanner.py 127.0.0.1 -p 1-1024 -t 300 --timeout 0.3
Scanning 127.0.0.1 (127.0.0.1) -- 1024 ports, 300 threads
Started: 2026-08-25T00:33:22

PORT    SERVICE     BANNER
135     ?
445     SMB

Done: 2 open port(s) found.
```

## Possible extensions

- UDP scanning (connect-less, needs ICMP-unreachable handling)
- Nmap-style service/version fingerprinting instead of a static hint list
- Export results to JSON/CSV for feeding into other tooling
