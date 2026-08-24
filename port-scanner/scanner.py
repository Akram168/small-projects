#!/usr/bin/env python3
"""
Multi-threaded TCP port scanner with banner grabbing and basic
outdated-service flagging.

Usage:
  python scanner.py <target> [-p 1-1024] [-t 200] [--timeout 0.5]

Example:
  python scanner.py scanme.nmap.org -p 1-1000 -t 300
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Minimal set of well-known ports for a friendlier report.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 27017: "MongoDB",
}

# Very small, illustrative list of banner substrings worth a second look.
# Not a real vulnerability database -- just flags "this looks old, go check it".
STALE_BANNER_HINTS = [
    "OpenSSH_5", "OpenSSH_6.0", "OpenSSH_6.1", "OpenSSH_6.2",
    "vsFTPd 2.3.4", "ProFTPD 1.3.3", "Apache/2.2", "Apache/2.0",
    "nginx/1.0", "nginx/1.1", "Microsoft-IIS/6.0",
]


def parse_ports(port_spec):
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def grab_banner(sock):
    try:
        sock.settimeout(1.0)
        return sock.recv(1024).decode(errors="replace").strip()
    except (socket.timeout, OSError):
        return ""


def scan_port(target, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((target, port)) != 0:
                return None
            banner = grab_banner(sock)
            return port, banner
    except OSError:
        return None


def flag_banner(banner):
    return any(hint in banner for hint in STALE_BANNER_HINTS)


def main():
    parser = argparse.ArgumentParser(description="Multi-threaded TCP port scanner with banner grabbing")
    parser.add_argument("target", help="hostname or IP to scan")
    parser.add_argument("-p", "--ports", default="1-1024", help="port or range, e.g. 1-1024 or 22,80,443")
    parser.add_argument("-t", "--threads", type=int, default=200, help="concurrent worker threads")
    parser.add_argument("--timeout", type=float, default=0.5, help="per-connection timeout in seconds")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Could not resolve host: {args.target}", file=sys.stderr)
        sys.exit(1)

    ports = parse_ports(args.ports)
    print(f"Scanning {args.target} ({target_ip}) -- {len(ports)} ports, {args.threads} threads")
    print(f"Started: {datetime.now().isoformat(timespec='seconds')}\n")

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_port, target_ip, p, args.timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda r: r[0])

    if not open_ports:
        print("No open ports found.")
        return

    print(f"{'PORT':<8}{'SERVICE':<12}{'BANNER'}")
    for port, banner in open_ports:
        service = COMMON_PORTS.get(port, "?")
        flag = "  [check version - looks old]" if flag_banner(banner) else ""
        print(f"{port:<8}{service:<12}{banner}{flag}")

    print(f"\nDone: {len(open_ports)} open port(s) found.")


if __name__ == "__main__":
    main()
