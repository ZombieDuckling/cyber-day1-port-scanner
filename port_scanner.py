#!/usr/bin/env python3
"""
Very basic TCP port scanner (beginner-friendly).

Usage examples:
  python3 port_scanner.py scanme.nmap.org --start 20 --end 100
  python3 port_scanner.py 127.0.0.1 -p 22,80,443
"""

from __future__ import annotations

import argparse
import socket
import sys
from typing import Iterable, List


def parse_ports(port_list: str) -> List[int]:
    """Parse a comma-separated port list like '22,80,443'."""
    ports = []
    for item in port_list.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid port: {item}")
        validate_port(port)
        ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("No valid ports provided")
    return sorted(set(ports))


def validate_port(port: int) -> None:
    if not (1 <= port <= 65535):
        raise argparse.ArgumentTypeError(f"Port out of range: {port}")


def scan_port(host: str, port: int, timeout: float) -> bool:
    """Return True if TCP port appears open, else False."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return result == 0


def resolve_target(target: str) -> str:
    """Resolve hostname/IP to an IPv4 address for scanning."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        print(f"[!] Could not resolve target '{target}': {exc}")
        sys.exit(1)


def build_port_list(args: argparse.Namespace) -> Iterable[int]:
    if args.ports:
        return args.ports
    validate_port(args.start)
    validate_port(args.end)
    if args.start > args.end:
        raise argparse.ArgumentTypeError("--start cannot be greater than --end")
    return range(args.start, args.end + 1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simple TCP connect() port scanner for learning purposes."
    )
    parser.add_argument("target", help="Target hostname or IPv4 address")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        help="Comma-separated ports (overrides --start/--end), for example: 22,80,443",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.5,
        help="Socket timeout in seconds (default: 0.5)",
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        print("[!] Timeout must be greater than 0")
        sys.exit(1)

    try:
        ports = list(build_port_list(args))
    except argparse.ArgumentTypeError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    ip = resolve_target(args.target)
    print(f"[*] Scanning target: {args.target} ({ip})")
    if len(ports) == 1:
        print(f"[*] Port: {ports[0]}")
    elif args.ports:
        print(f"[*] Ports: {', '.join(map(str, ports))} (count: {len(ports)})")
    else:
        print(f"[*] Ports: {ports[0]}-{ports[-1]} (count: {len(ports)})")
    print("[*] NOTE: Scan only systems you own or have explicit permission to test.\n")

    open_ports = []
    for port in ports:
        if scan_port(ip, port, args.timeout):
            open_ports.append(port)
            print(f"[OPEN]  {port}")

    print("\n[*] Scan complete")
    if open_ports:
        print(f"[*] Open ports found ({len(open_ports)}): {', '.join(map(str, open_ports))}")
    else:
        print("[*] No open ports found in the selected range")


if __name__ == "__main__":
    main()
