# Day 1/7: Basic Python TCP port scanner

This is a beginner-friendly cybersecurity portfolio project for Day 1 of 7.
It implements a minimal command-line TCP port scanner in Python using
`socket.connect_ex()`.

The goal is to learn fundamentals, not stealth or evasion techniques.
Use this only on systems you own or where you have explicit written
permission.

## Workflow followed

1. Research
2. Learn
3. Execute
4. Push

## Research references

1. Python Standard Library `socket` docs:
   https://docs.python.org/3/library/socket.html
2. Nmap Network Scanning book, TCP connect scan (`-sT`):
   https://nmap.org/book/scan-methods-connect-scan.html
3. Nmap legal issues and safe-use guidance:
   https://nmap.org/book/legal-issues.html

## Key learning points

- A basic TCP scanner can attempt full TCP connections to each port.
- In Python, `socket.connect_ex()` is useful because it returns an error code
  instead of raising an exception on connection failure.
- Open TCP ports generally return success (`0`) from `connect_ex()`.
- Timeouts matter: too low causes false negatives, too high makes scans slow.
- Hostname resolution (`gethostbyname`) is a practical first step before
  scanning.
- Ethical and legal boundaries are core: only scan authorized targets.

## Project files

- `port_scanner.py`: runnable scanner script
- `tests/test_port_scanner.py`: characterization tests for parsing, scanning, and CLI behavior
- `.github/workflows/ci.yml`: pull-request and `main` branch pytest workflow

## How to run

From this folder:

```bash
python3 port_scanner.py 127.0.0.1 --start 1 --end 200
```

Scan specific ports only:

```bash
python3 port_scanner.py scanme.nmap.org -p 22,80,443
```

Optional timeout control:

```bash
python3 port_scanner.py 127.0.0.1 -p 22,80,443 --timeout 1.0
```

## Testing

Install pytest in your preferred environment, then run:

```bash
python3 -m pytest -q
```

The GitHub Actions workflow runs the same test suite on Python 3.10 and 3.12 for pull requests and pushes to `main`.

## Expected output

- Displays target and scan range.
- Prints `[OPEN] <port>` for each open TCP port found.
- Prints a summary at the end.

## Legal and ethical note

Port scanning can be interpreted as hostile activity in many environments.
Never scan networks, hosts, or services without explicit authorization.
