from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import port_scanner  # noqa: E402


def test_parse_ports_deduplicates_sorts_and_ignores_blanks() -> None:
    assert port_scanner.parse_ports(" 443,22,,80,22 ") == [22, 80, 443]


@pytest.mark.parametrize("raw", ["abc", "0", "65536", ",,"])
def test_parse_ports_rejects_invalid_values(raw: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        port_scanner.parse_ports(raw)


def test_build_port_list_prefers_explicit_ports() -> None:
    args = argparse.Namespace(ports=[443, 22], start=1, end=10)
    assert list(port_scanner.build_port_list(args)) == [443, 22]


def test_build_port_list_rejects_reversed_range() -> None:
    args = argparse.Namespace(ports=None, start=10, end=1)
    with pytest.raises(argparse.ArgumentTypeError, match="start cannot be greater"):
        list(port_scanner.build_port_list(args))


def test_scan_port_detects_local_open_and_closed_ports() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    open_port = server.getsockname()[1]

    accepted: list[socket.socket] = []

    def accept_once() -> None:
        conn, _ = server.accept()
        accepted.append(conn)

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()

    try:
        assert port_scanner.scan_port("127.0.0.1", open_port, 1.0) is True
        thread.join(timeout=1.0)
        assert accepted, "local listener should accept the scanner connection"
    finally:
        for conn in accepted:
            conn.close()
        server.close()

    closed_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed_probe.bind(("127.0.0.1", 0))
    closed_port = closed_probe.getsockname()[1]
    closed_probe.close()
    assert port_scanner.scan_port("127.0.0.1", closed_port, 0.2) is False


def test_resolve_target_exits_cleanly_for_unresolvable_host(monkeypatch, capsys) -> None:
    def fake_gethostbyname(target: str) -> str:
        raise socket.gaierror("mock failure")

    monkeypatch.setattr(port_scanner.socket, "gethostbyname", fake_gethostbyname)

    with pytest.raises(SystemExit) as excinfo:
        port_scanner.resolve_target("not-a-real-host.invalid")

    assert excinfo.value.code == 1
    assert "Could not resolve target" in capsys.readouterr().out


def test_cli_reports_open_local_port_and_safety_note() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    open_port = server.getsockname()[1]

    accepted: list[socket.socket] = []

    def accept_once() -> None:
        conn, _ = server.accept()
        accepted.append(conn)

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "port_scanner.py"),
                "127.0.0.1",
                "-p",
                str(open_port),
                "--timeout",
                "1.0",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
    finally:
        thread.join(timeout=1.0)
        for conn in accepted:
            conn.close()
        server.close()

    assert f"[OPEN]  {open_port}" in result.stdout
    assert "Open ports found (1)" in result.stdout
    assert "explicit permission" in result.stdout


def test_cli_rejects_non_positive_timeout() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "port_scanner.py"), "127.0.0.1", "-p", "80", "--timeout", "0"],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    assert "Timeout must be greater than 0" in result.stdout
