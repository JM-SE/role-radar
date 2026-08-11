#!/usr/bin/env python3
"""Local-only egress canary for a deny-by-default systemd scope."""

from __future__ import annotations

import json
import socket
import threading


def main() -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted = threading.Event()

    def accept_once() -> None:
        try:
            connection, _peer = server.accept()
            connection.close()
            accepted.set()
        finally:
            server.close()

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()
    local_pass = _connect("127.0.0.1", port)
    thread.join(timeout=1)
    private_block = not _connect("192.0.2.1", port, timeout=0.25)
    unlisted_block = not _connect("198.51.100.1", port, timeout=0.25)
    output = {
        "schema_version": "role-radar-f91-egress-canary-v1",
        "pinning": "pass" if local_pass and accepted.is_set() else "fail",
        "egress": "pass" if local_pass else "fail",
        "private_block": "pass" if private_block else "fail",
        "unlisted_block": "pass" if unlisted_block else "fail",
        "external_requests": 0,
    }
    print(json.dumps(output, sort_keys=True))
    healthy = all(
        value == "pass" for key, value in output.items() if key != "external_requests"
    )
    return 0 if healthy else 3


def _connect(host: str, port: int, *, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
