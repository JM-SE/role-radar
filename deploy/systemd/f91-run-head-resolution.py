#!/usr/bin/env python3
"""Root launcher for an attested, deny-by-default F9.1 transient unit."""

from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ATTESTATION = Path("/run/role-radar/f91-egress-attestation.json")
SCHEMA_VERSION = "role-radar-f91-egress-v1"
POLICY_VERSION = "linkedin-head-resolution-v1"
ATTESTED_HOSTS = frozenset({"ar.linkedin.com", "imap.gmail.com", "www.linkedin.com"})


def main(argv: list[str]) -> int:
    if not argv:
        return 2
    allow = _read_allowlist()
    if allow is None:
        return 3
    command = [
        "systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--unit=role-radar-f91-head-resolution.service",
        "--uid=role-radar",
        "--working-directory=/opt/role-radar",
        "--setenv=PATH=/opt/role-radar/.venv/bin:/usr/bin",
        "--property=EnvironmentFile=/etc/role-radar/role-radar.env",
        "--property=IPAddressDeny=any",
        f"--property=IPAddressAllow={' '.join(allow)}",
        "--property=RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "--property=LoadCredential=gmail-username:/etc/role-radar/credentials/gmail-username",
        "--property=LoadCredential=gmail-app-password:/etc/role-radar/credentials/gmail-app-password",
        "--property=LoadCredential=mailbox-message-hmac:/etc/role-radar/credentials/mailbox-message-hmac",
        "--property=LoadCredential=mailbox-content-hmac:/etc/role-radar/credentials/mailbox-content-hmac",
        f"--property=LoadCredential=f91-egress-attestation:{ATTESTATION}",
        "/usr/bin/env",
        "role-radar",
        "mailbox",
        "linkedin-head-resolution",
        *argv,
    ]
    return subprocess.run(command, check=False).returncode


def _read_allowlist() -> tuple[str, ...] | None:
    try:
        payload = json.loads(ATTESTATION.read_text(encoding="utf-8"))
        if payload["schema_version"] != SCHEMA_VERSION:
            return None
        if payload["policy_version"] != POLICY_VERSION:
            return None
        expiry = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
        if expiry <= datetime.now(UTC):
            return None
        hosts = payload["hosts"]
        if not isinstance(hosts, dict) or set(hosts) != ATTESTED_HOSTS:
            return None
        values = hosts.values()
        addresses = sorted({str(item) for items in values for item in items})
        if not addresses or any(not _is_public(item) for item in addresses):
            return None
        return tuple(f"{item}/{'128' if ':' in item else '32'}" for item in addresses)
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _is_public(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return False
    return address.is_global and not address.is_private and not address.is_reserved


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
