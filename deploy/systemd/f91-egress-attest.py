#!/usr/bin/env python3
"""Create a short-lived F9.1 DNS/IP attestation as root.

This command performs DNS resolution only. It never opens HTTP connections.
The caller must install stdout atomically as a root-owned systemd credential.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
from datetime import UTC, datetime, timedelta

HOSTS = ("ar.linkedin.com", "www.linkedin.com")
SCHEMA_VERSION = "role-radar-f91-egress-v1"
POLICY_VERSION = "linkedin-head-resolution-v1"
TTL_SECONDS = 60


def main() -> int:
    hosts: dict[str, list[str]] = {}
    for host in HOSTS:
        try:
            rows = socket.getaddrinfo(host, 443, 0, socket.SOCK_STREAM)
        except OSError:
            return 3
        addresses = sorted(
            {
                str(row[4][0])
                for row in rows
                if _is_public(row[4][0])
            }
        )
        if not addresses:
            return 3
        hosts[host] = addresses
    payload = {
        "schema_version": SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "expires_at": (datetime.now(UTC) + timedelta(seconds=TTL_SECONDS)).isoformat(),
        "hosts": hosts,
    }
    json.dump(payload, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


def _is_public(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return False
    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


if __name__ == "__main__":
    raise SystemExit(main())
