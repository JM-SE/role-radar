"""HEAD-only pinned transport with bounded status/header parsing."""

from __future__ import annotations

import asyncio
import socket
import ssl
from contextlib import suppress
from typing import Protocol
from urllib.parse import urlsplit

from role_radar.mailbox.linkedin_resolution.contracts import HeadResponse

CONNECT_TIMEOUT_SECONDS = 2.0
OPERATION_TIMEOUT_SECONDS = 5.0
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADER_COUNT = 64
MAX_HEADER_LINE_BYTES = 4096
MAX_LOCATION_BYTES = 2048


class HeadTransportError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class HeadTransport(Protocol):
    async def head(self, url: str, *, host: str, address: str, deadline: float) -> HeadResponse: ...


class PinnedHeadTransport:
    """Connect to the already validated IP while retaining TLS SNI/Host."""

    async def head(self, url: str, *, host: str, address: str, deadline: float) -> HeadResponse:
        parsed = urlsplit(url)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        request = (
            f"HEAD {target} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: role-radar/0.1\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        if len(request) > MAX_HEADER_BYTES:
            raise HeadTransportError("headers_oversize")
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        writer: asyncio.StreamWriter | None = None
        timeout = min(
            CONNECT_TIMEOUT_SECONDS,
            max(0.001, deadline - asyncio.get_running_loop().time()),
        )
        try:
            context = ssl.create_default_context()
            async with asyncio.timeout(timeout):
                _reader, writer = await asyncio.open_connection(
                    host=address,
                    port=443,
                    family=family,
                    ssl=context,
                    server_hostname=host,
                    limit=MAX_HEADER_LINE_BYTES,
                )
                peer = writer.get_extra_info("peername")
                if peer is not None and str(peer[0]) != address:
                    raise HeadTransportError("dns_rebinding")
                writer.write(request)
                await writer.drain()
                return await _read_headers(_reader, deadline)
        except HeadTransportError:
            raise
        except TimeoutError as exc:
            raise HeadTransportError("timeout_connect") from exc
        except (OSError, ssl.SSLError) as exc:
            code = "tls_failure" if isinstance(exc, ssl.SSLError) else "response_protocol"
            raise HeadTransportError(code) from exc
        except (TypeError, ValueError) as exc:
            # asyncio/socket validation failures must not escape as an
            # unclassified internal error at the report-only boundary.
            raise HeadTransportError("response_protocol") from exc
        finally:
            if writer is not None:
                writer.close()
                with suppress(asyncio.CancelledError, Exception):
                    await writer.wait_closed()


async def _read_headers(
    reader: asyncio.StreamReader,
    deadline: float,
) -> HeadResponse:
    total = 0
    lines: list[bytes] = []
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise HeadTransportError("timeout_operation")
        try:
            async with asyncio.timeout(remaining):
                line = await reader.readline()
        except TimeoutError as exc:
            raise HeadTransportError("timeout_operation") from exc
        if not line or len(line) > MAX_HEADER_LINE_BYTES:
            raise HeadTransportError("response_protocol")
        total += len(line)
        if total > MAX_HEADER_BYTES:
            raise HeadTransportError("headers_oversize")
        lines.append(line)
        if line in {b"\r\n", b"\n"}:
            break
        if len(lines) > MAX_HEADER_COUNT + 2:
            raise HeadTransportError("headers_oversize")
    try:
        status_line = lines[0].decode("ascii", "strict")
        parts = status_line.split()
        if len(parts) < 2 or not parts[0].startswith("HTTP/"):
            raise ValueError
        status_code = int(parts[1])
    except (UnicodeDecodeError, ValueError) as exc:
        raise HeadTransportError("response_protocol") from exc
    locations: list[str] = []
    for raw in lines[1:-1]:
        try:
            name, value = raw.decode("ascii", "strict").split(":", 1)
        except (UnicodeDecodeError, ValueError) as exc:
            raise HeadTransportError("response_protocol") from exc
        if name.casefold() == "location":
            locations.append(value.strip())
    if len(locations) > 1:
        raise HeadTransportError("response_protocol")
    location = locations[0] if locations else None
    if location is not None and len(location.encode("utf-8")) > MAX_LOCATION_BYTES:
        raise HeadTransportError("headers_oversize")
    return HeadResponse(status_code, location)
