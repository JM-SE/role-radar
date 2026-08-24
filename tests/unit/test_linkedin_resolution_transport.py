"""F9.1 HEAD transport tests."""

import asyncio

import pytest

from role_radar.mailbox.linkedin_resolution.transport import PinnedHeadTransport


class FakeReader:
    def __init__(self) -> None:
        self.lines = [
            b"HTTP/1.1 302 Found\r\n",
            b"Location: https://boards.greenhouse.io/acme/jobs/eng-1\r\n",
            b"Content-Length: 999999\r\n",
            b"\r\n",
        ]
        self.body_read = False

    async def readline(self, _limit: int = -1) -> bytes:
        if self.lines:
            return self.lines.pop(0)
        self.body_read = True
        return b"body"


class FakeWriter:
    def __init__(self) -> None:
        self.payload = b""
        self.closed = False

    def write(self, payload: bytes) -> None:
        self.payload += payload

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, _name: str) -> tuple[str, int]:
        return ("8.8.8.8", 443)


@pytest.mark.asyncio
async def test_transport_sends_head_only_and_does_not_read_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = FakeReader()
    writer = FakeWriter()

    async def open_connection(**_kwargs: object) -> tuple[FakeReader, FakeWriter]:
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    response = await PinnedHeadTransport().head(
        "https://www.linkedin.com/jobs/1?trk=redacted",
        host="www.linkedin.com",
        address="8.8.8.8",
        deadline=asyncio.get_running_loop().time() + 2,
    )

    assert response.status_code == 302
    assert response.location == "https://boards.greenhouse.io/acme/jobs/eng-1"
    assert writer.payload.startswith(b"HEAD /jobs/1?trk=redacted HTTP/1.1")
    assert b"GET " not in writer.payload
    assert not reader.body_read
    assert writer.closed


@pytest.mark.asyncio
async def test_transport_sanitizes_socket_argument_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def open_connection(**_kwargs: object) -> tuple[FakeReader, FakeWriter]:
        raise ValueError("raw socket details must not escape")

    monkeypatch.setattr(asyncio, "open_connection", open_connection)

    from role_radar.mailbox.linkedin_resolution.transport import HeadTransportError

    with pytest.raises(HeadTransportError, match="response_protocol"):
        await PinnedHeadTransport().head(
            "https://www.linkedin.com/jobs/1",
            host="www.linkedin.com",
            address="8.8.8.8",
            deadline=asyncio.get_running_loop().time() + 2,
        )
