"""Synthetic AF_UNIX tests for the API readiness attestation."""

from __future__ import annotations

import asyncio
import os
import socket
import stat
import struct
from collections.abc import Iterator
from pathlib import Path

import pytest

import role_radar.api.fence_attestation as attestation


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def socket_identity(
    tmp_path: Path, synthetic_fence: Path, monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    old_umask = os.umask(0o177)
    directory = synthetic_fence / "api"
    directory.chmod(0o700)
    monkeypatch.setattr(attestation, "SOCKET_DIR", directory)
    monkeypatch.setattr(attestation, "SERVICE_UID", os.getuid())
    monkeypatch.setattr(attestation, "SERVICE_GID", os.getgid())
    monkeypatch.setattr(attestation, "IO_TIMEOUT_SECONDS", 0.1)
    try:
        yield directory
    finally:
        path = directory / f"ready-{os.getpid()}.sock"
        if path.exists() or path.is_symlink():
            path.unlink()
        os.umask(old_umask)


@pytest.mark.anyio
async def test_stale_path_fails_without_replacement(socket_identity: Path) -> None:
    path = attestation.socket_path()
    path.write_bytes(b"stale")

    with pytest.raises(attestation.FenceAttestationError):
        await attestation.FenceAttestationServer.start()

    assert path.read_bytes() == b"stale"


@pytest.mark.anyio
async def test_insecure_umask_fails_closed(socket_identity: Path) -> None:
    old_umask = os.umask(0o077)
    try:
        with pytest.raises(attestation.FenceAttestationError):
            await attestation.FenceAttestationServer.start()
    finally:
        os.umask(old_umask)
    assert not attestation.socket_path().exists()


@pytest.mark.anyio
async def test_peer_and_exact_payload(socket_identity: Path) -> None:
    server = await attestation.FenceAttestationServer.start()
    assert stat.S_IMODE(server.path.stat().st_mode) == 0o600
    try:
        reader, writer = await asyncio.open_unix_connection(os.fspath(server.path))
        try:
            client = writer.get_extra_info("socket")
            peer_pid, peer_uid, peer_gid = struct.unpack(
                "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            assert peer_pid == os.getpid()
            assert (peer_uid, peer_gid) == (os.getuid(), os.getgid())
            writer.write(attestation.READINESS_REQUEST)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=1)
            assert response == (
                attestation.READINESS_RESPONSE_PREFIX
                + attestation.FENCE_RELEASE.encode("ascii")
                + b"\n"
            )
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        await server.close()


@pytest.mark.anyio
async def test_bad_payload_is_closed(socket_identity: Path) -> None:
    server = await attestation.FenceAttestationServer.start()
    try:
        reader, writer = await asyncio.open_unix_connection(os.fspath(server.path))
        writer.write(b"wrong-payload\n")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), timeout=1) == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await server.close()


@pytest.mark.anyio
async def test_cleanup_never_unlinks_replacement_inode(socket_identity: Path) -> None:
    server = await attestation.FenceAttestationServer.start()
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.path.unlink()
        replacement.bind(os.fspath(server.path))
        replacement.listen(1)
        await server.close()
        assert server.path.exists()
    finally:
        replacement.close()
        if server.path.exists():
            server.path.unlink()


@pytest.mark.anyio
async def test_main_lifespan_installs_and_removes_attestation(
    socket_identity: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import role_radar.main as main
    from role_radar.config import Settings

    monkeypatch.setattr(
        main, "Settings",
        lambda: Settings(database_url=f"sqlite:///{tmp_path / 'synthetic.db'}"),
    )
    app = main.create_app()
    path = attestation.socket_path()
    async with app.router.lifespan_context(app):
        assert path.exists()
    assert not path.exists()
