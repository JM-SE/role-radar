from __future__ import annotations

import contextlib
import os
import socket
import threading
import time
from pathlib import Path

import pytest

import role_radar.fence_runtime as runtime
from role_radar.execution_fence import FenceError

RUN_ID = "00000000-0000-4000-8000-000000000001"


@pytest.fixture
def runtime_root(synthetic_fence: Path) -> Path:
    return synthetic_fence


def test_canary_channel_waits_for_peer_and_allows_only_after_auth(runtime_root: Path, monkeypatch):
    expected = f"/system.slice/role-radar-canary-worker@{RUN_ID}.service"
    monkeypatch.setattr(runtime, "_read_cgroup_path", lambda _pid: (expected,))
    received: list[bytes] = []

    with runtime.canary_channel(
        RUN_ID, worker_uid=os.getuid(), worker_gid=os.getgid()
    ) as channel:
        with pytest.raises(FenceError):
            channel.allow()

        def worker() -> None:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.connect(str(runtime_root / f"canary-{RUN_ID}.sock"))
                received.append(client.recv(len(runtime.CANARY_READY_TOKEN)))
            finally:
                client.close()

        thread = threading.Thread(target=worker)
        thread.start()
        channel.wait_ready(time.monotonic() + 2)
        channel.allow(time.monotonic() + 2)
        with pytest.raises(FenceError):
            channel.allow(time.monotonic() + 2)
        thread.join(timeout=2)
        assert received == [runtime.CANARY_READY_TOKEN]
    assert not (runtime_root / f"canary-{RUN_ID}.sock").exists()


def test_worker_accepts_fragmented_authorization(runtime_root: Path):
    path = runtime._socket_path(RUN_ID)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chmod(path, runtime.SOCKET_MODE)
    server.listen()

    def send_fragments():
        with server.accept()[0] as connection:
            connection.sendall(runtime.CANARY_READY_TOKEN[:4])
            time.sleep(0.05)
            connection.sendall(runtime.CANARY_READY_TOKEN[4:])

    sender = threading.Thread(target=send_fragments, daemon=True)
    sender.start()
    try:
        runtime._worker_wait_for_token(path, os.getgid(), time.monotonic() + 2)
    finally:
        sender.join(timeout=2)
        server.close()
        os.unlink(path)


def test_canary_channel_timeout_is_fail_closed(runtime_root: Path):
    with runtime.canary_channel(
        RUN_ID, worker_uid=os.getuid(), worker_gid=os.getgid()
    ) as channel:
        with pytest.raises(FenceError):
            channel.wait_ready(time.monotonic() - 1)
        with pytest.raises(FenceError):
            channel.allow()


def test_canary_channel_rejects_wrong_peer_identity(runtime_root: Path, monkeypatch):
    monkeypatch.setattr(
        runtime,
        "_peer_credentials",
        lambda _connection: (os.getpid(), os.getuid() + 1, os.getgid()),
    )
    path = runtime_root / f"canary-{RUN_ID}.sock"
    with runtime.canary_channel(
        RUN_ID, worker_uid=os.getuid(), worker_gid=os.getgid()
    ) as channel:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(path))
            with pytest.raises(FenceError):
                channel.wait_ready(time.monotonic() + 2)
            with pytest.raises(FenceError):
                channel.allow()
        finally:
            client.close()


def test_worker_guard_uses_exclusive_lock_only_for_exact_canary_cgroup(
    runtime_root: Path, monkeypatch
):
    calls: list[bool] = []

    @contextlib.contextmanager
    def fake_acquire(_path, *, exclusive, uid, gid, mode):
        calls.append(exclusive)
        yield object()

    monkeypatch.setattr(runtime, "acquire", fake_acquire)
    monkeypatch.setattr(runtime, "_read_cgroup_path", lambda _pid: ("/user.slice/user.service",))
    with pytest.raises(FenceError), runtime.worker_guard(RUN_ID):
        pytest.fail("a selected canary was authorized outside its unit")
    assert calls == []
    expected = f"/system.slice/role-radar-canary-worker@{RUN_ID}.service"
    monkeypatch.setattr(runtime, "_read_cgroup_path", lambda _pid: (expected,))
    with pytest.raises(FenceError), runtime.worker_guard(RUN_ID):
        pass
    assert calls == [True]


def test_guards_do_not_mask_body_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextlib.contextmanager
    def fake_acquire(_path, *, exclusive, uid, gid, mode):
        yield object()

    monkeypatch.setattr(runtime, "acquire", fake_acquire)
    monkeypatch.setattr(runtime, "_role_gid", lambda: os.getgid())
    with pytest.raises(RuntimeError, match="body"), runtime.producer_guard():
        raise RuntimeError("body")
    with pytest.raises(RuntimeError, match="body"), runtime.worker_guard(None):
        raise RuntimeError("body")
