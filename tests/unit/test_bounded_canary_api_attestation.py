from __future__ import annotations

import contextlib
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from scripts import bounded_canary_api_attestation as attestation


@pytest.fixture
def api_socket_root(synthetic_fence: Path, monkeypatch: pytest.MonkeyPatch):
    root = synthetic_fence / "api"
    monkeypatch.setattr(attestation, "API_RUNTIME_DIR", str(root))
    monkeypatch.setattr(
        attestation,
        "_read_cgroup_path",
        lambda _pid: (attestation.API_CGROUP_PATH,),
    )
    yield root
    path = root / f"{attestation.API_SOCKET_PREFIX}{os.getpid()}{attestation.API_SOCKET_SUFFIX}"
    if path.exists() or path.is_symlink():
        path.unlink()


def _listen(root: Path, pid: int) -> tuple[socket.socket, Path]:
    path = root / f"{attestation.API_SOCKET_PREFIX}{pid}{attestation.API_SOCKET_SUFFIX}"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(1)
    return listener, path


def _serve(
    listener: socket.socket,
    response: bytes,
    *,
    delay: float = 0.0,
    replace_path: Path | None = None,
) -> threading.Thread:
    def run() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                if connection.recv(len(attestation.API_READINESS_REQUEST)) != (
                    attestation.API_READINESS_REQUEST
                ):
                    return
                if replace_path is not None:
                    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        os.unlink(replace_path)
                        replacement.bind(str(replace_path))
                        replace_path.chmod(0o600)
                        replacement.listen(1)
                    finally:
                        replacement.close()
                if delay:
                    time.sleep(delay)
                with contextlib.suppress(BrokenPipeError):
                    connection.sendall(response)
        finally:
            listener.close()

    thread = threading.Thread(target=run)
    thread.start()
    return thread


def _verify(root: Path, *, deadline: float | None = None) -> None:
    uid, gid, pid = os.getuid(), os.getgid(), os.getpid()
    attestation.verify_api_fence(
        pid=pid,
        uid=uid,
        gid=gid,
        deadline=time.monotonic() + (1.0 if deadline is None else deadline),
    )


def test_success_attests_exact_peer_and_release(api_socket_root: Path) -> None:
    listener, _ = _listen(api_socket_root, os.getpid())
    thread = _serve(listener, attestation.API_READINESS_RESPONSE)
    try:
        assert _verify(api_socket_root) is None
    finally:
        thread.join(timeout=1)
        assert not thread.is_alive()


def test_wrong_peer_is_sanitized(api_socket_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    listener, _ = _listen(api_socket_root, os.getpid())
    thread = _serve(listener, attestation.API_READINESS_RESPONSE)
    monkeypatch.setattr(
        attestation,
        "_peer_credentials",
        lambda _connection: (os.getpid() + 1, os.getuid(), os.getgid()),
    )
    try:
        with pytest.raises(attestation.ApiFenceError) as error:
            _verify(api_socket_root)
        assert error.value.code == attestation.ApiFenceError.CODE
        assert str(error.value) == attestation.ApiFenceError.CODE
    finally:
        thread.join(timeout=1)


def test_bad_release_is_rejected(api_socket_root: Path) -> None:
    listener, _ = _listen(api_socket_root, os.getpid())
    thread = _serve(listener, b"role-radar-fence-ready-v1 wrong\n")
    try:
        with pytest.raises(attestation.ApiFenceError):
            _verify(api_socket_root)
    finally:
        thread.join(timeout=1)


def test_response_timeout_uses_absolute_deadline(api_socket_root: Path) -> None:
    listener, _ = _listen(api_socket_root, os.getpid())
    thread = _serve(listener, attestation.API_READINESS_RESPONSE, delay=0.2)
    try:
        started = time.monotonic()
        with pytest.raises(attestation.ApiFenceError) as error:
            _verify(api_socket_root, deadline=0.03)
        assert error.value.code == attestation.ApiFenceError.CODE
        assert time.monotonic() - started < 0.15
    finally:
        thread.join(timeout=1)


def test_socket_replacement_after_interaction_is_rejected(api_socket_root: Path) -> None:
    listener, path = _listen(api_socket_root, os.getpid())
    thread = _serve(
        listener,
        attestation.API_READINESS_RESPONSE,
        replace_path=path,
    )
    try:
        with pytest.raises(attestation.ApiFenceError):
            _verify(api_socket_root)
    finally:
        thread.join(timeout=1)


def test_canonical_pid_and_symlink_directory_are_rejected(
    api_socket_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(attestation, "API_RUNTIME_DIR", str(api_socket_root / "missing"))
    with pytest.raises(attestation.ApiFenceError) as error:
        attestation.verify_api_fence(
            pid=1,
            uid=os.getuid(),
            gid=os.getgid(),
            deadline=time.monotonic() + 1,
        )
    assert error.value.code == attestation.ApiFenceError.CODE
