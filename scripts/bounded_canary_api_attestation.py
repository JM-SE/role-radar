"""Fail-closed attestation of the already-running Role Radar API process.

The supervisor only connects to the socket whose name contains the canonical
systemd MainPID. This module does not create, remove, or mutate any runtime
path. Every failure is deliberately collapsed to :class:`ApiFenceError` so
that local socket details, process information, and protocol bytes never leak
through an operational error.
"""
from __future__ import annotations

import errno
import math
import os
import select
import socket
import stat
import struct
import time
from typing import Final

from role_radar.fence_release import FENCE_RELEASE


class ApiFenceError(RuntimeError):
    """Sanitized, stable error raised for every API fence failure."""

    CODE: Final[str] = "api_fence_unavailable"

    def __init__(self) -> None:
        self.code = self.CODE
        super().__init__(self.CODE)


API_RUNTIME_DIR: Final[str] = "/run/role-radar/api"
API_SOCKET_PREFIX: Final[str] = "ready-"
API_SOCKET_SUFFIX: Final[str] = ".sock"
API_CGROUP_PATH: Final[str] = "/system.slice/role-radar-api.service"
API_RUNTIME_DIR_MODE: Final[int] = 0o700
API_SOCKET_MODE: Final[int] = 0o600
API_READINESS_REQUEST: Final[bytes] = b"role-radar-fence-readiness-v1\n"
API_READINESS_RESPONSE: Final[bytes] = (
    b"role-radar-fence-ready-v1 " + FENCE_RELEASE.encode("ascii") + b"\n"
)
_MAX_ID: Final[int] = (1 << 32) - 1


def _failure() -> ApiFenceError:
    return ApiFenceError()


def _canonical_id(value: object) -> int:
    if type(value) is not int or value < 0 or value > _MAX_ID:
        raise _failure()
    return value


def _canonical_pid(pid: object) -> int:
    if type(pid) is not int or pid <= 1 or pid > _MAX_ID:
        raise _failure()
    return pid


def _canonical_deadline(deadline: object) -> float:
    if type(deadline) not in (int, float):
        raise _failure()
    value = float(deadline)
    if not math.isfinite(value) or value <= time.monotonic():
        raise _failure()
    return value


def _socket_path(pid: int) -> str:
    # pid has already been canonicalized; no caller-controlled path component
    # reaches the fixed runtime directory.
    return os.path.join(API_RUNTIME_DIR, f"{API_SOCKET_PREFIX}{pid}{API_SOCKET_SUFFIX}")


def _directory_metadata(uid: int, gid: int) -> os.stat_result:
    try:
        info = os.lstat(API_RUNTIME_DIR)
    except (OSError, ValueError):
        raise _failure() from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != API_RUNTIME_DIR_MODE
    ):
        raise _failure()
    return info


def _socket_metadata(path: str, uid: int, gid: int) -> os.stat_result:
    try:
        info = os.lstat(path)
    except (OSError, ValueError):
        raise _failure() from None
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != API_SOCKET_MODE
        or info.st_nlink != 1
    ):
        raise _failure()
    return info


def _verify_directory_identity(expected: os.stat_result, uid: int, gid: int) -> None:
    current = _directory_metadata(uid, gid)
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise _failure()


def _verify_path_identity(path: str, expected: os.stat_result, uid: int, gid: int) -> None:
    current = _socket_metadata(path, uid, gid)
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise _failure()


def _read_cgroup_path(pid: int) -> tuple[str, ...]:
    try:
        with open(f"/proc/{pid}/cgroup", encoding="ascii") as handle:
            rows = handle.read().splitlines()
    except (OSError, UnicodeError, ValueError):
        raise _failure() from None
    paths: list[str] = []
    for row in rows:
        fields = row.split(":", 2)
        if len(fields) != 3 or not fields[2].startswith("/"):
            raise _failure()
        paths.append(fields[2])
    if not paths:
        raise _failure()
    return tuple(paths)


def _verify_cgroup(pid: int) -> None:
    if API_CGROUP_PATH not in _read_cgroup_path(pid):
        raise _failure()


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        peer_pid, peer_uid, peer_gid = struct.unpack("3i", raw)
    except (AttributeError, OSError, struct.error):
        raise _failure() from None
    if peer_pid <= 1 or peer_uid < 0 or peer_gid < 0:
        raise _failure()
    return peer_pid, peer_uid, peer_gid


def _verify_peer(connection: socket.socket, pid: int, uid: int, gid: int) -> None:
    peer_pid, peer_uid, peer_gid = _peer_credentials(connection)
    if (peer_pid, peer_uid, peer_gid) != (pid, uid, gid):
        raise _failure()
    _verify_cgroup(pid)


def _wait(connection: socket.socket, *, readable: bool, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _failure()
    try:
        selected = select.select(
            [connection] if readable else [],
            [] if readable else [connection],
            [],
            remaining,
        )
    except (OSError, ValueError):
        raise _failure() from None
    if not (selected[0] if readable else selected[1]):
        raise _failure()


def _connect(connection: socket.socket, path: str, deadline: float) -> None:
    try:
        result = connection.connect_ex(path)
    except (OSError, ValueError):
        raise _failure() from None
    if result == 0:
        return
    if result not in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK):
        raise _failure()
    _wait(connection, readable=False, deadline=deadline)
    try:
        error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    except (OSError, ValueError):
        raise _failure() from None
    if error:
        raise _failure()


def _send_all(connection: socket.socket, payload: bytes, deadline: float) -> None:
    offset = 0
    while offset < len(payload):
        _wait(connection, readable=False, deadline=deadline)
        try:
            written = connection.send(payload[offset:])
        except (BlockingIOError, InterruptedError):
            continue
        except (OSError, ValueError):
            raise _failure() from None
        if written <= 0:
            raise _failure()
        offset += written


def _receive_exact(connection: socket.socket, expected: bytes, deadline: float) -> None:
    received = bytearray()
    while len(received) < len(expected):
        _wait(connection, readable=True, deadline=deadline)
        try:
            chunk = connection.recv(len(expected) - len(received))
        except (BlockingIOError, InterruptedError):
            continue
        except (OSError, ValueError):
            raise _failure() from None
        if not chunk:
            raise _failure()
        received.extend(chunk)
    if bytes(received) != expected:
        raise _failure()

    # Reject an already-readable trailing byte without waiting for a peer that
    # intentionally keeps the control connection open after its reply.
    try:
        readable, _, _ = select.select([connection], [], [], 0.0)
    except (OSError, ValueError):
        raise _failure() from None
    if readable:
        try:
            if connection.recv(1):
                raise _failure()
        except (BlockingIOError, InterruptedError):
            pass
        except (OSError, ValueError):
            raise _failure() from None


def verify_api_fence(*, pid: int, uid: int, gid: int, deadline: float) -> None:
    """Attest the exact local API process before allowing canary effects.

    ``deadline`` is an absolute ``time.monotonic()`` deadline. The function
    never creates or removes the fixed directory/socket and returns no peer or
    protocol data. All expected and unexpected operational failures become
    :class:`ApiFenceError` with the single sanitized code.
    """
    connection: socket.socket | None = None
    try:
        canonical_pid = _canonical_pid(pid)
        canonical_uid = _canonical_id(uid)
        canonical_gid = _canonical_id(gid)
        canonical_deadline = _canonical_deadline(deadline)
        expected_directory = _directory_metadata(canonical_uid, canonical_gid)
        path = _socket_path(canonical_pid)
        expected_socket = _socket_metadata(path, canonical_uid, canonical_gid)
        try:
            connection = socket.socket(
                socket.AF_UNIX,
                socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0),
            )
            connection.setblocking(False)
            _connect(connection, path, canonical_deadline)
            _verify_peer(connection, canonical_pid, canonical_uid, canonical_gid)
            _verify_path_identity(path, expected_socket, canonical_uid, canonical_gid)
            _send_all(connection, API_READINESS_REQUEST, canonical_deadline)
            _receive_exact(connection, API_READINESS_RESPONSE, canonical_deadline)
            _verify_directory_identity(expected_directory, canonical_uid, canonical_gid)
            _verify_path_identity(path, expected_socket, canonical_uid, canonical_gid)
            _verify_peer(connection, canonical_pid, canonical_uid, canonical_gid)
            _verify_cgroup(canonical_pid)
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    raise _failure() from None
                connection = None
    except ApiFenceError:
        raise
    except Exception:
        raise _failure() from None
