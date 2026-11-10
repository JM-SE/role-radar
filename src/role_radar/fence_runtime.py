"""Cooperating runtime guards for Role Radar execution.

The lock and the canary authorization channel are deliberately fixed paths.  No
runtime value is taken from the environment: callers supply only a canonical run
identifier and (on the supervisor side) the expected worker credentials.
"""

from __future__ import annotations

import contextlib
import errno
import grp
import math
import os
import select
import socket
import stat
import struct
import time
import uuid
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from role_radar.execution_fence import FenceError, acquire

ROOT_UID: Final = 0
GROUP_NAME: Final = "role-radar"
LOCK_PATH: Final = "/run/role-radar/execution.lock"
RUNTIME_DIR: Final = "/run/role-radar"
LOCK_MODE: Final = 0o640
RUNTIME_DIR_MODE: Final = 0o750
SOCKET_MODE: Final = 0o660
SOCKET_PREFIX: Final = "canary-"
CANARY_READY_TOKEN: Final = b"ROLE_RADAR_CANARY_READY\n"
CONNECT_TIMEOUT: Final = 600.0
_EXPECTED_CGROUP_PREFIX: Final = "/system.slice/"


def _failure() -> FenceError:
    return FenceError()


def _role_gid() -> int:
    try:
        value = grp.getgrnam(GROUP_NAME).gr_gid
    except (KeyError, AttributeError, OSError):
        raise _failure() from None
    if type(value) is not int or value < 0 or value > (1 << 32) - 1:
        raise _failure()
    return value


def _canonical_run_id(run_id: object) -> str:
    if not isinstance(run_id, str):
        raise _failure()
    try:
        parsed = uuid.UUID(run_id)
    except (ValueError, AttributeError, TypeError):
        raise _failure() from None
    canonical = str(parsed)
    if run_id != canonical:
        raise _failure()
    return canonical


def _socket_path(run_id: str) -> str:
    # run_id has already been canonicalized, so this cannot escape RUNTIME_DIR.
    return str(Path(RUNTIME_DIR) / f"{SOCKET_PREFIX}{run_id}.sock")


def _runtime_dir_metadata(gid: int) -> os.stat_result:
    try:
        info = os.stat(RUNTIME_DIR, follow_symlinks=False)
    except (OSError, ValueError):
        raise _failure() from None
    if not stat.S_ISDIR(info.st_mode):
        raise _failure()
    if info.st_uid != ROOT_UID or info.st_gid != gid:
        raise _failure()
    if stat.S_IMODE(info.st_mode) != RUNTIME_DIR_MODE:
        raise _failure()
    return info


def _socket_metadata(path: str, gid: int) -> os.stat_result:
    try:
        info = os.lstat(path)
    except (OSError, ValueError):
        raise _failure() from None
    if not stat.S_ISSOCK(info.st_mode):
        raise _failure()
    if info.st_uid != ROOT_UID or info.st_gid != gid:
        raise _failure()
    if stat.S_IMODE(info.st_mode) != SOCKET_MODE:
        raise _failure()
    return info


def _read_cgroup_path(pid: int) -> tuple[str, ...]:
    if type(pid) is not int or pid <= 0:
        raise _failure()
    try:
        with open(f"/proc/{pid}/cgroup", encoding="ascii") as handle:
            rows = handle.read().splitlines()
    except (OSError, UnicodeError):
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


def _is_exact_canary_cgroup(pid: int, run_id: str) -> bool:
    expected = f"{_EXPECTED_CGROUP_PREFIX}role-radar-canary-worker@{run_id}.service"
    return expected in _read_cgroup_path(pid)


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
    except (AttributeError, OSError, struct.error):
        raise _failure() from None
    if pid <= 0 or uid < 0 or gid < 0:
        raise _failure()
    return pid, uid, gid


def _wait_readable(connection: socket.socket, deadline: float) -> None:
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise _failure()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _failure()
    try:
        readable, _, _ = select.select([connection], [], [], remaining)
    except (OSError, ValueError):
        raise _failure() from None
    if not readable:
        raise _failure()


def _verify_path_unchanged(path: str, expected: os.stat_result, gid: int) -> None:
    current = _socket_metadata(path, gid)
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise _failure()
@contextlib.contextmanager
def producer_guard():
    """Hold the shared producer fence for the complete producer operation."""

    gid = _role_gid()
    with acquire(LOCK_PATH, exclusive=False, uid=ROOT_UID, gid=gid, mode=LOCK_MODE) as fence:
        yield fence


class _CanaryChannel:
    __slots__ = (
        "_allowed",
        "_authorized",
        "_connection",
        "_gid",
        "_path",
        "_run_id",
        "_server",
        "_socket_info",
        "_worker_gid",
        "_worker_uid",
    )
    def __init__(self, run_id: str, *, worker_uid: int, worker_gid: int) -> None:
        self._path = _socket_path(run_id)
        self._gid = _role_gid()
        if type(worker_uid) is not int or type(worker_gid) is not int:
            raise _failure()
        if worker_uid < 0 or worker_gid < 0:
            raise _failure()
        self._worker_uid = worker_uid
        self._worker_gid = worker_gid
        self._run_id = run_id
        self._server: socket.socket | None = None
        self._connection: socket.socket | None = None
        self._socket_info: os.stat_result | None = None
        self._authorized = False
        self._allowed = False

    def __enter__(self) -> Self:
        _runtime_dir_metadata(self._gid)
        try:
            # Refuse an existing name: never unlink or replace an unknown socket.
            os.lstat(self._path)
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            raise _failure() from None
        else:
            raise _failure()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        bound_info: os.stat_result | None = None
        try:
            server.setblocking(False)
            server.bind(self._path)
            bound_info = os.lstat(self._path)
            os.chmod(self._path, SOCKET_MODE, follow_symlinks=False)
            os.chown(self._path, ROOT_UID, self._gid, follow_symlinks=False)
            server.listen(1)
            self._socket_info = _socket_metadata(self._path, self._gid)
        except (OSError, ValueError):
            server.close()
            if bound_info is not None:
                with contextlib.suppress(OSError):
                    current = os.lstat(self._path)
                    if (current.st_dev, current.st_ino) == (
                        bound_info.st_dev,
                        bound_info.st_ino,
                    ):
                        os.unlink(self._path)
            raise _failure() from None
        self._server = server
        return self

    def wait_ready(self, deadline: float) -> None:
        if self._server is None or self._connection is not None or self._authorized:
            raise _failure()
        _wait_readable(self._server, deadline)
        connection: socket.socket | None = None
        try:
            connection, _ = self._server.accept()
            connection.setblocking(False)
            pid, uid, gid = _peer_credentials(connection)
            if uid != self._worker_uid or gid != self._worker_gid:
                raise _failure()
            if not _is_exact_canary_cgroup(pid, self._run_id):
                raise _failure()
            expected_socket = self._socket_info
            if expected_socket is None:
                raise _failure()
            _verify_path_unchanged(self._path, expected_socket, self._gid)
        except FenceError:
            if connection is not None:
                with contextlib.suppress(OSError):
                    connection.close()
            raise
        except (OSError, ValueError):
            if connection is not None:
                with contextlib.suppress(OSError):
                    connection.close()
            raise _failure() from None
        self._connection = connection
        self._authorized = True
        listener = self._server
        self._server = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                raise _failure() from None

    def allow(self, deadline: float | None = None) -> None:
        if not self._authorized or self._allowed or self._connection is None:
            raise _failure()
        if deadline is None:
            deadline = time.monotonic() + CONNECT_TIMEOUT
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise _failure()
        expected_socket = self._socket_info
        if expected_socket is None:
            raise _failure()
        _verify_path_unchanged(self._path, expected_socket, self._gid)
        payload = CANARY_READY_TOKEN
        try:
            while payload:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _failure()
                _, writable, _ = select.select([], [self._connection], [], remaining)
                if not writable:
                    raise _failure()
                sent = self._connection.send(payload)
                if sent <= 0:
                    raise _failure()
                payload = payload[sent:]
        except FenceError:
            raise
        except (BlockingIOError, OSError, ValueError):
            raise _failure() from None
        self._allowed = True

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> bool:
        connection = self._connection
        server = self._server
        self._connection = None
        self._server = None
        self._authorized = False
        self._allowed = False
        failure = False
        if connection is not None:
            try:
                connection.close()
            except OSError:
                failure = True
        if server is not None:
            try:
                server.close()
            except OSError:
                failure = True
        # Only remove the exact socket inode created by this context.
        try:
            if self._socket_info is not None:
                current = os.lstat(self._path)
                if (current.st_dev, current.st_ino) == (
                    self._socket_info.st_dev,
                    self._socket_info.st_ino,
                ):
                    os.unlink(self._path)
        except FileNotFoundError:
            pass
        except OSError:
            failure = True
        if failure:
            raise _failure()
        return False




def canary_channel(run_id: str, *, worker_uid: int, worker_gid: int) -> _CanaryChannel:
    """Create a fixed-path, authenticated canary authorization server."""

    canonical = _canonical_run_id(run_id)
    return _CanaryChannel(canonical, worker_uid=worker_uid, worker_gid=worker_gid)


def _worker_wait_for_token(path: str, gid: int, deadline: float) -> None:
    _runtime_dir_metadata(gid)
    info = _socket_metadata(path, gid)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        connection.setblocking(False)
        try:
            connection.connect(path)
        except BlockingIOError:
            pass
        except OSError as error:
            if error.errno != errno.EINPROGRESS:
                raise _failure() from None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _failure()
            _, writable, exceptional = select.select([], [connection], [connection], remaining)
            if exceptional:
                raise _failure()
            if writable:
                try:
                    error_number = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                except OSError:
                    raise _failure() from None
                if error_number:
                    raise _failure()
                break
        _verify_path_unchanged(path, info, gid)
        data = bytearray()
        while len(data) < len(CANARY_READY_TOKEN):
            _wait_readable(connection, deadline)
            chunk = connection.recv(len(CANARY_READY_TOKEN) - len(data))
            if not chunk:
                raise _failure()
            data.extend(chunk)
        if data != CANARY_READY_TOKEN:
            raise _failure()
    except FenceError:
        raise
    except (OSError, ValueError):
        raise _failure() from None
    finally:
        with contextlib.suppress(OSError):
            connection.close()


@contextlib.contextmanager
def worker_guard(run_id: str | None):
    """Hold a shared worker fence, or an authorized exclusive canary fence."""

    gid = _role_gid()
    if run_id is None:
        with acquire(LOCK_PATH, exclusive=False, uid=ROOT_UID, gid=gid, mode=LOCK_MODE) as fence:
            yield fence
        return
    canonical = _canonical_run_id(run_id)
    if not _is_exact_canary_cgroup(os.getpid(), canonical):
        raise _failure()
    path = _socket_path(canonical)
    deadline = time.monotonic() + CONNECT_TIMEOUT
    with acquire(LOCK_PATH, exclusive=True, uid=ROOT_UID, gid=gid, mode=LOCK_MODE) as fence:
        _worker_wait_for_token(path, gid, deadline)
        yield fence


__all__ = [
    "CANARY_READY_TOKEN",
    "FenceError",
    "canary_channel",
    "producer_guard",
    "worker_guard",
]
