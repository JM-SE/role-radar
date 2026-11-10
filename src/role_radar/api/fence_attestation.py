"""Private readiness attestation socket for the API process.

The socket is deliberately a small, one-request protocol.  It is not an HTTP
endpoint: the supervisor authenticates the process using the Unix socket's
peer credentials and then checks the response bytes against the pinned fence
release.
"""

from __future__ import annotations

import asyncio
import contextlib
import grp
import os
import pwd
import socket
import stat
from pathlib import Path
from typing import Final

from role_radar.fence_release import FENCE_RELEASE

SERVICE_USER: str = "role-radar"
# Tests and offline callers may set these explicitly.  In normal operation the
# service account and its primary group are the source of truth.
SERVICE_UID: int | None = None
SERVICE_GID: int | None = None

SOCKET_DIR: Path = Path("/run/role-radar/api")
SOCKET_NAME_PREFIX: str = "ready-"
SOCKET_NAME_SUFFIX: str = ".sock"
SOCKET_DIR_MODE: Final[int] = 0o700
SOCKET_MODE: Final[int] = 0o600

READINESS_REQUEST: Final[bytes] = b"role-radar-fence-readiness-v1\n"
READINESS_RESPONSE_PREFIX: Final[bytes] = b"role-radar-fence-ready-v1 "
# The request is intentionally bounded before it reaches application code.
MAX_REQUEST_BYTES: Final[int] = 128
IO_TIMEOUT_SECONDS: float = 1.0


class FenceAttestationError(RuntimeError):
    """Raised when the attestation endpoint cannot be installed safely."""


# Useful spelling for callers that distinguish setup errors from protocol errors.
FenceAttestationSetupError = FenceAttestationError


def service_identity() -> tuple[int, int]:
    """Return the service uid and primary group uid."""

    uid = SERVICE_UID
    gid = SERVICE_GID
    try:
        account = pwd.getpwnam(SERVICE_USER)
        group = grp.getgrnam(SERVICE_USER)
    except (KeyError, OSError) as exc:
        if uid is None or gid is None:
            raise FenceAttestationError("service identity unavailable") from exc
    else:
        if uid is None:
            uid = account.pw_uid
        if gid is None:
            gid = group.gr_gid
    assert uid is not None and gid is not None
    return uid, gid


def socket_path(pid: int | None = None) -> Path:
    """Return the process-specific readiness socket path."""

    process_id = os.getpid() if pid is None else pid
    return SOCKET_DIR / f"{SOCKET_NAME_PREFIX}{process_id}{SOCKET_NAME_SUFFIX}"


def _mode(st: os.stat_result) -> int:
    return stat.S_IMODE(st.st_mode)


def _lstat(path: Path, *, what: str) -> os.stat_result:
    try:
        return os.lstat(path)
    except OSError as exc:
        raise FenceAttestationError(f"{what} unavailable") from exc


def _validate_socket_dir(uid: int, gid: int) -> None:
    st = _lstat(SOCKET_DIR, what="attestation directory")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise FenceAttestationError("attestation directory is not a directory")
    if st.st_uid != uid or st.st_gid != gid or _mode(st) != SOCKET_DIR_MODE:
        raise FenceAttestationError("attestation directory identity or mode invalid")


def _ensure_socket_absent(path: Path) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise FenceAttestationError("attestation socket cannot be inspected") from exc
    raise FenceAttestationError("attestation socket already exists")


def _same_inode(path: Path, expected: tuple[int, int]) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return False
    return not stat.S_ISLNK(st.st_mode) and (st.st_dev, st.st_ino) == expected


class FenceAttestationServer:
    """Async one-request readiness server bound to the current API PID."""

    def __init__(self, server: asyncio.AbstractServer, path: Path, inode: tuple[int, int]) -> None:
        self._server = server
        self.path = path
        self._inode = inode
        self._tasks: set[asyncio.Task[None]] = set()
        self._closed = False

    @classmethod
    async def start(cls) -> FenceAttestationServer:
        """Install the listener, failing startup on every setup error."""

        uid, gid = service_identity()
        _validate_socket_dir(uid, gid)
        path = socket_path()
        _ensure_socket_absent(path)
        raw_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        raw_socket.set_inheritable(False)
        bound_inode: tuple[int, int] | None = None
        try:
            # bind() never replaces an existing pathname.  A race with a stale
            # or foreign inode therefore fails closed with EADDRINUSE.
            raw_socket.bind(os.fspath(path))
            st = os.lstat(path)
            bound_inode = (st.st_dev, st.st_ino)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISSOCK(st.st_mode):
                raise FenceAttestationError("attestation socket inode invalid")
            if st.st_uid != uid or st.st_gid != gid or _mode(st) != SOCKET_MODE:
                raise FenceAttestationError("attestation socket identity or mode invalid")
            raw_socket.listen(socket.SOMAXCONN)
            holder: dict[str, FenceAttestationServer] = {}

            def dispatch(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                instance = holder.get("server")
                if instance is None:
                    writer.close()
                    return
                task = asyncio.create_task(instance._serve_client(reader, writer))
                instance._tasks.add(task)
                task.add_done_callback(instance._tasks.discard)

            server = await asyncio.start_unix_server(
                dispatch, sock=raw_socket, limit=MAX_REQUEST_BYTES + 1
            )
            instance = cls(server, path, bound_inode)
            holder["server"] = instance
            return instance
        except asyncio.CancelledError:
            raw_socket.close()
            if bound_inode is not None and _same_inode(path, bound_inode):
                with contextlib.suppress(OSError):
                    os.unlink(path)
            raise
        except FenceAttestationError:
            raw_socket.close()
            if bound_inode is not None and _same_inode(path, bound_inode):
                with contextlib.suppress(OSError):
                    os.unlink(path)
            raise
        except OSError as exc:
            raw_socket.close()
            if bound_inode is not None and _same_inode(path, bound_inode):
                with contextlib.suppress(OSError):
                    os.unlink(path)
            raise FenceAttestationError("attestation listener setup failed") from exc

    async def _serve_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            async with asyncio.timeout(IO_TIMEOUT_SECONDS):
                payload = await reader.readexactly(len(READINESS_REQUEST))
                if payload != READINESS_REQUEST:
                    return
                writer.write(READINESS_RESPONSE_PREFIX + FENCE_RELEASE.encode("ascii") + b"\n")
                await writer.drain()
        except (TimeoutError, OSError, RuntimeError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                async with asyncio.timeout(IO_TIMEOUT_SECONDS):
                    await writer.wait_closed()
            except (TimeoutError, OSError):
                pass

    async def close(self) -> None:
        """Stop accepting and remove only this instance's socket inode."""

        if self._closed:
            return
        self._closed = True
        self._server.close()
        await self._server.wait_closed()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if _same_inode(self.path, self._inode):
            with contextlib.suppress(OSError):
                os.unlink(self.path)

    async def aclose(self) -> None:
        """Alias for async context-manager integrations."""

        await self.close()

    async def __aenter__(self) -> FenceAttestationServer:
        return self

    async def __aexit__(self, _type: object, _value: object, _traceback: object) -> None:
        await self.close()


async def install_fence_attestation() -> FenceAttestationServer:
    """Install and return the API readiness server for lifespan startup."""

    return await FenceAttestationServer.start()
