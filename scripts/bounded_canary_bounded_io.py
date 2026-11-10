"""Bounded, fork-based execution for small JSON results.

``call_bounded`` deliberately has a narrow contract: the callable is inherited by
``fork`` rather than serialized, and only a bounded JSON frame crosses the pipe.
The child is placed in its own process group and its standard streams are sent to
``/dev/null``.  This is a process-isolation primitive, not a security sandbox:
a callable can still access resources inherited from the parent and a process
that escapes its process group cannot be forcibly reclaimed by this module.
"""
from __future__ import annotations

import json
import math
import os
import signal
import struct
import time
from collections.abc import Callable
from contextlib import suppress
from select import select
from typing import Any

# This is a wire bound, not a promise that a callable cannot allocate a larger
# object before returning it.  Keeping it well below typical pipe capacities
# also makes one-frame writes practical while the parent drains concurrently.
MAX_RESULT_BYTES = 64 * 1024
_MAX_FRAME_BYTES = 16 + MAX_RESULT_BYTES
_HEADER = struct.Struct("!6sBI")
_MAGIC = b"BCIO01"
_STATUS_OK = 0
_STATUS_CHILD_EXCEPTION = 1
_STATUS_RESULT_INVALID = 2
_STATUS_INTERNAL = 3
_STATUS_OUTPUT_TOO_LARGE = 4
_POLL_SECONDS = 0.01


class BoundedIOError(Exception):
    """A privacy-safe, finite failure from :func:`call_bounded`."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error_frame(status: int) -> bytes:
    return _HEADER.pack(_MAGIC, status, 0)


class _ResultTooLarge(Exception):
    pass


def _encode_result(result: Any) -> bytes:
    # allow_nan=False keeps the frame standard JSON and avoids accepting values
    # that many JSON consumers cannot parse.
    encoded = json.dumps(
        result,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_RESULT_BYTES:
        raise _ResultTooLarge
    return encoded


def _write_nonblocking(fd: int, data: bytes, deadline: float) -> bool:
    """Write one bounded frame without allowing a blocked pipe to hang a child."""
    offset = 0
    while offset < len(data):
        try:
            written = os.write(fd, data[offset:])
        except InterruptedError:
            continue
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return False
            # A short bounded sleep avoids a busy loop while the parent drains.
            with suppress(InterruptedError):
                select([], [], [], min(_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
            continue
        except OSError:
            return False
        if written <= 0:
            return False
        offset += written
    return True


def _child_main(write_fd: int, fn: Callable[[], Any], deadline: float) -> None:
    """Run in the fork child; every exit path uses ``os._exit``."""
    try:
        # The child makes this call itself so a parent scheduling race cannot
        # leave the callable in the parent's process group.
        os.setpgid(0, 0)
        os.set_blocking(write_fd, False)
        read_fd = None
        try:
            read_fd = os.open(os.devnull, os.O_RDWR)
            os.dup2(read_fd, 1)
            os.dup2(read_fd, 2)
        finally:
            if read_fd is not None and read_fd > 2:
                with suppress(OSError):
                    os.close(read_fd)

        try:
            result = fn()
        except BaseException:
            _write_nonblocking(write_fd, _error_frame(_STATUS_CHILD_EXCEPTION), deadline)
            os._exit(1)

        try:
            payload = _encode_result(result)
            frame = _HEADER.pack(_MAGIC, _STATUS_OK, len(payload)) + payload
        except _ResultTooLarge:
            _write_nonblocking(write_fd, _error_frame(_STATUS_OUTPUT_TOO_LARGE), deadline)
            os._exit(1)
        except BaseException:
            _write_nonblocking(write_fd, _error_frame(_STATUS_RESULT_INVALID), deadline)
            os._exit(1)

        if not _write_nonblocking(write_fd, frame, deadline):
            os._exit(1)
        os._exit(0)
    except BaseException:
        # This includes failure to create the process group or redirect the
        # streams.  Never send exception text or a traceback through the pipe.
        with suppress(BaseException):
            _write_nonblocking(write_fd, _error_frame(_STATUS_INTERNAL), deadline)
        os._exit(1)

def _signal_process(pid: int, sig: signal.Signals) -> None:
    with suppress(ProcessLookupError, PermissionError, OSError):
        os.kill(pid, sig)


def _signal_group(pid: int, sig: signal.Signals) -> None:
    with suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(pid, sig)


def _reap_bounded(pid: int) -> bool:
    """Kill and reap without waiting; the caller's deadline remains strict."""
    # The leader is deliberately not reaped before killpg.  Until waitpid below
    # succeeds, its PID/PGID cannot be reused for an unrelated process group.
    _signal_group(pid, signal.SIGTERM)
    _signal_process(pid, signal.SIGTERM)
    _signal_group(pid, signal.SIGKILL)
    _signal_process(pid, signal.SIGKILL)
    while True:
        try:
            waited, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return False
        except InterruptedError:
            continue
        except OSError:
            return False
        return waited == pid


def _read_available(fd: int, buffer: bytearray) -> str | None:
    """Drain a nonblocking pipe; return a fixed parse error or ``None``."""
    while True:
        try:
            chunk = os.read(fd, 8192)
        except InterruptedError:
            continue
        except BlockingIOError:
            return None
        except OSError:
            return "channel_read_failed"
        if not chunk:
            return None
        buffer.extend(chunk)
        if len(buffer) > _MAX_FRAME_BYTES:
            return "output_too_large"


def _parse_frame(buffer: bytearray) -> tuple[int, Any] | str | None:
    if len(buffer) < _HEADER.size:
        return None
    magic, status, length = _HEADER.unpack(buffer[:_HEADER.size])
    if magic != _MAGIC:
        return "channel_invalid"
    if length > MAX_RESULT_BYTES:
        return "output_too_large"
    total = _HEADER.size + length
    if len(buffer) < total:
        return None
    if len(buffer) != total:
        return "channel_extra_data"
    payload = bytes(buffer[_HEADER.size:total])
    if status != _STATUS_OK:
        if status == _STATUS_CHILD_EXCEPTION:
            return "child_exception"
        if status == _STATUS_RESULT_INVALID:
            return "result_invalid"
        if status == _STATUS_OUTPUT_TOO_LARGE:
            return "output_too_large"
        return "child_failed"
    try:
        # Re-encoding is intentionally not used as validation: JSON's parser
        # already rejects malformed syntax, and the child produced this frame.
        result = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "channel_invalid"
    return status, result


def call_bounded(fn: Callable[[], Any], *, deadline: float) -> Any:
    """Run ``fn`` in a fork child until an absolute monotonic deadline.

    The returned value is JSON-decoded from a bounded private pipe.  ``fn`` must
    therefore be callable after ``fork`` and return a JSON-compatible value.
    Every failure is represented by :class:`BoundedIOError` with a fixed code;
    exception text, child stdout/stderr, and arbitrary Python object state never
    cross the process boundary.
    """
    if not callable(fn):
        raise BoundedIOError("callable_invalid")
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise BoundedIOError("deadline_invalid")
    try:
        deadline_value = float(deadline)
    except (OverflowError, ValueError):
        raise BoundedIOError("deadline_invalid") from None
    if not math.isfinite(deadline_value):
        raise BoundedIOError("deadline_invalid")
    if time.monotonic() >= deadline_value:
        raise BoundedIOError("deadline_expired")

    read_fd = write_fd = -1
    try:
        read_fd, write_fd = os.pipe()
        pid = os.fork()
    except OSError:
        if read_fd >= 0:
            with suppress(OSError):
                os.close(read_fd)
        if write_fd >= 0:
            with suppress(OSError):
                os.close(write_fd)
        raise BoundedIOError("fork_failed") from None

    if pid == 0:
        with suppress(OSError):
            os.close(read_fd)
        _child_main(write_fd, fn, deadline_value)
        os._exit(1)

    os.close(write_fd)
    try:
        os.set_blocking(read_fd, False)
    except OSError:
        _reap_bounded(pid)
        os.close(read_fd)
        raise BoundedIOError("channel_unavailable") from None

    # Parent-side setpgid closes the small race before the child executes its
    # own setpgid.  ESRCH only means the child already exited.
    try:
        os.setpgid(pid, pid)
    except ProcessLookupError:
        pass
    except OSError:
        os.close(read_fd)
        _reap_bounded(pid)
        raise BoundedIOError("process_group_unavailable") from None

    buffer = bytearray()
    child_status: Any | None = None
    failure: str | None = None
    frame: tuple[int, Any] | str | None = None
    try:
        while True:
            now = time.monotonic()
            if now >= deadline_value:
                failure = "timeout"
                break

            if child_status is None:
                try:
                    observed = os.waitid(
                        os.P_PID,
                        pid,
                        os.WEXITED | os.WNOHANG | os.WNOWAIT,
                    )
                except ChildProcessError:
                    failure = "child_not_reapable"
                    break
                except InterruptedError:
                    continue
                except OSError:
                    failure = "child_not_reapable"
                    break
                if observed is not None and observed.si_pid == pid:
                    # WNOWAIT keeps the leader unreaped while its process group
                    # is terminated, preventing PID/PGID reuse races.
                    child_status = observed

            if failure is None:
                failure = _read_available(read_fd, buffer)
                if failure is None:
                    frame = _parse_frame(buffer)
                    if isinstance(frame, str):
                        failure = frame

            if failure is None and child_status is not None:
                if frame is None:
                    # Do not wait for EOF: a descendant may retain this fd.
                    failure = "channel_incomplete"
                elif isinstance(frame, str):
                    failure = frame
                elif (
                    child_status.si_code != os.CLD_EXITED
                    or child_status.si_status != 0
                ):
                    failure = "child_failed"
                else:
                    # WNOWAIT kept the leader unreaped.  Kill descendants
                    # before the final nonblocking waitpid can free its PID.
                    if time.monotonic() >= deadline_value:
                        failure = "timeout"
                    elif not _reap_bounded(pid):
                        failure = "child_not_reapable"
                    else:
                        return frame[1]

            if failure is not None:
                break
            remaining = max(0.0, deadline_value - time.monotonic())
            with suppress(InterruptedError):
                select([read_fd], [], [], min(_POLL_SECONDS, remaining))
    finally:
        os.close(read_fd)

    _reap_bounded(pid)
    raise BoundedIOError(failure or "child_failed")
