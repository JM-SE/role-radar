from __future__ import annotations

import fcntl
import multiprocessing
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from role_radar.execution_fence import FenceError, acquire


def _identity() -> tuple[int, int]:
    return os.getuid(), os.getgid()


def _receive(connection: Any, process: Any) -> Any:
    if not connection.poll(5):
        if process.is_alive():
            process.terminate()
        process.join(timeout=5)
        pytest.fail("synthetic fence process did not respond")
    return connection.recv()


def _hold(path: str, exclusive: bool, ready: Any, release: Any) -> None:
    uid, gid = _identity()
    try:
        with acquire(path, exclusive=exclusive, uid=uid, gid=gid, mode=0o600):
            ready.send("ready")
            release.recv()
        ready.send("released")
    except FenceError as exc:
        ready.send(("error", exc.code))


def _try_acquire(path: str, exclusive: bool, result: Any) -> None:
    uid, gid = _identity()
    try:
        with acquire(path, exclusive=exclusive, uid=uid, gid=gid, mode=0o600):
            result.send("acquired")
    except FenceError as exc:
        result.send(("error", exc.code))


def _start_holder(path: Path, *, exclusive: bool):
    context = multiprocessing.get_context("fork")
    ready_parent, ready_child = context.Pipe()
    release_parent, release_child = context.Pipe()
    process = context.Process(
        target=_hold,
        args=(str(path), exclusive, ready_child, release_child),
    )
    process.start()
    assert _receive(ready_parent, process) == "ready"
    return process, ready_parent, release_parent


def _stop_holder(process: Any, ready: Any, release: Any) -> None:
    release.send("release")
    assert _receive(ready, process) == "released"
    process.join(timeout=5)
    assert process.exitcode == 0


def _attempt(path: Path, *, exclusive: bool) -> Any:
    context = multiprocessing.get_context("fork")
    parent, child = context.Pipe()
    process = context.Process(target=_try_acquire, args=(str(path), exclusive, child))
    process.start()
    result = _receive(parent, process)
    process.join(timeout=5)
    assert process.exitcode == 0
    return result


def _new_lock_file(path: Path) -> tuple[int, int]:
    path.touch()
    path.chmod(0o600)
    return _identity()


def test_shared_producers_can_hold_the_same_fence(tmp_path: Path) -> None:
    path = tmp_path / "execution.lock"
    uid, gid = _new_lock_file(path)
    context = multiprocessing.get_context("fork")
    processes = []
    ready = []
    releases = []
    try:
        for _ in range(3):
            ready_parent, ready_child = context.Pipe()
            release_parent, release_child = context.Pipe()
            process = context.Process(
                target=_hold,
                args=(str(path), False, ready_child, release_child),
            )
            process.start()
            processes.append(process)
            ready.append(ready_parent)
            releases.append(release_parent)
            assert _receive(ready_parent, process) == "ready"
        assert all(process.is_alive() for process in processes)
        assert uid == os.stat(path).st_uid and gid == os.stat(path).st_gid
    finally:
        for release in releases:
            release.send("release")
        for parent, process in zip(ready, processes, strict=True):
            assert _receive(parent, process) == "released"
        for process in processes:
            process.join(timeout=5)
            assert process.exitcode == 0


@pytest.mark.parametrize(
    ("held_exclusive", "attempt_exclusive"), [(False, True), (True, False)]
)
def test_shared_and_exclusive_modes_are_mutually_exclusive(
    tmp_path: Path, held_exclusive: bool, attempt_exclusive: bool
) -> None:
    path = tmp_path / "execution.lock"
    _new_lock_file(path)
    process, ready, release = _start_holder(path, exclusive=held_exclusive)
    try:
        assert _attempt(path, exclusive=attempt_exclusive) == (
            "error",
            FenceError.CODE,
        )
    finally:
        _stop_holder(process, ready, release)
    assert _attempt(path, exclusive=attempt_exclusive) == "acquired"


def test_forked_helper_cannot_unlock_parent_fence(tmp_path: Path) -> None:
    path = tmp_path / "execution.lock"
    uid, gid = _new_lock_file(path)
    with acquire(path, exclusive=True, uid=uid, gid=gid, mode=0o600) as fence:
        read_fd, write_fd = os.pipe()
        held_fd = fence._fd
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                fcntl.flock(held_fd, fcntl.LOCK_UN)
                os.write(write_fd, b"unlocked")
            except OSError:
                os.write(write_fd, b"closed")
            os._exit(0)
        os.close(write_fd)
        result = os.read(read_fd, 32)
        os.close(read_fd)
        os.waitpid(child, 0)
        assert result == b"closed"
        assert _attempt(path, exclusive=False) == ("error", FenceError.CODE)


def test_nonblocking_contention_fails_closed_without_path_details(tmp_path: Path) -> None:
    path = tmp_path / "private lock [secret]"
    _new_lock_file(path)
    process, ready, release = _start_holder(path, exclusive=True)
    try:
        with pytest.raises(FenceError) as error, acquire(
            path, exclusive=True, uid=os.getuid(), gid=os.getgid(), mode=0o600
        ):
            pytest.fail("contended exclusive lock unexpectedly acquired")
        assert error.value.code == FenceError.CODE
        assert str(path) not in str(error.value)
        assert str(error.value) == FenceError.CODE
    finally:
        _stop_holder(process, ready, release)


def test_descriptor_is_retained_and_path_replacement_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "execution.lock"
    replacement = tmp_path / "replacement.lock"
    uid, gid = _new_lock_file(path)
    _new_lock_file(replacement)
    with acquire(path, exclusive=True, uid=uid, gid=gid, mode=0o600) as fence:
        os.replace(replacement, path)
        with pytest.raises(FenceError):
            fence.verify()
        # The retained descriptor still owns the old inode, not the replacement.
        assert _attempt(path, exclusive=True) == "acquired"
    assert _attempt(path, exclusive=True) == "acquired"


def test_symlink_is_rejected_before_locking(tmp_path: Path) -> None:
    target = tmp_path / "target"
    lock = tmp_path / "execution.lock"
    _new_lock_file(target)
    lock.symlink_to(target)
    with pytest.raises(FenceError) as error, acquire(
        lock, exclusive=True, uid=os.getuid(), gid=os.getgid(), mode=0o600
    ):
        pass
    assert error.value.code == FenceError.CODE


def test_hardlinked_lock_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "execution.lock"
    alias = tmp_path / "alias.lock"
    _new_lock_file(path)
    os.link(path, alias)
    with pytest.raises(FenceError), acquire(
        path, exclusive=True, uid=os.getuid(), gid=os.getgid(), mode=0o600
    ):
        pass


def test_expected_mode_rejects_metadata_drift_before_lock(tmp_path: Path) -> None:
    path = tmp_path / "execution.lock"
    _new_lock_file(path)
    path.chmod(0o640)
    with pytest.raises(FenceError), acquire(
        path, exclusive=True, uid=os.getuid(), gid=os.getgid(), mode=0o600
    ):
        pass


def test_parent_replacement_is_detected_by_anchored_directory_check(tmp_path: Path) -> None:
    parent = tmp_path / "anchor"
    parent.mkdir(mode=0o700)
    path = parent / "execution.lock"
    _new_lock_file(path)
    moved = tmp_path / "old-anchor"
    with acquire(
        path, exclusive=True, uid=os.getuid(), gid=os.getgid(), mode=0o600
    ) as fence:
        os.rename(parent, moved)
        parent.mkdir()
        _new_lock_file(parent / "execution.lock")
        with pytest.raises(FenceError):
            fence.verify()


def test_metadata_drift_is_detected_via_fd_and_name(tmp_path: Path) -> None:
    path = tmp_path / "execution.lock"
    uid, gid = _new_lock_file(path)
    with acquire(path, exclusive=True, uid=uid, gid=gid, mode=0o600) as fence:
        path.chmod(0o640)
        with pytest.raises(FenceError):
            fence.verify()
        path.chmod(0o600)
        assert fence.verify() is fence


def test_release_occurs_when_operation_raises(tmp_path: Path) -> None:
    path = tmp_path / "execution.lock"
    _new_lock_file(path)
    with pytest.raises(RuntimeError, match="operation failed"), acquire(
        path, exclusive=True, uid=os.getuid(), gid=os.getgid(), mode=0o600
    ):
        raise RuntimeError("operation failed")
    assert _attempt(path, exclusive=True) == "acquired"


def test_existing_file_only_and_explicit_metadata_validation(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    with pytest.raises(FenceError):
        acquire(
            missing, exclusive=False, uid=os.getuid(), gid=os.getgid(), mode=0o600
        ).__enter__()

    path = tmp_path / "execution.lock"
    _new_lock_file(path)
    for uid, gid in ((True, os.getgid()), (-1, os.getgid()), (os.getuid(), True)):
        with pytest.raises(FenceError):
            acquire(path, exclusive=False, uid=uid, gid=gid, mode=0o600)
    with pytest.raises(FenceError), acquire(
        path, exclusive=False, uid=os.getuid() + 1, gid=os.getgid(), mode=0o600
    ):
        pass
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_lock_path_is_not_created_or_modified(tmp_path: Path) -> None:
    path = tmp_path / "execution.lock"
    assert not path.exists()
    with pytest.raises(FenceError), acquire(
        path, exclusive=False, uid=os.getuid(), gid=os.getgid(), mode=0o600
    ):
        pass
    assert not path.exists()
