"""Offline filesystem contracts for F10.1F private artifacts."""

from __future__ import annotations

from pathlib import Path

import pytest

from role_radar.evaluation.fresh_acquisition.filesystem import (
    FilesystemError,
    atomic_write,
    bounded_read,
    ensure_private_root,
    fenced_lock,
    resolve_nofollow,
    write_no_replace,
)


def test_private_root_is_bounded_private_and_no_follow(tmp_path: Path) -> None:
    root = ensure_private_root(tmp_path / "private" / "f10-1f")

    assert root.is_dir()
    assert root.stat().st_mode & 0o777 == 0o700
    assert resolve_nofollow(root, "dataset", "manifest.json") == root / "dataset" / "manifest.json"

    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(FilesystemError) as exc:
        resolve_nofollow(root, "link", "manifest.json")
    assert exc.value.code == "filesystem_symlink_rejected"


def test_filesystem_rejects_historical_roots_and_symlink_files(tmp_path: Path) -> None:
    with pytest.raises(FilesystemError) as historical:
        ensure_private_root(Path("/opt/role-radar/data/evaluation/snapshot"))
    assert historical.value.code == "filesystem_historical_root_rejected"

    root = ensure_private_root(tmp_path / "private")
    target = tmp_path / "target"
    target.write_bytes(b"not through a link")
    linked = root / "linked"
    linked.symlink_to(target)
    with pytest.raises(FilesystemError) as exc:
        bounded_read(linked)
    assert exc.value.code == "filesystem_symlink_rejected"


def test_reads_and_writes_are_bounded_and_no_replace(tmp_path: Path) -> None:
    root = ensure_private_root(tmp_path / "private")
    target = root / "artifact.json"

    atomic_write(target, b"first", max_bytes=5)
    assert bounded_read(target, max_bytes=5) == b"first"
    atomic_write(target, b"second")
    assert target.read_bytes() == b"second"

    with pytest.raises(FilesystemError) as read_error:
        bounded_read(target, max_bytes=2)
    assert read_error.value.code == "filesystem_read_bound_exceeded"

    write_no_replace(target, b"second")
    with pytest.raises(FilesystemError) as conflict:
        write_no_replace(target, b"different")
    assert conflict.value.code == "filesystem_no_replace_conflict"

    with pytest.raises(FilesystemError) as write_error:
        atomic_write(root / "too-large", b"123", max_bytes=2)
    assert write_error.value.code == "filesystem_write_bound_exceeded"


def test_fence_creates_mode_600_lock_and_rejects_lock_symlink(tmp_path: Path) -> None:
    root = ensure_private_root(tmp_path / "private")
    with fenced_lock(root):
        lock = root / ".f10-1f.fence.lock"
        assert lock.is_file()
        assert lock.stat().st_mode & 0o777 == 0o600

    lock.unlink()
    outside = tmp_path / "lock-target"
    outside.write_bytes(b"")
    lock.symlink_to(outside)
    with pytest.raises(FilesystemError) as exc, fenced_lock(root):
        pass
    assert exc.value.code == "filesystem_symlink_rejected"


def test_existing_parent_mode_is_not_broadened(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o755)
    root = ensure_private_root(parent / "private")

    assert root.stat().st_mode & 0o777 == 0o700
    assert parent.stat().st_mode & 0o777 == 0o755
