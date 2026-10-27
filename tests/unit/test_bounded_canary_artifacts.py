from __future__ import annotations

import os
import stat

import pytest

from scripts import bounded_canary_artifacts as artifacts

MODE = 0o600
PAYLOAD = b"synthetic-private-payload"


def _owner(info, uid, gid):
    # Root ownership is modeled; actual synthetic file content and metadata are real.
    assert (uid, gid) == (0, 0)
    if (info.st_uid, info.st_gid) != (os.getuid(), os.getgid()):
        raise artifacts.ArtifactError("artifact_metadata_invalid")


def _writer(directory_fd, name, payload=PAYLOAD, *, validate_parent=lambda: None):
    return artifacts.write_new_at(
        directory_fd, name, payload, uid=0, gid=0, mode=MODE,
        chown=lambda _fd, _uid, _gid: None, require_owner=_owner,
        validate_parent=validate_parent,
    )


@pytest.mark.parametrize("drift", ["mode", "nlink", "owner", "type", "identity"])
def test_prewrite_revalidation_rejects_metadata_and_path_drift(tmp_path, drift):
    directory = tmp_path / "artifacts"
    directory.mkdir(mode=0o700)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    calls = 0
    destination = directory / "record.bin"

    def drift_before_write():
        nonlocal calls
        calls += 1
        if calls != 3:
            return
        if drift == "mode":
            destination.chmod(0o644)
        elif drift == "nlink":
            os.link(destination, directory / "second-link")
        elif drift == "owner":
            raise artifacts.ArtifactError("artifact_metadata_invalid")
        elif drift == "type":
            destination.unlink()
            destination.symlink_to("missing-target")
        else:
            destination.rename(directory / "held.bin")
            destination.write_bytes(b"replacement")
            destination.chmod(MODE)

    try:
        with pytest.raises(artifacts.ArtifactError, match="artifact_metadata_invalid"):
            _writer(fd, "record.bin", validate_parent=drift_before_write)
        assert calls == 3
        if drift in ("mode", "nlink"):
            assert destination.stat(follow_symlinks=False).st_size == 0
        elif drift == "type":
            assert destination.is_symlink() and not (directory / "missing-target").exists()
        elif drift == "identity":
            assert (directory / "held.bin").stat().st_size == 0
            assert destination.read_bytes() == b"replacement"
    finally:
        os.close(fd)


def test_successful_write_is_private_single_link_and_descriptor_bound(tmp_path):
    directory = tmp_path / "artifacts"
    directory.mkdir(mode=0o700)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        identity = _writer(fd, "record.bin")
        info = os.stat("record.bin", dir_fd=fd, follow_symlinks=False)
        assert stat.S_ISREG(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == MODE
        assert info.st_nlink == 1
        assert (directory / "record.bin").read_bytes() == PAYLOAD
        assert identity[:2] == (info.st_dev, info.st_ino)
    finally:
        os.close(fd)


def test_empty_destination_is_retained_on_failed_protection_proof(tmp_path):
    directory = tmp_path / "artifacts"
    directory.mkdir(mode=0o700)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        file_fd, identity = artifacts.create_empty_at(
            fd, "database.sqlite", uid=0, gid=0, mode=MODE,
            chown=lambda _fd, _uid, _gid: None, require_owner=_owner,
        )
        os.link(directory / "database.sqlite", directory / "extra-link")
        with pytest.raises(artifacts.ArtifactError, match="artifact_metadata_invalid"):
            artifacts.verify_file(file_fd, fd, "database.sqlite", identity,
                                  uid=0, gid=0, mode=MODE, require_owner=_owner)
        assert (directory / "database.sqlite").stat().st_size == 0
        os.close(file_fd)
    finally:
        os.close(fd)
