from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from scripts import bounded_canary_install_preflight as installer

OLD_BYTES = b"reviewed installed helper preimage\n"
CANDIDATE_BYTES = b"reviewed workspace candidate\n"


def _fixture(tmp_path: Path):
    root = tmp_path / "rootfs"
    root.mkdir(mode=0o700)
    paths = (
        ("opt", 0o755),
        ("opt/role-radar", 0o755),
        ("opt/role-radar/scripts", 0o755),
        ("opt/role-radar/data", 0o755),
        ("root", 0o700),
    )
    for relative, mode in paths:
        directory = root / relative
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(mode)

    target = root / installer.TARGET.relative_to("/")
    target.write_bytes(OLD_BYTES)
    target.chmod(0o644)
    candidate = tmp_path / "candidate.py"
    candidate.write_bytes(CANDIDATE_BYTES)

    owner = (os.getuid(), os.getgid())
    policy = {
        "/": (*owner, 0o700),
        "/opt": (*owner, 0o755),
        "/opt/role-radar": (*owner, 0o755),
        "/opt/role-radar/scripts": (*owner, 0o755),
        "/root": (*owner, 0o700),
    }
    kwargs = {
        "root": root,
        "directory_policy": policy,
        "candidate_path": candidate,
        "expected_candidate_sha256": hashlib.sha256(CANDIDATE_BYTES).hexdigest(),
        "expected_preimage_sha256": hashlib.sha256(OLD_BYTES).hexdigest(),
        "expected_target_owner": owner,
    }
    return root, target, candidate, kwargs


def _tree_state(root: Path):
    state = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            payload = os.readlink(path)
        elif stat.S_ISREG(info.st_mode):
            payload = path.read_bytes()
        else:
            payload = None
        state.append(
            (
                str(path.relative_to(root)),
                info.st_dev,
                info.st_ino,
                stat.S_IFMT(info.st_mode),
                stat.S_IMODE(info.st_mode),
                info.st_uid,
                info.st_gid,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                payload,
            )
        )
    return tuple(state)


def _run(capsys, kwargs):
    result = installer.main([], **kwargs)
    captured = capsys.readouterr()
    return result, captured.out, captured.err


def test_default_plan_pins_only_the_expected_trusted_ancestors():
    assert str(installer.TARGET) == "/opt/role-radar/scripts/bounded_canary_preflight.py"
    assert str(installer.BACKUP) == (
        "/root/role-radar-preflight-status-3c3ec2a23026d05868e7951f34fbeb09"
    )
    assert installer.DIRECTORY_POLICY == {
        "/": (0, 0, 0o755),
        "/opt": (0, 0, 0o755),
        "/opt/role-radar": (1000, 1000, 0o755),
        "/opt/role-radar/scripts": (0, 0, 0o755),
        "/root": (0, 0, 0o700),
    }
    assert "/opt/role-radar/data" not in installer.DIRECTORY_POLICY


def test_trusted_operator_parent_and_root_backup_parent_pass_without_mutation(tmp_path, capsys):
    root, _target, _candidate, kwargs = _fixture(tmp_path)
    data_backups = root / "opt/role-radar/data/backups"
    decoy = tmp_path / "service-owned-decoy"
    decoy.mkdir()
    data_backups.symlink_to(decoy, target_is_directory=True)
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 0
    assert stdout == (
        "INSTALL_PREFLIGHT: PASS (read-only; target preimage and backup path verified)\n"
    )
    assert stderr == ""
    assert _tree_state(root) == before
    assert not (root / installer.BACKUP.relative_to("/")).exists()


def test_wrong_operator_parent_owner_fails_closed_without_mutation(tmp_path, capsys):
    root, _target, _candidate, kwargs = _fixture(tmp_path)
    kwargs["directory_policy"]["/opt/role-radar"] = (os.getuid() + 1, os.getgid(), 0o755)
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 1
    assert stdout == "INSTALL_PREFLIGHT: FAIL (directory_metadata_mismatch)\n"
    assert stderr == ""
    assert _tree_state(root) == before


def test_candidate_hash_mismatch_fails_before_host_path_access(tmp_path, capsys):
    _root, _target, _candidate, kwargs = _fixture(tmp_path)
    kwargs["root"] = tmp_path / "must-not-be-opened"
    kwargs["expected_candidate_sha256"] = "0" * 64

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 1
    assert stdout == "INSTALL_PREFLIGHT: FAIL (candidate_hash_mismatch)\n"
    assert stderr == ""
    assert not kwargs["root"].exists()


def test_candidate_is_proven_regular_before_open_and_symlinks_are_rejected(tmp_path, capsys):
    root, _target, candidate, kwargs = _fixture(tmp_path)

    class StatBeforeOpen:
        def __init__(self):
            self.candidate_stat_seen = False
            self.events = []

        def __getattr__(self, name):
            return getattr(os, name)

        def stat(self, path, *args, **options):
            if os.fspath(path) == os.fspath(candidate):
                self.candidate_stat_seen = True
                self.events.append("stat-candidate")
            return os.stat(path, *args, **options)

        def open(self, path, flags, mode=0o777, *, dir_fd=None):
            if os.fspath(path) == os.fspath(candidate):
                self.events.append("open-candidate")
                assert self.candidate_stat_seen, "candidate was opened before type proof"
            if dir_fd is None:
                return os.open(path, flags, mode)
            return os.open(path, flags, mode, dir_fd=dir_fd)

    fs = StatBeforeOpen()
    kwargs["fs"] = fs
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 0
    assert stdout == (
        "INSTALL_PREFLIGHT: PASS (read-only; target preimage and backup path verified)\n"
    )
    assert stderr == ""
    assert fs.events[:2] == ["stat-candidate", "open-candidate"]
    assert _tree_state(root) == before

    symlink = candidate.with_name("candidate-link.py")
    symlink.symlink_to(candidate.name)
    kwargs["candidate_path"] = symlink
    fs = StatBeforeOpen()
    kwargs["fs"] = fs

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 1
    assert stdout == "INSTALL_PREFLIGHT: FAIL (source_metadata_mismatch)\n"
    assert stderr == ""
    assert "open-candidate" not in fs.events
    assert _tree_state(root) == before


def test_symlink_target_parent_is_rejected_without_mutation(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    scripts = target.parent
    decoy = tmp_path / "decoy-scripts"
    decoy.mkdir()
    scripts.rename(tmp_path / "original-scripts")
    scripts.symlink_to(decoy, target_is_directory=True)
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 1
    assert stdout == "INSTALL_PREFLIGHT: FAIL (filesystem_proof_unavailable)\n"
    assert stderr == ""
    assert _tree_state(root) == before


def test_parent_rebinding_during_preflight_fails_closed(tmp_path, capsys, monkeypatch):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    scripts = target.parent
    displaced = scripts.with_name("scripts-before-rebind")
    original_read = installer._read_target

    def replace_parent_after_read(fs, descriptor, expected_owner):
        digest = original_read(fs, descriptor, expected_owner)
        scripts.rename(displaced)
        scripts.mkdir()
        scripts.chmod(0o755)
        replacement = scripts / installer.TARGET.name
        replacement.write_bytes(OLD_BYTES)
        replacement.chmod(0o644)
        return digest

    monkeypatch.setattr(installer, "_read_target", replace_parent_after_read)

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 1
    assert stdout == "INSTALL_PREFLIGHT: FAIL (parent_chain_changed)\n"
    assert stderr == ""
    assert (displaced / installer.TARGET.name).read_bytes() == OLD_BYTES
    assert target.read_bytes() == OLD_BYTES
    assert not (root / installer.BACKUP.relative_to("/")).exists()


def test_existing_backup_destination_fails_before_target_access(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    backup = root / installer.BACKUP.relative_to("/")
    backup.mkdir()
    target.unlink()
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 1
    assert stdout == "INSTALL_PREFLIGHT: FAIL (backup_destination_exists)\n"
    assert stderr == ""
    assert _tree_state(root) == before


@pytest.mark.parametrize("leaf", ["candidate", "target", "backup"])
@pytest.mark.parametrize("kind", ["fifo", "dangling", "hardlink", "directory"])
def test_special_leaf_is_rejected_without_mutation(tmp_path, capsys, leaf, kind):
    root, target, candidate, kwargs = _fixture(tmp_path)
    backup = root / installer.BACKUP.relative_to("/")
    path = {"candidate": candidate, "target": target, "backup": backup}[leaf]
    if path.exists() or path.is_symlink():
        path.unlink()
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "dangling":
        path.symlink_to("missing")
    elif kind == "hardlink":
        other = tmp_path / "other"
        other.write_bytes(OLD_BYTES)
        os.link(other, path)
    else:
        path.mkdir()

    before = _tree_state(tmp_path)
    code = {
        "candidate": "source_metadata_mismatch",
        "target": "target_metadata_mismatch",
        "backup": "backup_destination_exists",
    }[leaf]
    assert _run(capsys, kwargs) == (
        1,
        f"INSTALL_PREFLIGHT: FAIL ({code})\n",
        "",
    )
    assert _tree_state(tmp_path) == before


@pytest.mark.parametrize("leaf", ["candidate", "target"])
def test_fifo_swap_before_open_fails_closed(tmp_path, capsys, leaf):
    root, target, candidate, kwargs = _fixture(tmp_path)
    victim = candidate if leaf == "candidate" else target

    class Swap:
        def __getattr__(self, name):
            return getattr(os, name)

        def open(self, path, flags, mode=0o777, *, dir_fd=None):
            expected = os.fspath(candidate) if leaf == "candidate" else target.name
            if os.fspath(path) == expected:
                assert flags & os.O_NONBLOCK
                assert flags & os.O_NOFOLLOW
                victim.unlink()
                os.mkfifo(victim)
            return os.open(path, flags, mode, dir_fd=dir_fd)

    kwargs["fs"] = Swap()
    result, stdout, stderr = _run(capsys, kwargs)
    code = "source_changed_during_open" if leaf == "candidate" else "target_changed_during_open"
    assert (result, stdout, stderr) == (
        1,
        f"INSTALL_PREFLIGHT: FAIL ({code})\n",
        "",
    )
    assert stat.S_ISFIFO(victim.lstat().st_mode)
    assert not (root / installer.BACKUP.relative_to("/")).exists()


def test_backup_permission_error_is_not_absence(tmp_path, capsys):
    _root, _target, _candidate, kwargs = _fixture(tmp_path)

    class Deny:
        def __getattr__(self, name):
            return getattr(os, name)

        def stat(self, path, *args, **options):
            if path == installer.BACKUP.name:
                raise PermissionError()
            return os.stat(path, *args, **options)

    kwargs["fs"] = Deny()
    before = _tree_state(tmp_path)
    assert _run(capsys, kwargs) == (
        1,
        "INSTALL_PREFLIGHT: FAIL (backup_destination_unavailable)\n",
        "",
    )
    assert _tree_state(tmp_path) == before


def test_target_symlink_and_preimage_drift_fail_closed(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    replacement = target.with_name("replacement")
    replacement.write_bytes(OLD_BYTES)
    target.unlink()
    target.symlink_to(replacement.name)
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 1
    assert stdout == "INSTALL_PREFLIGHT: FAIL (target_metadata_mismatch)\n"
    assert stderr == ""
    assert _tree_state(root) == before

    target.unlink()
    target.write_bytes(b"unexpected preimage\n")
    target.chmod(0o644)
    kwargs["expected_preimage_sha256"] = hashlib.sha256(OLD_BYTES).hexdigest()
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert result == 1
    assert stdout == "INSTALL_PREFLIGHT: FAIL (target_preimage_mismatch)\n"
    assert stderr == ""
    assert _tree_state(root) == before


def test_cli_rejects_path_overrides(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        installer.main(["--target", "/tmp/other"], root=tmp_path / "unused")

    captured = capsys.readouterr()
    assert error.value.code == 2
    assert "unrecognized arguments: --target /tmp/other" in captured.err
    assert captured.out == ""
    assert not (tmp_path / "unused").exists()
