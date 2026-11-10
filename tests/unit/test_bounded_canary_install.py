from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from scripts import bounded_canary_install as installer

OLD_BYTES = b"reviewed installed parser preimage\n"
CANDIDATE_BYTES = b"reviewed parser candidate\n"


def _fixture(tmp_path: Path):
    root = tmp_path / "rootfs"
    root.mkdir(mode=0o700)
    paths = (
        ("opt", 0o755),
        ("opt/role-radar", 0o755),
        ("opt/role-radar/scripts", 0o755),
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
        "require_root": False,
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


def test_install_atomically_replaces_target_and_preserves_protected_preimage(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    backup = root / installer.BACKUP.relative_to("/")

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (0, "PARSER_INSTALL: PASS\n", "")
    assert target.read_bytes() == CANDIDATE_BYTES
    target_info = target.lstat()
    assert (target_info.st_uid, target_info.st_gid, stat.S_IMODE(target_info.st_mode)) == (
        *kwargs["expected_target_owner"],
        0o644,
    )
    assert target_info.st_nlink == 1
    assert backup.is_dir()
    backup_info = backup.lstat()
    assert (backup_info.st_uid, backup_info.st_gid, stat.S_IMODE(backup_info.st_mode)) == (
        *kwargs["expected_target_owner"],
        0o700,
    )
    assert {path.name for path in backup.iterdir()} == {installer.BACKUP_FILE_NAME}
    preimage = backup / installer.BACKUP_FILE_NAME
    assert preimage.read_bytes() == OLD_BYTES
    preimage_info = preimage.lstat()
    assert (preimage_info.st_uid, preimage_info.st_gid, stat.S_IMODE(preimage_info.st_mode)) == (
        *kwargs["expected_target_owner"],
        0o600,
    )
    assert preimage_info.st_nlink == 1
    assert {path.name for path in target.parent.iterdir()} == {target.name}


def test_candidate_hash_mismatch_fails_before_target_path_access(tmp_path, capsys):
    _root, _target, _candidate, kwargs = _fixture(tmp_path)
    kwargs["root"] = tmp_path / "must-not-be-opened"
    kwargs["expected_candidate_sha256"] = "0" * 64

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (candidate_hash_mismatch)\n",
        "",
    )
    assert not kwargs["root"].exists()


def test_wrong_target_preimage_fails_without_any_mutation(tmp_path, capsys):
    _root, _target, _candidate, kwargs = _fixture(tmp_path)
    kwargs["expected_preimage_sha256"] = "0" * 64
    before = _tree_state(tmp_path)

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (target_preimage_mismatch)\n",
        "",
    )
    assert _tree_state(tmp_path) == before


def test_existing_backup_fails_without_touching_target_or_backup(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    backup = root / installer.BACKUP.relative_to("/")
    backup.mkdir(mode=0o700)
    marker = backup / "keep"
    marker.write_bytes(b"existing")
    target.unlink()
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (backup_destination_exists)\n",
        "",
    )
    assert _tree_state(root) == before


def test_untrusted_target_parent_fails_without_mutation(tmp_path, capsys):
    root, _target, _candidate, kwargs = _fixture(tmp_path)
    kwargs["directory_policy"]["/opt/role-radar/scripts"] = (
        os.getuid(),
        os.getgid(),
        0o700,
    )
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (directory_metadata_mismatch)\n",
        "",
    )
    assert _tree_state(root) == before


def test_symlinked_target_parent_is_rejected_without_mutation(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    scripts_dir = target.parent
    displaced = scripts_dir.with_name("scripts-displaced")
    scripts_dir.rename(displaced)
    scripts_dir.symlink_to(displaced)
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (filesystem_proof_unavailable)\n",
        "",
    )
    assert _tree_state(root) == before


def test_existing_stage_fails_without_mutation(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    stage = target.parent / installer.STAGE_FILE_NAME
    stage.write_bytes(b"preserve this existing file")
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (stage_destination_exists)\n",
        "",
    )
    assert _tree_state(root) == before


def test_target_fifo_swap_before_open_fails_closed(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)

    class Swap:
        def __getattr__(self, name):
            return getattr(os, name)

        def open(self, path, flags, mode=0o777, *, dir_fd=None):
            if os.fspath(path) == target.name:
                assert flags & os.O_NONBLOCK
                assert flags & os.O_NOFOLLOW
                target.unlink()
                os.mkfifo(target)
            return os.open(path, flags, mode, dir_fd=dir_fd)

    kwargs["fs"] = Swap()
    before = _tree_state(root)

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (target_changed_during_open)\n",
        "",
    )
    assert stat.S_ISFIFO(target.lstat().st_mode)
    assert not (root / installer.BACKUP.relative_to("/")).exists()
    assert _tree_state(root) != before


def test_candidate_fifo_swap_before_open_fails_without_target_access(tmp_path, capsys):
    _root, _target, candidate, kwargs = _fixture(tmp_path)

    class Swap:
        def __getattr__(self, name):
            return getattr(os, name)

        def open(self, path, flags, mode=0o777, *, dir_fd=None):
            if os.fspath(path) == os.fspath(candidate):
                assert flags & os.O_NONBLOCK
                assert flags & os.O_NOFOLLOW
                candidate.unlink()
                os.mkfifo(candidate)
            return os.open(path, flags, mode, dir_fd=dir_fd)

    kwargs["fs"] = Swap()
    kwargs["root"] = tmp_path / "must-not-be-opened"

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (candidate_changed_during_open)\n",
        "",
    )
    assert stat.S_ISFIFO(candidate.lstat().st_mode)
    assert not kwargs["root"].exists()


def test_stage_write_failure_closes_descriptor_and_keeps_preimage(tmp_path, capsys, monkeypatch):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    backup = root / installer.BACKUP.relative_to("/")
    real_open, real_write, real_close = os.open, os.write, os.close
    stage_fd = None
    stage_fd_closed = False

    def observe_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal stage_fd
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if os.fspath(path) == installer.STAGE_FILE_NAME and flags & os.O_CREAT:
            stage_fd = descriptor
        return descriptor

    def fail_stage_write(descriptor, data):
        if descriptor == stage_fd:
            raise OSError("injected stage write failure")
        return real_write(descriptor, data)

    def record_close(descriptor):
        nonlocal stage_fd_closed
        if descriptor == stage_fd:
            stage_fd_closed = True
        return real_close(descriptor)

    monkeypatch.setattr(installer.artifacts.os, "open", observe_open)
    monkeypatch.setattr(installer.artifacts.os, "write", fail_stage_write)
    monkeypatch.setattr(installer.artifacts.os, "close", record_close)

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (stage_outcome_uncertain)\n",
        "",
    )
    assert stage_fd is not None
    assert stage_fd_closed
    assert target.read_bytes() == OLD_BYTES
    assert (backup / installer.BACKUP_FILE_NAME).read_bytes() == OLD_BYTES
    assert (target.parent / installer.STAGE_FILE_NAME).read_bytes() == b""


def test_backup_directory_rebinding_stops_before_target_replacement(tmp_path, capsys, monkeypatch):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    backup = root / installer.BACKUP.relative_to("/")
    displaced = backup.with_name("backup-displaced")

    real_open, real_mkdir = os.open, os.mkdir
    backup_identity = None
    rebound = False

    def observe_mkdir(path, mode=0o777, *, dir_fd=None):
        nonlocal backup_identity
        result = real_mkdir(path, mode, dir_fd=dir_fd)
        if os.fspath(path) == installer.BACKUP.name:
            info = backup.lstat()
            backup_identity = (info.st_dev, info.st_ino)
        return result

    def rebind_before_backup_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal rebound
        if (
            not rebound
            and os.fspath(path) == installer.BACKUP_FILE_NAME
            and dir_fd is not None
            and backup_identity is not None
        ):
            info = os.fstat(dir_fd)
            if (info.st_dev, info.st_ino) == backup_identity:
                backup.rename(displaced)
                backup.mkdir(mode=0o700)
                rebound = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(installer.artifacts.os, "open", rebind_before_backup_open)
    monkeypatch.setattr(installer.artifacts.os, "mkdir", observe_mkdir)

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (backup_outcome_uncertain)\n",
        "",
    )
    assert target.read_bytes() == OLD_BYTES
    assert not any(backup.iterdir())
    assert (displaced / installer.BACKUP_FILE_NAME).read_bytes() == b""


def test_post_replace_verification_error_is_reported_as_uncertain(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    backup = root / installer.BACKUP.relative_to("/")

    class ReadAfterReplaceFailure:
        def __init__(self):
            self.replaced = False
            self.failed = False

        def __getattr__(self, name):
            return getattr(os, name)

        def replace(self, *args, **options):
            result = os.replace(*args, **options)
            self.replaced = True
            return result

        def read(self, descriptor, size):
            if self.replaced and not self.failed:
                self.failed = True
                raise OSError("injected post-replace read failure")
            return os.read(descriptor, size)

    kwargs["fs"] = ReadAfterReplaceFailure()

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (install_outcome_uncertain)\n",
        "",
    )
    assert target.read_bytes() == CANDIDATE_BYTES
    assert (backup / installer.BACKUP_FILE_NAME).read_bytes() == OLD_BYTES


def test_replace_error_reports_uncertainty_and_preserves_preimage_backup(tmp_path, capsys):
    root, target, _candidate, kwargs = _fixture(tmp_path)
    backup = root / installer.BACKUP.relative_to("/")

    class ReplaceThenError:
        def __getattr__(self, name):
            return getattr(os, name)

        def replace(self, *args, **options):
            os.replace(*args, **options)
            raise OSError("injected post-replace uncertainty")

    kwargs["fs"] = ReplaceThenError()

    result, stdout, stderr = _run(capsys, kwargs)

    assert (result, stdout, stderr) == (
        1,
        "PARSER_INSTALL: FAIL (install_outcome_uncertain)\n",
        "",
    )
    assert target.read_bytes() == CANDIDATE_BYTES
    assert (backup / installer.BACKUP_FILE_NAME).read_bytes() == OLD_BYTES


def test_cli_requires_root_by_default_without_touching_target(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(installer.os, "geteuid", lambda: 1000)
    root = tmp_path / "must-not-be-opened"

    result, stdout, stderr = _run(capsys, {"root": root})

    assert (result, stdout, stderr) == (1, "PARSER_INSTALL: FAIL (root_required)\n", "")
    assert not root.exists()


def test_cli_rejects_path_overrides(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        installer.main(["--target", "/tmp/other"], root=tmp_path / "unused")

    captured = capsys.readouterr()
    assert error.value.code == 2
    assert "unrecognized arguments: --target /tmp/other" in captured.err
    assert captured.out == ""
    assert not (tmp_path / "unused").exists()


def test_documented_writer_launch_imports_in_clean_environment(tmp_path):
    import shlex
    import subprocess

    project = Path(installer.__file__).resolve().parents[1]
    runbook = (project / "docs/operations/bounded-canary.md").read_text()
    invocation = next(
        line
        for line in runbook.splitlines()
        if line.startswith("sudo -n ")
        and (
            "scripts/bounded_canary_install.py" in line
            or "-m scripts.bounded_canary_install" in line
        )
    )
    command = shlex.split(invocation)[2:]
    command[0] = str(project / command[0])
    expected_stdout = (
        "usage: bounded_canary_install.py [-h]\n\n"
        "Install the one reviewed canary parser artifact.\n\n"
        "options:\n"
        "  -h, --help  show this help message and exit\n"
    )
    result = subprocess.run(
        [*command, "--help"],
        cwd=project,
        env={
            "PATH": os.defpath,
            "HOME": str(tmp_path),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert (result.returncode, result.stdout, result.stderr) == (0, expected_stdout, "")
    assert list(tmp_path.iterdir()) == []
