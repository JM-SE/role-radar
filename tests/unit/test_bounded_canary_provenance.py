from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from scripts import bounded_canary_provenance as gate

PINS = {path: hashlib.sha256(path.encode()).hexdigest() for path in gate.SOURCE_PATHS}
MODES = {path: (0o664 if path.endswith("discovery/contracts.py") else 0o644)
         for path in gate.SOURCE_PATHS}


@dataclass
class Entry:
    data: bytes
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    nlink: int = 1
    dev: int = 1
    ino: int = 1
    kind: int = stat.S_IFREG
    mtime_ns: int = 1
    ctime_ns: int = 1

    def stat(self):
        return SimpleNamespace(st_mode=self.kind | self.mode, st_uid=self.uid,
                               st_gid=self.gid, st_nlink=self.nlink,
                               st_dev=self.dev, st_ino=self.ino, st_size=len(self.data),
                               st_mtime_ns=self.mtime_ns, st_ctime_ns=self.ctime_ns)


class MemoryFS:
    """In-memory descriptor filesystem; read offsets and EOF match os.read."""

    def __init__(self, pins=PINS):
        self.entries = {path: Entry(path.encode(), mode=MODES[path], ino=i + 100)
                        for i, path in enumerate(pins)}
        self.directories = {"/": Entry(b"", kind=stat.S_IFDIR, ino=1)}
        for path in pins:
            parts = ("opt", "role-radar", *path.split("/")[:-1])
            for index in range(1, len(parts) + 1):
                name = "/" + "/".join(parts[:index])
                self.directories.setdefault(name, Entry(b"", kind=stat.S_IFDIR,
                                                         ino=len(self.directories) + 1))
        self.fds = {}
        self.opened = []
        self.next_fd = 10
        self.reads = []
        self.read_paths = []
        self.closed = []
        self.events = []
        self.rebind_after_read = False
        self.rebind_parent_after_read = False
        self.rebind_on_leaf_open = False

    def _path(self, name, dir_fd=None):
        parent = self.fds[dir_fd][1] if dir_fd is not None else "/"
        return (parent.rstrip("/") + "/" + name).replace("//", "/")

    def open(self, name, flags, dir_fd=None):
        path = name if name == "/" else self._path(name, dir_fd)
        self.events.append(("open", path))
        relative = path.removeprefix("/opt/role-radar/")
        entry = self.directories.get(path) if flags & os.O_DIRECTORY else self.entries.get(relative)
        if entry is None:
            raise FileNotFoundError
        if flags & os.O_DIRECTORY and not stat.S_ISDIR(entry.stat().st_mode):
            raise NotADirectoryError
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = [entry, path, 0]
        self.opened.append(fd)
        if self.rebind_on_leaf_open and not flags & os.O_DIRECTORY:
            self.directories["/opt/role-radar/src"].ino += 100
        return fd

    def stat(self, name, dir_fd=None, follow_symlinks=True):
        path = self._path(name, dir_fd)
        self.events.append(("stat", path))
        entry = self.entries.get(path.removeprefix("/opt/role-radar/"))
        if entry is None:
            raise FileNotFoundError
        return entry.stat()

    def fstat(self, fd):
        return self.fds[fd][0].stat()

    def read(self, fd, size):
        entry, path, offset = self.fds[fd]
        self.reads.append(fd)
        self.read_paths.append(path)
        self.events.append(("read", fd))
        if self.rebind_after_read:
            entry.ino += 1
        if self.rebind_parent_after_read:
            self.directories["/opt/role-radar/src"].ino += 1
        entry.mtime_ns += 1 if self.rebind_after_read else 0
        entry.ctime_ns += 1 if self.rebind_after_read else 0
        chunk = entry.data[offset:offset + size]
        self.fds[fd][2] += len(chunk)
        return chunk

    def close(self, fd):
        self.closed.append(fd)
        self.fds.pop(fd, None)

    def os(self):
        return SimpleNamespace(O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW,
                               O_DIRECTORY=os.O_DIRECTORY, open=self.open,
                               fstat=self.fstat, stat=self.stat, read=self.read,
                               close=self.close)


def _assert_all_fds_closed(fs):
    assert set(fs.opened) == set(fs.closed)
    assert len(fs.opened) == len(fs.closed)
    assert not fs.fds


def test_valid_declared_inventory_passes_using_pinned_bytes_and_safe_metadata():
    fs = MemoryFS()
    report = gate.verify_sources(fs=fs.os(), pins=PINS)
    assert report == len(PINS) == 20
    assert len(fs.reads) >= 20
    _assert_all_fds_closed(fs)


@pytest.mark.parametrize("path", list(PINS))
def test_changed_source_fails_closed_for_every_pinned_blob(path):
    fs = MemoryFS()
    fs.entries[path].data += b"drift"
    with pytest.raises(gate.GateError, match="source_hash_mismatch"):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    _assert_all_fds_closed(fs)


@pytest.mark.parametrize("field,value", [
    ("uid", 1000), ("mode", 0o600), ("nlink", 2), ("kind", stat.S_IFLNK),
])
def test_incompatible_leaf_metadata_fails_before_read(field, value):
    fs = MemoryFS()
    path = next(iter(PINS))
    setattr(fs.entries[path], field, value)
    with pytest.raises(gate.GateError):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    assert fs.reads == []
    _assert_all_fds_closed(fs)


def test_oversized_source_is_rejected_before_read():
    fs = MemoryFS()
    path = next(iter(PINS))
    fs.entries[path].data = b"x" * (gate.MAX_SOURCE_BYTES + 1)
    with pytest.raises(gate.GateError, match="source_size_invalid"):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    assert fs.reads == []
    _assert_all_fds_closed(fs)


def test_compatible_observed_mode_variants_and_known_leaf_modes():
    fs = MemoryFS()
    fs.entries["src/role_radar/cli/main.py"].mode = 0o664
    assert gate.verify_sources(fs=fs.os(), pins=PINS) == 20
    _assert_all_fds_closed(fs)

    fs = MemoryFS()
    fs.entries["src/role_radar/discovery/contracts.py"].mode = 0o644
    with pytest.raises(gate.GateError, match="source_metadata_invalid"):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    assert "discovery/contracts.py" not in fs.read_paths
    _assert_all_fds_closed(fs)


def test_parent_or_path_identity_drift_and_unavailable_proof_fail_closed():
    fs = MemoryFS()
    fs.rebind_after_read = True
    with pytest.raises(gate.GateError):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    _assert_all_fds_closed(fs)

    fs = MemoryFS()
    fs.rebind_parent_after_read = True
    with pytest.raises(gate.GateError, match="source_parent_changed"):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    _assert_all_fds_closed(fs)

    fs = MemoryFS()
    fs.directories["/opt/role-radar/src"].kind = stat.S_IFLNK
    with pytest.raises(gate.GateError, match="source_proof_unavailable"):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    assert fs.reads == []
    _assert_all_fds_closed(fs)

    fs = MemoryFS()
    fs.rebind_on_leaf_open = True
    with pytest.raises(gate.GateError, match="source_parent_changed"):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    assert fs.reads == []
    _assert_all_fds_closed(fs)

    class Unavailable(MemoryFS):
        def open(self, name, flags, dir_fd=None):
            raise PermissionError

    fs = Unavailable()
    with pytest.raises(gate.GateError, match="source_proof_unavailable"):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    assert fs.reads == []
    _assert_all_fds_closed(fs)

    class MissingTimestamps(MemoryFS):
        def fstat(self, fd):
            values = vars(super().fstat(fd)).copy()
            values.pop("st_mtime_ns")
            values.pop("st_ctime_ns")
            return SimpleNamespace(**values)

    fs = MissingTimestamps()
    with pytest.raises(gate.GateError, match="source_proof_unavailable"):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    assert fs.reads == []
    _assert_all_fds_closed(fs)

    fs = MemoryFS()
    del fs.entries[next(iter(PINS))]
    with pytest.raises(gate.GateError, match="source_proof_unavailable"):
        gate.verify_sources(fs=fs.os(), pins=PINS)
    assert fs.reads == []
    _assert_all_fds_closed(fs)


def test_inventory_must_match_the_fixed_declared_path_set():
    fs = MemoryFS()
    with pytest.raises(gate.GateError, match="source_inventory_invalid"):
        gate.verify_sources(fs=fs.os(), pins={})
    assert fs.opened == []
    assert fs.reads == []


def test_cli_has_fixed_privacy_safe_output_and_no_effects_on_rejection(capsys):
    fs = MemoryFS()
    assert gate.main([], fs=fs.os(), pins=PINS) == 0
    output = capsys.readouterr()
    assert output.out == "SOURCE_PROVENANCE_GATE: PASS (20 declared critical paths; gate only)\n"
    assert output.err == ""
    _assert_all_fds_closed(fs)

    fs = MemoryFS()
    fs.entries[next(iter(PINS))].data = b"private payload drift"
    before = {path: entry.data for path, entry in fs.entries.items()}
    assert gate.main([], fs=fs.os(), pins=PINS) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "SOURCE_PROVENANCE_GATE: FAIL (source_hash_mismatch)\n"
    assert "private" not in output.err
    assert before == {path: entry.data for path, entry in fs.entries.items()}
    _assert_all_fds_closed(fs)


def test_unrecognized_cli_arguments_fail_with_fixed_output_before_reads(capsys):
    fs = MemoryFS()
    assert gate.main(["--unexpected-private-value"], fs=fs.os(), pins=PINS) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "SOURCE_PROVENANCE_GATE: FAIL (source_arguments_invalid)\n"
    assert fs.opened == []
    assert fs.reads == []


class OwnerBoundaryOS:
    """Real descriptors beneath pytest scratch, with only leaf owner faked."""

    def __init__(self, tamper_path=None):
        self.directory_paths = {}
        self.opened = []
        self.closed = []
        self.first_leaf = None
        self.tamper_path = tamper_path
        self.tampered = False

    @staticmethod
    def _stat(st):
        return SimpleNamespace(st_dev=st.st_dev, st_ino=st.st_ino, st_uid=0,
                               st_gid=0, st_mode=st.st_mode, st_nlink=st.st_nlink,
                               st_size=st.st_size, st_mtime_ns=st.st_mtime_ns,
                               st_ctime_ns=st.st_ctime_ns)

    def open(self, name, flags, dir_fd=None):
        fd = os.open(name, flags, dir_fd=dir_fd)
        self.opened.append(fd)
        if flags & os.O_DIRECTORY:
            parent = self.directory_paths.get(dir_fd, "") if dir_fd is not None else ""
            self.directory_paths[fd] = os.path.join(parent, name.lstrip("/")) or "/"
        elif self.first_leaf is None:
            self.first_leaf = fd
        return fd

    def fstat(self, fd):
        return self._stat(os.fstat(fd))

    def stat(self, name, dir_fd=None, follow_symlinks=True):
        return self._stat(os.stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks))

    def read(self, fd, size):
        chunk = os.read(fd, size)
        if fd == self.first_leaf and not chunk and self.tamper_path and not self.tampered:
            before = os.stat(self.tamper_path)
            replacement = b"Z" * before.st_size
            write_fd = os.open(self.tamper_path, os.O_WRONLY | os.O_NOFOLLOW)
            try:
                assert os.pwrite(write_fd, replacement, 0) == before.st_size
            finally:
                os.close(write_fd)
            os.utime(self.tamper_path, ns=(before.st_atime_ns, before.st_mtime_ns + 5_000_000_000))
            self.tampered = True
        return chunk

    def close(self, fd):
        self.closed.append(fd)
        os.close(fd)

    def assert_all_closed(self):
        assert set(self.opened) == set(self.closed)
        assert len(self.opened) == len(self.closed)


def _real_fd_fixture(root, monkeypatch, tamper=False):
    root.mkdir()
    pins = {}
    for path in gate.SOURCE_PATHS:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        data = ("synthetic source: " + path).encode()
        target.write_bytes(data)
        target.chmod(0o664 if path == "src/role_radar/discovery/contracts.py" else 0o644)
        pins[path] = hashlib.sha256(data).hexdigest()
    first = root / gate.SOURCE_PATHS[0]
    boundary = OwnerBoundaryOS(first if tamper else None)
    monkeypatch.setattr(gate, "ROOT", str(root))
    return pins, boundary, first


def test_real_fd_stable_sources_pass_through_public_main(tmp_path, monkeypatch, capsys):
    pins, boundary, _ = _real_fd_fixture(tmp_path / "stable", monkeypatch)
    assert gate.main([], fs=boundary, pins=pins) == 0
    output = capsys.readouterr()
    assert output.out == "SOURCE_PROVENANCE_GATE: PASS (20 declared critical paths; gate only)\n"
    assert output.err == ""
    boundary.assert_all_closed()


def test_public_main_rejects_same_size_write_between_hash_and_final_fstat(
    tmp_path, monkeypatch, capsys
):
    pins, boundary, target = _real_fd_fixture(tmp_path / "mutating", monkeypatch, tamper=True)
    original_size = target.stat().st_size
    assert gate.main([], fs=boundary, pins=pins) == 1
    output = capsys.readouterr()
    assert boundary.tampered
    assert target.stat().st_size == original_size
    assert output.out == ""
    assert output.err == "SOURCE_PROVENANCE_GATE: FAIL (source_identity_changed)\n"
    assert "synthetic source" not in output.err
    boundary.assert_all_closed()


def test_public_help_is_gate_only_and_never_reads_sources(capsys):
    with pytest.raises(SystemExit) as result:
        gate.main(["--help"])
    assert result.value.code == 0
    output = capsys.readouterr()
    assert "20 declared critical paths" in output.out
    assert "not overall readiness" in output.out
