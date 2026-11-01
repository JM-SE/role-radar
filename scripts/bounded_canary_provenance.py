#!/usr/bin/env python3
"""Read-only provenance gate for a declared critical-source inventory."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys

ROOT = "/opt/role-radar"
MAX_SOURCE_BYTES = 2_000_000
SOURCE_PATHS = (
    "src/role_radar/cli/main.py",
    "src/role_radar/worker/main.py",
    "src/role_radar/worker/runner.py",
    "src/role_radar/worker/pipeline.py",
    "src/role_radar/worker/checkpoints.py",
    "src/role_radar/execution_budget.py",
    "src/role_radar/repositories/runs.py",
    "src/role_radar/services/eligibility_reprocessing.py",
    "src/role_radar/acquisition/discovery_policy.py",
    "src/role_radar/discovery/policy.py",
    "src/role_radar/domain/profile.py",
    "src/role_radar/matching/profile_intake.py",
    "src/role_radar/services/acquired_job_writer.py",
    "src/role_radar/services/pipeline_discovery.py",
    "src/role_radar/discovery/contracts.py",
    "src/role_radar/broker/client.py",
    "src/role_radar/broker/compat_check.py",
    "src/role_radar/broker/consumer-compat/v1/structured-extraction.json",
    "scripts/canary_supervisor.py",
    "src/role_radar/config.py",
)
EXPECTED_HASHES = dict((
    ("src/role_radar/cli/main.py", "9899763647e64e0a0b62e48f87d20c4b"
     "ce19716d565bc04e469464d47166a3d9"),
    ("src/role_radar/worker/main.py", "8d4a9d5f542468c2057d27242209c4b9"
     "6aec9dba92b4d82d6e6de11a95ef66b9"),
    ("src/role_radar/worker/runner.py", "44bcd7d59a25ddb6d737dc3e368fc0ff"
     "5ca8179f9aed80acbf9cf78769846af5"),
    ("src/role_radar/worker/pipeline.py", "c06a72a923095a703868e222741c7142"
     "c61a0dbbf57a4e61b3e1da648a5ea3a9"),
    ("src/role_radar/worker/checkpoints.py", "49cfbc9b56745287b9f58b860e00775a"
     "68794d3b4831bc26a208b06a1cc4c9da"),
    ("src/role_radar/execution_budget.py", "6ee12af78b8313f2640ff4ec98e8d4fd"
     "9274813a88319ed27ff0f1da434bdc4f"),
    ("src/role_radar/repositories/runs.py", "627ef6a1163ddf465f3ac719ddad0982"
     "10b0d41a6a24fea21864017b643cf1bb"),
    ("src/role_radar/services/eligibility_reprocessing.py", "0b0bdf1b0f3700082da24d5e30d85874"
     "3cabbfdb4dd139d1a7bae493a0076d7b"),
    ("src/role_radar/acquisition/discovery_policy.py", "e7bd9c2072e9d9c7ca4f26db51538382"
     "a52d315aec176f3f84f7c9b7842d6675"),
    ("src/role_radar/discovery/policy.py", "45a8b6d767580c49714f764a1562477d"
     "36546f43fb65914aeabca2c3de5cacd8"),
    ("src/role_radar/domain/profile.py", "090b1c45c4a2662b561347da215771a3"
     "03e07df3c91cc077a53045e8dc990e1f"),
    ("src/role_radar/matching/profile_intake.py", "3cf1704d23993c0fb280430977c59c3"
     "098b7f5d19fd2d991693d7b593f191d59"),
    ("src/role_radar/services/acquired_job_writer.py", "db98adc5b6f3a49966f44b23f96e1de2"
     "615d1ee8b867fccafa91ebbd15c7cac0"),
    ("src/role_radar/services/pipeline_discovery.py", "6bedf540c02f187d94a9b1777897cdb1"
     "da4c561d42a803d8d16d7e6e26dfba90"),
    ("src/role_radar/discovery/contracts.py", "6b354b9e87cc65ddd7d62ef13422aa6b"
     "8cfe43f9cb5aef9add2d60c2c522807c"),
    ("src/role_radar/broker/client.py", "0b2f0b4b442ff1a58520b165e6ad1cb9"
     "e76c972ad936ad5dfd3bf3cfa71689da"),
    ("src/role_radar/broker/compat_check.py", "8bdfbb7e61faba31055efed946891e40"
     "db4bbb063f218431e8cd05998ac3c673"),
    ("src/role_radar/broker/consumer-compat/v1/structured-extraction.json",
     "c4ab5ce5e98e3cb9804e7cbb6b685d69c1ced2caa4450240a4e2b7baf8b0b34a"),
    ("scripts/canary_supervisor.py", "9730d43e4edbaa6ff587a93c904c8031"
     "214e9925b241f059c85b1f0d205e89de"),
    ("src/role_radar/config.py", "b500b7f624fb5915d6d90139c3b3d69f"
     "f3fa3ec08b2450bfbefda914022c4bf2"),
))
EXACT_MODES = {
    "src/role_radar/discovery/contracts.py": 0o664,
    "src/role_radar/services/pipeline_discovery.py": 0o644,
}
ALLOWED_MODES = {0o644, 0o664}


class GateError(Exception):
    """A fixed public provenance failure code."""


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode),
            st.st_nlink, st.st_size, stat.S_IFMT(st.st_mode), st.st_mtime_ns,
            st.st_ctime_ns)


def _open_chain(fs, absolute):
    parts = absolute.strip("/").split("/")
    fds = []
    identities = []
    try:
        fd = fs.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(fd)
        root_stat = fs.fstat(fd)
        identities.append((root_stat.st_dev, root_stat.st_ino))
        for part in parts:
            fd = fs.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=fds[-1])
            fds.append(fd)
            st = fs.fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                raise GateError("source_path_invalid")
            identities.append((st.st_dev, st.st_ino))
        return fds, tuple(identities)
    except GateError:
        for fd in reversed(fds):
            fs.close(fd)
        raise
    except Exception:
        for fd in reversed(fds):
            fs.close(fd)
        raise GateError("source_proof_unavailable") from None


def _read_source(fs, relative, expected):
    parts = relative.split("/")
    parent = ROOT + "/" + "/".join(parts[:-1])
    leaf = parts[-1]
    dirs, chain = _open_chain(fs, parent)
    fd = None
    try:
        before = fs.stat(leaf, dir_fd=dirs[-1], follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1:
            raise GateError("source_metadata_invalid")
        mode = stat.S_IMODE(before.st_mode)
        if mode not in ALLOWED_MODES or mode != EXACT_MODES.get(relative, mode):
            raise GateError("source_metadata_invalid")
        if before.st_size < 0 or before.st_size > MAX_SOURCE_BYTES:
            raise GateError("source_size_invalid")
        fd = fs.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dirs[-1])
        opened = fs.fstat(fd)
        if _identity(before) != _identity(opened):
            raise GateError("source_identity_changed")
        current_dirs, current_chain = _open_chain(fs, parent)
        for current_fd in reversed(current_dirs):
            fs.close(current_fd)
        if current_chain != chain:
            raise GateError("source_parent_changed")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = fs.read(fd, min(65536, MAX_SOURCE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
                raise GateError("source_size_invalid")
            digest.update(chunk)
        after = fs.fstat(fd)
        path_after = fs.stat(leaf, dir_fd=dirs[-1], follow_symlinks=False)
        current_dirs, current_chain = _open_chain(fs, parent)
        for current_fd in reversed(current_dirs):
            fs.close(current_fd)
        if current_chain != chain:
            raise GateError("source_parent_changed")
        if _identity(opened) != _identity(after) or _identity(after) != _identity(path_after):
            raise GateError("source_identity_changed")
        if digest.hexdigest() != expected:
            raise GateError("source_hash_mismatch")
    except GateError:
        raise
    except Exception:
        raise GateError("source_proof_unavailable") from None
    finally:
        if fd is not None:
            fs.close(fd)
        for directory_fd in reversed(dirs):
            fs.close(directory_fd)


def _filesystem():
    return os


def verify_sources(fs=None, pins=None):
    fs = fs if fs is not None else _filesystem()
    pins = EXPECTED_HASHES if pins is None else pins
    if set(pins) != set(SOURCE_PATHS):
        raise GateError("source_inventory_invalid")
    for path in SOURCE_PATHS:
        _read_source(fs, path, pins[path])
    return len(SOURCE_PATHS)


def main(argv=None, *, fs=None, pins=None):
    parser = argparse.ArgumentParser(
        description="Read-only gate for 20 declared critical paths; not overall readiness."
    )
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv not in (["--help"], ["-h"]):
        print("SOURCE_PROVENANCE_GATE: FAIL (source_arguments_invalid)", file=sys.stderr)
        return 1
    if argv:
        parser.parse_args(argv)
    try:
        count = verify_sources(fs=fs, pins=pins)
    except GateError as exc:
        print(f"SOURCE_PROVENANCE_GATE: FAIL ({exc})", file=sys.stderr)
        return 1
    print(f"SOURCE_PROVENANCE_GATE: PASS ({count} declared critical paths; gate only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
