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
    "src/role_radar/main.py",
    "src/role_radar/execution_fence.py",
    "src/role_radar/fence_runtime.py",
    "src/role_radar/fence_release.py",
    "src/role_radar/api/fence_attestation.py",
    "scripts/bounded_canary_supervision.py",
    "scripts/bounded_canary_bounded_io.py",
    "scripts/bounded_canary_api_attestation.py",
)
EXPECTED_HASHES = dict((
    ("src/role_radar/cli/main.py", "3ee61f8455936b38aef14d3fa0dbdff2"
     "640aedb96c2edae3b17bf799491b205e"),
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
    ("src/role_radar/repositories/runs.py", "aeea186c52d0408d83d6e11d89997143"
     "9276b6ce6b7d569403dce73d2609ec63"),
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
    ("src/role_radar/services/acquired_job_writer.py", "dd351d737b921b8e0fd6b7d228e53626"
     "fa04dc590bd8d91b9c2a3fa6178ef958"),
    ("src/role_radar/services/pipeline_discovery.py", "dd05f31105f935989357640565deb867"
     "a63cc950773e346b39c67313e144bd14"),
    ("src/role_radar/discovery/contracts.py", "b051435802d3ef191ed738bf7b0977bc"
     "7f926e102dfb994108fd9d13e70af5a4"),
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
    ("src/role_radar/main.py", "05f771121a9290ed26c8f5eb3a1f2ee4ef44df1772a4d58259dcec69434c858a"),
    ("src/role_radar/execution_fence.py", "ad49bf1b9c105f617637c32fdc250967b7d0e089bbe84f805610da6edfbe139d"),
    ("src/role_radar/fence_runtime.py", "0a40d092b181f58916b7ef64cf7b73d29d8ee8ebd1c3b7ffce35277d61c07a02"),
    ("src/role_radar/fence_release.py", "5498bebc52d1549326abccf6ba385539f6c16c524b3f2fa0c5def5e9184c68a7"),
    ("src/role_radar/api/fence_attestation.py", "cceb4bf02776792067ceccc4ad0ccf0efaaac3fc5d6e21278feeac03923a53fa"),
    ("scripts/bounded_canary_supervision.py", "f3e7cbb828a41f268489fb372a643f1dfccd8a9490ebb54b6366513b7792d423"),
    ("scripts/bounded_canary_bounded_io.py", "92f7cc54936f2d40481d4bbd69473dea5b9316e13dd92ef5a2515dbf06f02c40"),
    ("scripts/bounded_canary_api_attestation.py", "7d712746b0a6711b7b4e3f34eedfbdb9e1729c18ab58b9f2d04f6ca70149ff9a"),
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
        description="Read-only gate for declared critical paths; not overall readiness."
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
