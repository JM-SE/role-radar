#!/usr/bin/env python3
"""Emit a public, self-contained root promotion program; never execute it here."""
import argparse
import ast
import hashlib
import json
import os
import subprocess
import sys
from types import SimpleNamespace

TRANSPORT = "odd/operations/discovery-verification-diagnostics-install.py"
TRANSPORT_COMMIT = "69303add33e054b022037f994f1842803b31e949"
TRANSPORT_SHA256 = "3fb6c892614482d54535ea6d9dc7ee8fac3696da1de88e5c9dd8f9ff169ca69c"
SOURCE_COMMIT = "ec2fdac275d2a11799871cae65831c29b93a9866"
BASELINE_COMMIT = "9f29f7c4c9b37f3058d57b9b69da066a159fa6f0"
SOURCE_HASHES = {
    "src/role_radar/discovery/contracts.py": (
        "6b354b9e87cc65ddd7d62ef13422aa6b8cfe43f9cb5aef9add2d60c2c522807c"
    ),
    "src/role_radar/services/pipeline_discovery.py": (
        "6bedf540c02f187d94a9b1777897cdb1da4c561d42a803d8d16d7e6e26dfba90"
    ),
}
OLD_HASHES = {
    "src/role_radar/discovery/contracts.py": (
        "e83a8308503160ce970a8caaf72cd38dd7e3de58d01b2e45e7d55f1929f120c8"
    ),
    "src/role_radar/services/pipeline_discovery.py": (
        "ee654bd5e3766b554ccf9a16b2576df1f0920a6846d4c6bc6cde97cd036a612e"
    ),
}
TARGETS = {
    "/opt/role-radar/src/role_radar/discovery/contracts.py": (
        "src/role_radar/discovery/contracts.py",
        0o664,
    ),
    "/opt/role-radar/src/role_radar/services/pipeline_discovery.py": (
        "src/role_radar/services/pipeline_discovery.py",
        0o644,
    ),
}

ROOT = r'''#!/usr/bin/python3
import hashlib
import json
import os
import stat
import subprocess
import sys
import time

SOURCES = SOURCES_LITERAL
SOURCE_HASHES = HASHES_LITERAL
OLD_HASHES = OLD_HASHES_LITERAL
NORMAL_ROLE = NORMAL_ROLE_LITERAL
CANDIDATE_ROLE = CANDIDATE_ROLE_LITERAL
TARGETS = {
    "/opt/role-radar/src/role_radar/discovery/contracts.py": (
        "src/role_radar/discovery/contracts.py", 0o664
    ),
    "/opt/role-radar/src/role_radar/services/pipeline_discovery.py": (
        "src/role_radar/services/pipeline_discovery.py", 0o644
    ),
}
BACKUPS = "/opt/role-radar/data/backups"
ENV = "/etc/role-radar/role-radar.env"
POLICY = "/etc/role-radar/discovery-policy.toml"
UNITS = (
    "role-radar-api.service",
    "role-radar-worker.service",
    "role-radar-continuous-acquisition.service",
    "role-radar-continuous-acquisition.timer",
    "role-radar-continuous-discovery.service",
    "role-radar-continuous-discovery.timer",
    "role-radar-scheduler.service",
    "role-radar-scheduler.timer",
    "llm-broker-api.service",
    "llm-broker-worker.service",
    "llama-server.service",
    "llama-swap.service",
)
SERVICE_PROPS = (
    "Id", "LoadState", "ActiveState", "SubState", "UnitFileState",
    "MainPID", "ExecMainStartTimestampMonotonic",
)
TIMER_PROPS = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState")
TIMERS = {
    "role-radar-continuous-acquisition.timer",
    "role-radar-continuous-discovery.timer",
    "role-radar-scheduler.timer",
}
API = {
    "role-radar-api.service", "llm-broker-api.service", "llama-server.service",
    "llama-swap.service", "llm-broker-worker.service",
}
QUIESCENT_WORKERS = {"role-radar-worker.service"}
PRODUCERS = {
    "role-radar-continuous-acquisition.service",
    "role-radar-continuous-discovery.service",
    "role-radar-scheduler.service",
}
STATE = {}
DEADLINE = None
PARENTS = {}

class Stop(Exception):
    def __init__(self, code):
        self.code = code

def digest(data):
    return hashlib.sha256(data).hexdigest()

def remaining():
    if DEADLINE is None:
        return 170.0
    seconds = DEADLINE - time.monotonic()
    if seconds <= 0:
        raise Stop("operation_deadline_exceeded")
    return seconds

def command(argv, timeout, timeout_result=False, **kwargs):
    seconds = remaining()
    effective = min(seconds, timeout)
    try:
        return subprocess.run(argv, timeout=effective, check=False, **kwargs)
    except subprocess.TimeoutExpired:
        if seconds <= timeout or remaining() <= 0:
            raise Stop("operation_deadline_exceeded")
        if timeout_result:
            return None
        raise Stop("subprocess_timeout")

def metadata(path, uid, gid, mode, kind="file"):
    parts = path.strip("/").split("/")
    current = "/"
    for part in parts[:-1]:
        current = os.path.join(current, part)
        parent = os.lstat(current)
        if not stat.S_ISDIR(parent.st_mode):
            raise Stop("parent_not_directory")
    st = os.lstat(path)
    correct_type = stat.S_ISREG(st.st_mode) if kind == "file" else stat.S_ISDIR(st.st_mode)
    if (not correct_type or stat.S_ISLNK(st.st_mode)
            or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, mode)
            or (kind == "file" and st.st_nlink != 1)):
        raise Stop("metadata_mismatch")
    return st

def directory(path, uid, gid, mode):
    return metadata(path, uid, gid, mode, "directory")

def open_parent_chain(path):
    parts = path.strip("/").split("/")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    chain = []
    try:
        chain.append((os.fstat(fd).st_dev, os.fstat(fd).st_ino))
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            opened = os.fstat(fd)
            chain.append((opened.st_dev, opened.st_ino))
        return fd, parts[-1], tuple(chain)
    except BaseException:
        os.close(fd)
        raise

def same_parent_chain(path):
    fd, _name, chain = open_parent_chain(path)
    try:
        original = PARENTS[path][2]
        if chain != original:
            raise Stop("target_parent_changed")
    finally:
        os.close(fd)

def target_parent(path):
    same_parent_chain(path)
    return PARENTS[path]

def read_target(path, spec):
    dfd, name, _chain = target_parent(path)
    before = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode),
                before.st_nlink) != (0, 0, spec[1], 1)):
        raise Stop("metadata_mismatch")
    if before.st_size > 2_000_000:
        raise Stop("target_size")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
    try:
        opened = os.fstat(fd)
        identity = (before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                    stat.S_IMODE(before.st_mode), before.st_nlink)
        opened_identity = (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid,
                           stat.S_IMODE(opened.st_mode), opened.st_nlink)
        if identity != opened_identity:
            raise Stop("target_changed_during_open")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > 2_000_000:
                raise Stop("target_size")
            chunks.append(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    final = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    same_parent_chain(path)
    final_identity = (final.st_dev, final.st_ino, final.st_size, final.st_uid,
                      final.st_gid, stat.S_IMODE(final.st_mode), final.st_nlink)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_uid,
                      after.st_gid, stat.S_IMODE(after.st_mode), after.st_nlink)
    if after_identity != final_identity:
        raise Stop("target_changed_during_read")
    return final, b"".join(chunks)

def classify(observed):
    states = []
    for path, (key, _mode) in TARGETS.items():
        value = digest(observed[path][1])
        if value == OLD_HASHES[key]:
            states.append("old")
        elif value == SOURCE_HASHES[key]:
            states.append("candidate")
        else:
            states.append("other")
    if states == ["old", "old"]:
        return "old"
    if states == ["candidate", "candidate"]:
        return "candidate"
    raise Stop("mixed_or_unrecognized_sources")

def parse_blocks(text, allowed, required, optional=()):
    blocks = {}
    row = {}
    rows = []
    for line in text.splitlines() + [""]:
        if not line:
            if row:
                rows.append(row)
                row = {}
            continue
        if "=" not in line:
            raise Stop("unit_output_invalid")
        key, value = line.split("=", 1)
        if key in row:
            raise Stop("unit_property_duplicate")
        row[key] = value
    for values in rows:
        name = values.get("Id")
        if name not in allowed or name in blocks:
            raise Stop("unit_duplicate_or_unknown")
        if set(values) - set(required) - set(optional):
            raise Stop("unit_property_unexpected")
        if not set(required) <= set(values):
            raise Stop("unit_properties_incomplete")
        blocks[name] = values
    if set(blocks) != set(allowed):
        raise Stop("unit_set_incomplete")
    return blocks

def parse_units(text):
    blocks = parse_blocks(text, set(UNITS), SERVICE_PROPS[:5], SERVICE_PROPS[5:])
    for name, values in blocks.items():
        if name not in TIMERS and not set(SERVICE_PROPS[5:]) <= set(values):
            raise Stop("unit_properties_incomplete")
        if values["Id"] != name or values["LoadState"] != "loaded":
            raise Stop("unit_identity_or_load")
        if name in API:
            if not (values["ActiveState"] == "active"
                    and values["SubState"] == "running"
                    and values["UnitFileState"] == "enabled"
                    and int(values.get("MainPID", "0")) > 0):
                raise Stop("api_not_active")
        elif name in QUIESCENT_WORKERS:
            if not (values["ActiveState"] == "inactive"
                    and values["SubState"] == "dead"
                    and values["UnitFileState"] == "disabled"
                    and values.get("MainPID") == "0"):
                raise Stop("worker_not_quiescent")
        elif name in PRODUCERS:
            if not (values["ActiveState"] in ("failed", "inactive")
                    and values["UnitFileState"] == "static"
                    and values.get("MainPID") == "0"):
                raise Stop("producer_not_quiescent")
        elif name in TIMERS:
            if not (values["ActiveState"] == "inactive"
                    and values["UnitFileState"] == "disabled"
                    and values.get("MainPID", "0") in ("", "0", "n/a")):
                raise Stop("timer_not_quiescent")
    return blocks

def parse_canaries(text, names):
    required = ("Id", "ActiveState", "SubState", "MainPID")
    blocks = parse_blocks(text, set(names), required)
    for name, values in blocks.items():
        if values["Id"] != name or values["MainPID"] != "0":
            raise Stop("canary_not_quiescent")
        state = (values["ActiveState"], values["SubState"])
        if state not in (("inactive", "dead"), ("failed", "failed")):
            raise Stop("canary_not_quiescent")
    return len(blocks)

def unit_snapshot():
    p = command(
        ["/usr/bin/systemctl", "show", "--no-pager",
         "--property=" + ",".join(SERVICE_PROPS), *UNITS],
        15, stdin=subprocess.DEVNULL, text=True, capture_output=True,
    )
    if p.returncode:
        raise Stop("unit_query_failed")
    units = parse_units(p.stdout)
    listed = command(
        ["/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend",
         "role-radar-canary-worker@*.service"],
        10, stdin=subprocess.DEVNULL, text=True, capture_output=True,
    )
    if listed.returncode:
        raise Stop("canary_query_failed")
    names = []
    for line in listed.stdout.splitlines():
        fields = line.split()
        if fields and fields[0].startswith("role-radar-canary-worker@"):
            name = fields[0]
            if not name.endswith(".service") or name in names:
                raise Stop("canary_name_invalid")
            names.append(name)
    if names:
        p = command(
            ["/usr/bin/systemctl", "show", "--no-pager",
             "--property=Id,ActiveState,SubState,MainPID", *names],
            10, stdin=subprocess.DEVNULL, text=True, capture_output=True,
        )
        if p.returncode:
            raise Stop("canary_state_query_failed")
        parse_canaries(p.stdout, names)
    return units

def metadata_snapshot():
    result = {}
    for path, uid, gid, mode in (
        ("/etc/role-radar/role-radar.env", 0, 0, 0o600),
        ("/etc/role-radar/discovery-policy.toml", 0, 988, 0o640),
    ):
        st = metadata(path, uid, gid, mode)
        result[path] = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                        st.st_ctime_ns, st.st_nlink, st.st_uid, st.st_gid,
                        stat.S_IMODE(st.st_mode))
    return result

def role(role_text):
    env = ["PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=/nonexistent",
           "PYTHONDONTWRITEBYTECODE=1", "UV_OFFLINE=1",
           "ROLE_RADAR_TEST_NETWORK_DENY=1"]
    return command(
        ["/usr/sbin/runuser", "-u", "role-radar", "--", "/usr/bin/env", "-i",
         *env, "/opt/role-radar/.venv/bin/python", "-I", "-B", "-"],
        40, timeout_result=True, input=role_text, cwd="/opt/role-radar", text=True,
        capture_output=True,
    )

def validate_role_output(stdout, returncode, candidate=False):
    if returncode != 0 or not isinstance(stdout, str):
        raise Stop("role_verification_failed")
    lines = stdout.splitlines()
    if len(lines) != (1 if candidate else 2):
        raise Stop("role_output_shape")
    try:
        records = [json.loads(line) for line in lines]
    except (ValueError, TypeError):
        raise Stop("role_output_invalid")
    result = records[0]
    cases = {
        "test_canary_discovery_searches_once_and_verifies_only_one_greenhouse",
        "test_board_verification_diagnostics_are_local_and_preserve_accepted_jobs",
        "test_reused_cycle_preserves_historical_stats_without_verification",
        "test_finalize_persists_bounded_writer_diagnostics_across_zero_accept_writes",
        "test_finalize_sanitizes_board_verification_counts",
        "test_writer_adds_missing_application_url_reason_once",
    }
    guards = {
        "sqlite_alias", "sqlite_reject_before_native", "sqlite_memory_delegates",
        "socket_class", "socket_reject_before_native", "ssl_cached_constructor",
        "ssl_methods_reject", "fake_fd_wrap", "connect_reject", "dns_reject", "assertions",
    }
    if candidate:
        guards.add("real_packages")
    if not isinstance(result, dict) or set(result) != {"stage", "results", "assertions", "guards"}:
        raise Stop("role_result_invalid")
    if (result["stage"] != "complete" or type(result["assertions"]) is not int
            or result["assertions"] != 21):
        raise Stop("role_result_incomplete")
    if not isinstance(result["results"], dict) or set(result["results"]) != cases:
        raise Stop("role_cases_invalid")
    if any(value is not True for value in result["results"].values()):
        raise Stop("role_case_failed")
    if not isinstance(result["guards"], dict) or set(result["guards"]) != guards:
        raise Stop("role_guards_invalid")
    if any(value is not True for value in result["guards"].values()):
        raise Stop("role_guard_failed")
    if not candidate:
        expected_sources = (
            ("role_radar.discovery.contracts",
             "/opt/role-radar/src/role_radar/discovery/contracts.py",
             SOURCE_HASHES["src/role_radar/discovery/contracts.py"], 436),
            ("role_radar.services.pipeline_discovery",
             "/opt/role-radar/src/role_radar/services/pipeline_discovery.py",
             SOURCE_HASHES["src/role_radar/services/pipeline_discovery.py"], 420),
        )
        proof = records[1]
        if not isinstance(proof, dict) or set(proof) != {"public_sources"}:
            raise Stop("role_provenance_failed")
        sources = proof["public_sources"]
        keys = {"module", "path", "sha256", "uid", "gid", "mode", "nlink",
                "device", "inode"}
        if not isinstance(sources, list) or len(sources) != len(expected_sources):
            raise Stop("role_provenance_failed")
        for source, expected in zip(sources, expected_sources):
            if not isinstance(source, dict) or set(source) != keys:
                raise Stop("role_provenance_failed")
            module, path, digest, mode = expected
            if (source["module"] != module or source["path"] != path
                    or source["sha256"] != digest or type(source["uid"]) is not int
                    or source["uid"] != 0 or type(source["gid"]) is not int
                    or source["gid"] != 0 or type(source["mode"]) is not int
                    or source["mode"] != mode or type(source["nlink"]) is not int
                    or source["nlink"] != 1 or type(source["device"]) is not int
                    or source["device"] < 0 or type(source["inode"]) is not int
                    or source["inode"] <= 0):
                raise Stop("role_provenance_failed")
    return True

def role_check(code, candidate=False, stage="role_verification"):
    STATE["stage"] = stage
    proc = role(code)
    if proc is None:
        STATE["role_rc"] = None
        raise Stop("role_timeout")
    STATE["role_rc"] = proc.returncode if type(proc.returncode) is int else None
    if type(proc.returncode) is not int:
        raise Stop("role_rc_unavailable")
    return validate_role_output(proc.stdout, proc.returncode, candidate)

def fresh_guard(previous_units, previous_meta):
    if unit_snapshot() != previous_units:
        raise Stop("unit_state_drift")
    if metadata_snapshot() != previous_meta:
        raise Stop("configuration_metadata_drift")

def root_only():
    if os.geteuid() != 0:
        raise Stop("not_root")
    os.environ.clear()
    os.environ.update({"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                       "LANG": "C.UTF-8", "HOME": "/root"})
    if os.environ != {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                      "LANG": "C.UTF-8", "HOME": "/root"}:
        raise Stop("unclean_environment")
    os.umask(0o077)
    os.chdir("/")

def write_manifest(backup, name, data, exclusive=False):
    path = os.path.join(backup, name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    if exclusive:
        flags |= os.O_EXCL
    else:
        st = os.lstat(path)
        if (not stat.S_ISREG(st.st_mode)
                or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink)
                != (0, 0, 0o600, 1)):
            raise Stop("manifest_metadata")
        flags |= os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(json.dumps(data, sort_keys=True).encode() + b"\n")
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(backup, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)

def open_backup(observed):
    backup = os.path.join(
        BACKUPS, "role-radar-board-verification-diagnostics-" + str(time.time_ns())
    )
    before = {"state": "backup_complete", "writes": 0, "targets": {}}
    result = {"state": "staging", "writes": 0, "intent": None, "stages": {}}
    STATE.update({"backup": backup, "writes": 0, "write_intent": None,
                  "target_writes": 0, "backup_created": False,
                  "backup_mutations": 0, "stage_mutations": 0})
    try:
        try:
            os.mkdir(backup, 0o700)
        except FileExistsError:
            raise Stop("backup_path_collision")
        except BaseException:
            STATE["backup_created"] = None
            STATE["backup_mutations"] = None
            raise
        STATE["backup_created"] = True
        STATE["backup_mutations"] = 1
        os.chown(backup, 0, 0)
        STATE["backup_mutations"] += 1
        os.chmod(backup, 0o700)
        STATE["backup_mutations"] += 1
        directory(backup, 0, 0, 0o700)
        parent_fd = os.open(BACKUPS, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        for index, (path, (key, mode)) in enumerate(TARGETS.items()):
            st, data = observed[path]
            before["targets"][path] = {
                "sha256": digest(data), "dev": st.st_dev, "ino": st.st_ino,
                "uid": st.st_uid, "gid": st.st_gid,
                "mode": stat.S_IMODE(st.st_mode),
            }
            fd = os.open(os.path.join(backup, "before-" + str(index)),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600)
            with os.fdopen(fd, "wb") as saved:
                saved.write(data)
                saved.flush()
                os.fsync(saved.fileno())
            STATE["backup_mutations"] += 1
        write_manifest(backup, "before.json", before, exclusive=True)
        STATE["backup_mutations"] += 1
        write_manifest(backup, "result.json", result, exclusive=True)
        STATE["backup_mutations"] += 1
    except BaseException as error:
        result["state"] = "partial_or_failed"
        result["error"] = error.code if isinstance(error, Stop) else "operation_exception"
        result["created"] = STATE["backup_created"]
        result["target_writes"] = STATE["writes"]
        result["backup_mutations"] = STATE["backup_mutations"]
        result["stage_mutations"] = STATE["stage_mutations"]
        STATE["failure"] = result["error"]
        if STATE["backup_created"]:
            for exclusive in (False, True):
                try:
                    write_manifest(backup, "result.json", result, exclusive=exclusive)
                    break
                except Exception:
                    continue
        raise
    return backup, before, result

def target_state(path, spec):
    st, data = read_target(path, spec)
    return {"dev": st.st_dev, "ino": st.st_ino, "sha256": digest(data),
            "uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode),
            "nlink": st.st_nlink}

def promote():
    global DEADLINE, PARENTS
    DEADLINE = time.monotonic() + 170
    STATE["stage"] = "root_entry"
    root_only()
    opened = {}
    try:
        for path in TARGETS:
            opened[path] = open_parent_chain(path)
        PARENTS = opened
        return _promote_body()
    finally:
        PARENTS = {}
        for dfd, _name, _chain in opened.values():
            os.close(dfd)

def _promote_body():
    STATE["stage"] = "root_entry"
    STATE["stage"] = "metadata_snapshot"
    config_before = metadata_snapshot()
    STATE["stage"] = "initial_unit_snapshot"
    units_before = unit_snapshot()
    STATE["stage"] = "source_disposition"
    observed = {path: read_target(path, spec) for path, spec in TARGETS.items()}
    disposition = classify(observed)
    if disposition == "candidate":
        initial = {
            path: {
                "dev": st.st_dev, "ino": st.st_ino, "sha256": digest(data),
                "uid": st.st_uid, "gid": st.st_gid,
                "mode": stat.S_IMODE(st.st_mode), "nlink": st.st_nlink,
            }
            for path, (st, data) in observed.items()
        }
        fresh_guard(units_before, config_before)
        role_check(NORMAL_ROLE, stage="already_candidate_role_verify")
        final = {path: target_state(path, spec) for path, spec in TARGETS.items()}
        if final != initial:
            raise Stop("installed_source_drift")
        if any(final[path]["sha256"] != SOURCE_HASHES[TARGETS[path][0]]
               for path in TARGETS):
            raise Stop("installed_source_drift")
        fresh_guard(units_before, config_before)
        return {"ok": True, "mode": "already_installed_verified", "writes": 0,
                "stage": STATE.get("stage"), "role_rc": STATE.get("role_rc"),
                "hashes": {path: value["sha256"] for path, value in final.items()}}
    fresh_guard(units_before, config_before)
    directory(BACKUPS, 0, 0, 0o755)
    required = 4 * sum(len(data) for _st, data in observed.values())
    space = os.statvfs(BACKUPS)
    if space.f_bavail * space.f_frsize < required:
        raise Stop("backup_space")
    backup, before, result = open_backup(observed)
    stages = {}
    try:
        for path, (key, _mode) in TARGETS.items():
            source = SOURCES[key].encode()
            if digest(source) != SOURCE_HASHES[key]:
                raise Stop("candidate_hash_mismatch")
            compile(source, path, "exec")
            dfd, _target_name, _chain = target_parent(path)
            same_parent_chain(path)
            stage_name = ".role-radar-stage-" + os.urandom(16).hex()
            fd = os.open(stage_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, 0o600, dir_fd=dfd)
            STATE["stage_mutations"] += 1
            with os.fdopen(fd, "wb") as staged:
                staged.write(source)
                staged.flush()
                os.fsync(staged.fileno())
            stage_st = os.stat(stage_name, dir_fd=dfd, follow_symlinks=False)
            stage = stage_name
            if (not stat.S_ISREG(stage_st.st_mode)
                    or (stage_st.st_uid, stage_st.st_gid,
                        stat.S_IMODE(stage_st.st_mode), stage_st.st_nlink)
                    != (0, 0, 0o600, 1)):
                raise Stop("stage_metadata")
            stages[path] = {"name": stage, "dev": stage_st.st_dev,
                            "ino": stage_st.st_ino, "sha256": digest(source)}
        result["stages"] = {path: dict(value) for path, value in stages.items()}
        result["state"] = "staged_precheck_pending"
        write_manifest(backup, "result.json", result)
        role_check(CANDIDATE_ROLE, candidate=True, stage="candidate_role_precheck")
        fresh_guard(units_before, config_before)
        promoted = {}
        for path, (key, mode) in TARGETS.items():
            fresh_guard(units_before, config_before)
            for check_path, spec in TARGETS.items():
                current = target_state(check_path, spec)
                if check_path in promoted:
                    if current != promoted[check_path]:
                        raise Stop("promoted_target_drift")
                else:
                    old_st = observed[check_path][0]
                    old_data = observed[check_path][1]
                    expected = {
                        "dev": old_st.st_dev, "ino": old_st.st_ino,
                        "sha256": digest(old_data), "uid": 0, "gid": 0,
                        "mode": spec[1], "nlink": 1,
                    }
                    if current != expected:
                        raise Stop("source_changed_before_replace")
            dfd, target_name, _chain = target_parent(path)
            stage = stages[path]
            stage_st = os.stat(stage["name"], dir_fd=dfd, follow_symlinks=False)
            if (stage_st.st_dev, stage_st.st_ino) != (stage["dev"], stage["ino"]):
                raise Stop("stage_identity_changed")
            fd = os.open(stage["name"], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
            with os.fdopen(fd, "rb") as staged:
                opened = os.fstat(staged.fileno())
                if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid,
                        stat.S_IMODE(opened.st_mode), opened.st_nlink) != (
                        stage["dev"], stage["ino"], 0, 0, 0o600, 1):
                    raise Stop("stage_identity_changed")
                if digest(staged.read()) != stage["sha256"]:
                    raise Stop("stage_hash_changed")
            original_st = observed[path][0]
            fd = os.open(stage["name"], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
            try:
                os.fchown(fd, original_st.st_uid, original_st.st_gid)
                os.fchmod(fd, mode)
                stage_st = os.fstat(fd)
            finally:
                os.close(fd)
            if ((stage_st.st_dev, stage_st.st_ino) != (stage["dev"], stage["ino"])
                    or (stage_st.st_uid, stage_st.st_gid, stat.S_IMODE(stage_st.st_mode),
                        stage_st.st_nlink) != (0, 0, mode, 1)):
                raise Stop("stage_metadata_changed")
            result["state"] = "write_intent"
            result["intent"] = path
            STATE["write_intent"] = path
            write_manifest(backup, "result.json", result)
            same_parent_chain(path)
            os.replace(stage["name"], target_name, src_dir_fd=dfd, dst_dir_fd=dfd)
            same_parent_chain(path)
            result["writes"] += 1
            STATE["writes"] = result["writes"]
            result["state"] = "promotion_partial"
            result["intent"] = None
            STATE["write_intent"] = None
            os.fsync(dfd)
            installed = target_state(path, (key, mode))
            if (installed["sha256"] != SOURCE_HASHES[key]
                    or installed["dev"] != stage["dev"]
                    or installed["ino"] != stage["ino"]):
                raise Stop("promoted_target_invalid")
            promoted[path] = installed
            write_manifest(backup, "result.json", result)
        role_check(NORMAL_ROLE, stage="installed_role_verify")
        fresh_guard(units_before, config_before)
        for path in TARGETS:
            same_parent_chain(path)
        final = {path: target_state(path, spec) for path, spec in TARGETS.items()}
        for path, (key, mode) in TARGETS.items():
            if (final[path]["sha256"] != SOURCE_HASHES[key]
                    or final[path]["mode"] != mode
                    or final[path]["uid"] != 0 or final[path]["gid"] != 0
                    or final[path]["nlink"] != 1):
                raise Stop("final_target_invalid")
        for index, (path, _spec) in enumerate(TARGETS.items()):
            saved = os.path.join(backup, "before-" + str(index))
            st = os.lstat(saved)
            if (not stat.S_ISREG(st.st_mode)
                    or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink)
                    != (0, 0, 0o600, 1)):
                raise Stop("backup_file_invalid")
            fd = os.open(saved, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as old:
                if digest(old.read()) != before["targets"][path]["sha256"]:
                    raise Stop("backup_hash_invalid")
        result["state"] = "verified_complete"
        write_manifest(backup, "result.json", result)
        return {"ok": True, "mode": "promoted_and_verified", "writes": 2,
                "stage": STATE.get("stage"), "role_rc": STATE.get("role_rc"),
                "hashes": {path: value["sha256"] for path, value in final.items()},
                "backup": backup}
    except BaseException as error:
        result["state"] = "partial_or_failed"
        result["error"] = error.code if isinstance(error, Stop) else "operation_exception"
        result["created"] = STATE["backup_created"]
        result["target_writes"] = STATE["writes"]
        result["backup_mutations"] = STATE["backup_mutations"]
        result["stage_mutations"] = STATE["stage_mutations"]
        STATE["failure"] = result["error"]
        try:
            write_manifest(backup, "result.json", result)
        except Exception:
            pass
        raise

def main():
    try:
        result = promote()
    except Stop as error:
        result = {"ok": False, "code": error.code, **STATE}
    except BaseException:
        result = {"ok": False, "code": "operation_exception", **STATE}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

if __name__ == "__main__":
    raise SystemExit(main())
'''


def owner_blob(commit, path, expected):
    blob = subprocess.check_output(["git", "show", f"{commit}:{path}"])
    if hashlib.sha256(blob).hexdigest() != expected:
        raise ValueError(f"pinned blob mismatch: {path}")
    return blob


def role_program(candidate):
    transport_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "operations", os.path.basename(TRANSPORT)
    )
    committed = owner_blob(TRANSPORT_COMMIT, TRANSPORT, TRANSPORT_SHA256)
    with open(transport_path, "rb") as current_file:
        if current_file.read() != committed:
            raise ValueError("accepted transport bytes changed")
    command = [sys.executable, "-B", transport_path, "--emit-role"]
    if candidate:
        command.append("--candidate")
    code = subprocess.check_output(command, text=True)
    if not candidate:
        proof = '''
import hashlib, importlib, json, os, stat
checks = (
    ("role_radar.discovery.contracts",
     "/opt/role-radar/src/role_radar/discovery/contracts.py",
     "CONTRACT_HASH", 0o664),
    ("role_radar.services.pipeline_discovery",
     "/opt/role-radar/src/role_radar/services/pipeline_discovery.py",
     "PIPELINE_HASH", 0o644),
)
def collect_public_sources(checks):
    records = []
    def metadata(st):
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink)
    for module_name, path, expected, mode in checks:
        module = importlib.import_module(module_name)
        if module.__file__ != path:
            raise RuntimeError("module path mismatch")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            path_before = os.lstat(path)
            if metadata(before) != metadata(path_before):
                raise RuntimeError("source identity changed")
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or before.st_gid != 0 or stat.S_IMODE(before.st_mode) != mode
                    or before.st_nlink != 1 or before.st_size >= 2 * 1024 * 1024):
                raise RuntimeError("source metadata rejected")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(fd, min(65536, 2 * 1024 * 1024 - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total >= 2 * 1024 * 1024:
                    raise RuntimeError("source too large")
                digest.update(chunk)
            after = os.fstat(fd)
            path_after = os.lstat(path)
            if (digest.hexdigest() != expected or metadata(before) != metadata(after)
                    or metadata(before) != metadata(path_after)):
                raise RuntimeError("source identity changed")
            records.append({"module": module_name, "path": path, "sha256": digest.hexdigest(),
                            "uid": before.st_uid, "gid": before.st_gid, "mode": mode,
                            "nlink": before.st_nlink, "device": before.st_dev,
                            "inode": before.st_ino})
        finally:
            os.close(fd)
    return records
print(json.dumps({"public_sources": collect_public_sources(checks)}, sort_keys=True))
'''.replace("CONTRACT_HASH", SOURCE_HASHES["src/role_radar/discovery/contracts.py"])
        proof = proof.replace(
            "PIPELINE_HASH", SOURCE_HASHES["src/role_radar/services/pipeline_discovery.py"]
        )
        code += proof
    return code


def emit_root():
    sources = {}
    for path, expected in SOURCE_HASHES.items():
        sources[path] = owner_blob(SOURCE_COMMIT, path, expected).decode()
    old_hashes = {}
    for path, expected in OLD_HASHES.items():
        blob = owner_blob(BASELINE_COMMIT, path, expected)
        old_hashes[path] = hashlib.sha256(blob).hexdigest()
    roles = (role_program(False), role_program(True))
    code = ROOT.replace("SOURCES_LITERAL", repr(sources))
    code = code.replace("OLD_HASHES_LITERAL", repr(old_hashes))
    code = code.replace("HASHES_LITERAL", repr(SOURCE_HASHES))
    code = code.replace("NORMAL_ROLE_LITERAL", repr(roles[0]))
    code = code.replace("CANDIDATE_ROLE_LITERAL", repr(roles[1]))
    compile(code, "<emitted-root-promotion>", "exec")
    return code


def self_test():
    code = emit_root()
    namespace = {"__name__": "root_emitter_self_test"}
    exec(compile(code, "<emitted-root-promotion>", "exec"), namespace)
    paths = list(namespace["TARGETS"])
    old_pair = {
        path: (None, owner_blob(BASELINE_COMMIT, namespace["TARGETS"][path][0],
                               OLD_HASHES[namespace["TARGETS"][path][0]]))
        for path in paths
    }
    candidate_pair = {
        path: (None, owner_blob(SOURCE_COMMIT, namespace["TARGETS"][path][0],
                               SOURCE_HASHES[namespace["TARGETS"][path][0]]))
        for path in paths
    }
    classify = namespace["classify"]
    assert classify(old_pair) == "old"
    assert classify(candidate_pair) == "candidate"
    mixed = dict(old_pair)
    mixed[paths[1]] = candidate_pair[paths[1]]
    try:
        classify(mixed)
    except namespace["Stop"]:
        pass
    else:
        raise AssertionError("mixed sources accepted")
    units = namespace["UNITS"]
    timers = namespace["TIMERS"]
    rows = []
    for name in units:
        timer = name in timers
        inactive = namespace["PRODUCERS"] | namespace["QUIESCENT_WORKERS"]
        fields = [
            ("Id", name),
            ("LoadState", "loaded"),
            ("ActiveState", "inactive" if timer or name in inactive else "active"),
            ("SubState", "dead" if timer or name in inactive else "running"),
            ("UnitFileState", "disabled" if timer or name in namespace["QUIESCENT_WORKERS"]
             else "static" if name in namespace["PRODUCERS"] else "enabled"),
        ]
        if not timer:
            pid = "0" if name in inactive else "123"
            fields.extend([
                ("MainPID", pid),
                ("ExecMainStartTimestampMonotonic", "n/a"),
            ])
        rows.extend(f"{key}={value}" for key, value in reversed(fields))
        rows.append("")
    # Broker worker is active like the API/service posture, including positive PID.
    unit_text = "\n".join(rows)
    parsed = namespace["parse_units"](unit_text)
    assert set(parsed) == set(units)
    unit_blocks = unit_text.strip().split("\n\n")
    for invalid_units in ("\n\n".join(unit_blocks[1:]),
                          unit_text + "\n" + unit_blocks[0]):
        try:
            namespace["parse_units"](invalid_units)
        except namespace["Stop"]:
            pass
        else:
            raise AssertionError("missing or duplicate unit block accepted")
    parse_canaries = namespace["parse_canaries"]
    canary = (
        "MainPID=0\nSubState=dead\nId=role-radar-canary-worker@synthetic.service\n"
        "ActiveState=inactive\n"
    )
    assert parse_canaries(canary, ["role-radar-canary-worker@synthetic.service"]) == 1
    for bad in (
        "MainPID=0\nSubState=dead\nId=role-radar-canary-worker@x.service\n"
        "ActiveState=active\n",
        "MainPID=0\nMainPID=0\nSubState=dead\n"
        "Id=role-radar-canary-worker@x.service\nActiveState=inactive\n",
    ):
        try:
            parse_canaries(bad, ["role-radar-canary-worker@x.service"])
        except namespace["Stop"]:
            pass
        else:
            raise AssertionError("invalid canary accepted")
    validator = namespace["validate_role_output"]
    valid = {
        "stage": "complete", "assertions": 21,
        "results": {name: True for name in (
            "test_canary_discovery_searches_once_and_verifies_only_one_greenhouse",
            "test_board_verification_diagnostics_are_local_and_preserve_accepted_jobs",
            "test_reused_cycle_preserves_historical_stats_without_verification",
            "test_finalize_persists_bounded_writer_diagnostics_across_zero_accept_writes",
            "test_finalize_sanitizes_board_verification_counts",
            "test_writer_adds_missing_application_url_reason_once",
        )},
        "guards": {name: True for name in (
            "sqlite_alias", "sqlite_reject_before_native", "sqlite_memory_delegates",
            "socket_class", "socket_reject_before_native", "ssl_cached_constructor",
            "ssl_methods_reject", "fake_fd_wrap", "connect_reject", "dns_reject", "assertions",
        )},
    }
    bad_true = json.loads(json.dumps(valid))
    bad_true["results"][next(iter(bad_true["results"]))] = 1
    boolean_proof = json.dumps({"installed_modules": True, "public_sources": True})
    try:
        validator(json.dumps(valid) + "\n" + boolean_proof, 0)
    except namespace["Stop"]:
        pass
    else:
        raise AssertionError("boolean-only normal-role provenance accepted")
    expected_sources = [
        {"module": "role_radar.discovery.contracts",
         "path": "/opt/role-radar/src/role_radar/discovery/contracts.py",
         "sha256": SOURCE_HASHES["src/role_radar/discovery/contracts.py"],
         "uid": 0, "gid": 0, "mode": 436, "nlink": 1, "device": 7, "inode": 9},
        {"module": "role_radar.services.pipeline_discovery",
         "path": "/opt/role-radar/src/role_radar/services/pipeline_discovery.py",
         "sha256": SOURCE_HASHES["src/role_radar/services/pipeline_discovery.py"],
         "uid": 0, "gid": 0, "mode": 420, "nlink": 1, "device": 7, "inode": 10},
    ]
    proof_line = json.dumps({"public_sources": expected_sources})
    validator(json.dumps(valid) + "\n" + proof_line, 0)
    invalid_proofs = [
        {"installed_modules": True, "public_sources": True},
        {"public_sources": [*expected_sources, expected_sources[0]]},
        {"public_sources": [{**expected_sources[0], "uid": True}, expected_sources[1]]},
        {"public_sources": [{**expected_sources[0], "device": 7.0}, expected_sources[1]]},
        {"public_sources": [{**expected_sources[0], "path": "/tmp/other"}, expected_sources[1]]},
        {"public_sources": [{**expected_sources[0], "sha256": "0" * 64}, expected_sources[1]]},
        {"public_sources": [{**expected_sources[0], "extra": 1}, expected_sources[1]]},
        {"public_sources": [expected_sources[0]]},
    ]
    for invalid_proof in invalid_proofs:
        try:
            validator(json.dumps(valid) + "\n" + json.dumps(invalid_proof), 0)
        except namespace["Stop"]:
            continue
        raise AssertionError("invalid normal-role provenance accepted")
    try:
        validator(json.dumps(bad_true) + "\n" + proof_line, 0)
    except namespace["Stop"]:
        strict_role = True
    else:
        raise AssertionError("integer one accepted as True")
    malformed_role = True
    for invalid in ("null", "[]", "{}"):
        try:
            validator(invalid + "\n" + proof_line, 0)
        except namespace["Stop"]:
            continue
        malformed_role = False
        break
    collector_node = next(node for node in ast.parse(role_program(False)).body
                          if isinstance(node, ast.FunctionDef)
                          and node.name == "collect_public_sources")
    collector_ns = {"hashlib": hashlib, "stat": __import__("stat"),
                    "importlib": SimpleNamespace(import_module=lambda name:
                        SimpleNamespace(__file__=dict((item[0], item[1])
                            for item in collector_checks)[name]))}
    exec(compile(ast.Module(body=[collector_node], type_ignores=[]),
                 "<isolated-role-collector>", "exec"), collector_ns)
    collector_checks = [
        ("role_radar.discovery.contracts", "/mock/contracts.py",
         hashlib.sha256(b"sourcebytes").hexdigest(), 0o664),
        ("role_radar.services.pipeline_discovery", "/mock/pipeline.py",
         hashlib.sha256(b"sourcebytes").hexdigest(), 0o644),
    ]
    closed_runs = []
    collector_events = []
    collector_read_counts = []
    def run_collector(change=None):
        opened, closed, reads, stats = [], [], {}, {}
        swapped = [False]
        def file_stat(path, **updates):
            values = dict(st_mode=__import__("stat").S_IFREG | next(
                item[3] for item in collector_checks if item[1] == path),
                st_uid=0, st_gid=0, st_nlink=1, st_size=11, st_dev=7,
                st_ino=10 + len(stats), st_mtime_ns=20, st_ctime_ns=30)
            values.update(updates)
            return SimpleNamespace(**values)
        def open_file(path, flags):
            fd = len(opened) + 20
            collector_events.append(("open", fd))
            opened.append((fd, path))
            stats[fd] = file_stat(path)
            reads[fd] = 0
            return fd
        def fstat(fd):
            collector_events.append(("fstat", fd))
            st = stats[fd]
            if change == "fd-change" and reads[fd] > 0:
                return file_stat(opened[fd - 20][1], st_ctime_ns=31)
            if change in ("mode", "link") and reads[fd] == 0:
                changed = ({"st_mode": __import__("stat").S_IFREG | 0o600}
                           if change == "mode" else {"st_nlink": 2})
                return file_stat(opened[fd - 20][1], **changed)
            return st
        def lstat(path):
            collector_events.append(("lstat", next(fd for fd, p in opened if p == path)))
            if ((change == "pre-path-replace" and path == "/mock/contracts.py")
                    or (change == "during-read-swap" and swapped[0]
                        and path == "/mock/contracts.py")):
                return file_stat(path, st_ino=999)
            return next(stats[fd] for fd, opened_path in opened if opened_path == path)
        def read_file(fd, size):
            collector_events.append(("read", fd))
            reads[fd] += 1
            if change == "during-read-swap":
                swapped[0] = True
            return b"sourcebytes" if reads[fd] == 1 else b""
        fake_os = SimpleNamespace(O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW,
            open=open_file, fstat=fstat, lstat=lstat,
            read=read_file, close=lambda fd: (collector_events.append(("close", fd)),
                                               closed.append(fd)))
        collector_ns["os"] = fake_os
        try:
            result = collector_ns["collect_public_sources"](collector_checks)
            return result, opened, closed
        finally:
            closed_runs.append((opened, closed))
            collector_read_counts.append(sum(reads.values()))
    collected, opened, closed = run_collector()
    assert (len(collected) == 2 and collected[0]["inode"] == 10
            and [fd for fd, _ in opened] == closed)
    expected_events = []
    for fd, _ in opened:
        expected_events.extend([("open", fd), ("fstat", fd), ("lstat", fd),
                                ("read", fd), ("read", fd), ("fstat", fd),
                                ("lstat", fd), ("close", fd)])
    assert collector_events == expected_events, collector_events
    try:
        run_collector("pre-path-replace")
    except RuntimeError:
        assert collector_read_counts[-1] == 0
        assert [fd for fd, _ in closed_runs[-1][0]] == closed_runs[-1][1]
    else:
        raise AssertionError("pre-read path mismatch was accepted")
    try:
        run_collector("during-read-swap")
    except RuntimeError:
        assert collector_read_counts[-1] > 0
        assert [fd for fd, _ in closed_runs[-1][0]] == closed_runs[-1][1]
    else:
        raise AssertionError("during-read path swap was accepted")
    for collector_change in ("fd-change", "mode", "link"):
        try:
            run_collector(collector_change)
        except RuntimeError:
            opened_failed, closed_failed = closed_runs[-1]
            assert [fd for fd, _ in opened_failed] == closed_failed
            continue
        raise AssertionError("collector accepted changed source metadata: " + collector_change)

    fake_os = SimpleNamespace(
        geteuid=lambda: 0,
        environ={"SUDO_UID": "123", "USER": "root", "PATH": "injected"},
        umask=lambda value: value,
        chdir=lambda path: path,
    )
    real_os = namespace["os"]
    namespace["os"] = fake_os
    namespace["root_only"]()
    assert fake_os.environ == {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root",
    }
    namespace["os"] = real_os
    directory_stat = SimpleNamespace(
        st_mode=namespace["stat"].S_IFDIR | 0o755,
        st_uid=0, st_gid=0, st_nlink=2,
    )
    fake_path_os = SimpleNamespace(
        lstat=lambda path: directory_stat,
        path=real_os.path,
    )
    namespace["os"] = fake_path_os
    namespace["directory"]("/mock/backups", 0, 0, 0o755)
    try:
        namespace["metadata"]("/mock/backups", 0, 0, 0o755)
    except namespace["Stop"]:
        directory_vs_file = True
    else:
        directory_vs_file = False
    namespace["os"] = real_os
    file_stat = SimpleNamespace(
        st_mode=namespace["stat"].S_IFREG | 0o644, st_uid=0, st_gid=0,
        st_nlink=1, st_size=3, st_dev=7, st_ino=9,
    )
    parent_stat = SimpleNamespace(
        st_mode=namespace["stat"].S_IFDIR | 0o755, st_uid=0, st_gid=0,
        st_dev=7, st_ino=8,
    )
    reads = [b"abc", b""]
    opened_stats = [file_stat, file_stat]
    def file_open(path, flags, dir_fd=None, mode=0o777):
        if dir_fd is None and path == "/":
            return 30
        if dir_fd is not None and path == "mock":
            return 31
        return 17
    fake_file_os = SimpleNamespace(
        path=real_os.path, O_RDONLY=real_os.O_RDONLY, O_NOFOLLOW=real_os.O_NOFOLLOW,
        O_DIRECTORY=real_os.O_DIRECTORY, open=file_open,
        fstat=lambda fd: parent_stat if fd != 17 else opened_stats.pop(0),
        stat=lambda name, **kwargs: file_stat,
        lstat=lambda path: parent_stat if path == "/mock" else file_stat,
        read=lambda fd, size: reads.pop(0), close=lambda fd: None,
    )
    namespace["PARENTS"]["/mock/source.py"] = (
        31, "source.py", ((7, 8), (7, 8)))
    namespace["os"] = fake_file_os
    read_result = namespace["read_target"]("/mock/source.py", ("source", 0o644))
    assert read_result[1] == b"abc"
    opened_stats = [SimpleNamespace(**{**vars(file_stat), "st_ino": 10})]
    try:
        namespace["read_target"]("/mock/source.py", ("source", 0o644))
    except namespace["Stop"]:
        fstat_binding = True
    else:
        fstat_binding = False
    namespace["os"] = real_os
    leaf_reads = []
    def rebound_open(path, flags, dir_fd=None, mode=0o777):
        if path == "/":
            return 40
        if path == "mock":
            return 41
        if path == "source.py":
            leaf_reads.append(path)
            return 17
        raise AssertionError("unexpected open path")
    rebound_parent = SimpleNamespace(**{**vars(parent_stat), "st_ino": 99})
    rebound_os = SimpleNamespace(
        path=real_os.path, O_RDONLY=real_os.O_RDONLY, O_NOFOLLOW=real_os.O_NOFOLLOW,
        O_DIRECTORY=real_os.O_DIRECTORY, open=rebound_open,
        fstat=lambda fd: parent_stat if fd == 40 else rebound_parent,
        close=lambda fd: None,
    )
    namespace["os"] = rebound_os
    try:
        namespace["read_target"]("/mock/source.py", ("source", 0o644))
    except namespace["Stop"]:
        parent_rebind_before_leaf_open = not leaf_reads
    else:
        parent_rebind_before_leaf_open = False
    assert parent_rebind_before_leaf_open, "parent rebind before leaf open was accepted"
    namespace["os"] = real_os
    namespace["PARENTS"] = {}
    fake_time = SimpleNamespace(monotonic=lambda: 171.0)
    real_time = namespace["time"]
    namespace["time"] = fake_time
    namespace["DEADLINE"] = 170.0
    try:
        namespace["remaining"]()
    except namespace["Stop"] as error:
        deadline = error.code == "operation_deadline_exceeded"
    else:
        deadline = False
    namespace["time"] = real_time
    real_stat = namespace["stat"]
    class BackupFile:
        def __init__(self, fd, path, files):
            self._fd = fd
            self._path = path
            self._files = files
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def write(self, data):
            self._files[self._path].extend(data)
        def flush(self):
            pass
        def fileno(self):
            return self._fd
    observed = {}
    for path, (key, mode) in namespace["TARGETS"].items():
        observed[path] = (
            SimpleNamespace(st_dev=7, st_ino=9, st_uid=0, st_gid=0,
                            st_mode=real_stat.S_IFREG | mode),
            b"body-" + key.encode(),
        )
    def backup_fake_os(fail=None):
        planned = []
        dirs = {"/", "/opt", "/opt/role-radar", "/opt/role-radar/data",
                namespace["BACKUPS"]}
        files = {}
        fds = {}
        events = []
        counter = [100]
        def mkdir(path, mode):
            events.append(("mkdir", path))
            if fail == "collision":
                raise FileExistsError(path)
            if fail == "mkdir":
                raise OSError("mkdir failed")
            dirs.add(path)
            planned.append(path)
        def chown(path, uid, gid):
            events.append(("chown", path))
            if fail == "chown":
                raise OSError("chown failed")
        def chmod(path, mode):
            events.append(("chmod", path))
            if fail == "chmod":
                raise OSError("chmod failed")
        def lstat(path):
            if path in dirs:
                mode = 0o700 if planned and path == planned[0] else 0o755
                return SimpleNamespace(st_mode=real_stat.S_IFDIR | mode, st_uid=0,
                                       st_gid=0, st_nlink=2, st_size=0, st_dev=7,
                                       st_ino=8)
            if path in files:
                return SimpleNamespace(
                    st_mode=real_stat.S_IFREG | 0o600, st_uid=0, st_gid=0,
                    st_nlink=1, st_size=len(files[path]), st_dev=7, st_ino=9)
            raise FileNotFoundError(path)
        def open_(path, flags, mode=0o777, dir_fd=None, follow_symlinks=True):
            if flags & real_os.O_DIRECTORY:
                fds[101] = path
                return 101
            events.append(("open", path))
            if fail == "copy" and path.endswith("before-0"):
                raise OSError("copy open failed")
            if flags & real_os.O_EXCL and path in files:
                raise FileExistsError(path)
            files.setdefault(path, bytearray())
            counter[0] += 1
            fds[counter[0]] = path
            return counter[0]
        fake = SimpleNamespace(
            path=real_os.path, mkdir=mkdir, chown=chown, chmod=chmod, lstat=lstat,
            open=open_,
            fdopen=lambda fd, mode, closefd=True: BackupFile(fd, fds[fd], files),
            fchown=lambda fd, uid, gid: events.append(("fchown", fds[fd])),
            fchmod=lambda fd, mode: events.append(("fchmod", fds[fd])),
            fsync=lambda fd: events.append(("fsync", fds.get(fd, fd))),
            close=lambda fd: events.append(("close", fds.get(fd, fd))),
            O_RDONLY=real_os.O_RDONLY, O_WRONLY=real_os.O_WRONLY,
            O_CREAT=real_os.O_CREAT, O_EXCL=real_os.O_EXCL,
            O_NOFOLLOW=real_os.O_NOFOLLOW, O_DIRECTORY=real_os.O_DIRECTORY,
        )
        return fake, dirs, files, fds, events, planned
    assert "open_backup" in namespace, "backup boundary function missing"
    namespace["time"] = SimpleNamespace(time_ns=lambda: 987654321)
    namespace["STATE"] = {}
    fake, _dirs, _files, _fds, events, _planned = backup_fake_os("collision")
    namespace["os"] = fake
    try:
        namespace["open_backup"](observed)
    except namespace["Stop"] as error:
        collision_code = error.code
    else:
        collision_code = None
    namespace["os"] = real_os
    collision_state = dict(namespace["STATE"])
    assert collision_code == "backup_path_collision", collision_code
    assert collision_state["backup_created"] is False
    assert collision_state["backup_mutations"] == 0
    assert collision_state["writes"] == 0 and collision_state["target_writes"] == 0
    assert events == [("mkdir", collision_state["backup"])], events
    collision_public = {"ok": False, "code": collision_code, **collision_state}
    assert collision_public["backup"] == collision_state["backup"]
    protection_code = None
    for protection_fail, expected_mutations in (("chown", 1), ("chmod", 2)):
        namespace["STATE"] = {}
        fake, _dirs, files, _fds, _events, _planned = backup_fake_os(protection_fail)
        namespace["os"] = fake
        try:
            namespace["open_backup"](observed)
        except BaseException as error:
            protection_code = (error.code if isinstance(error, namespace["Stop"])
                               else "operation_exception")
        namespace["os"] = real_os
        protection_state = dict(namespace["STATE"])
        record_path = protection_state["backup"] + "/result.json"
        assert protection_code == "operation_exception", protection_code
        assert protection_state["backup_created"] is True
        assert protection_state["writes"] == 0
        assert protection_state["backup_mutations"] == expected_mutations
        assert record_path in files, "durable failure record missing"
        protection_record = json.loads(bytes(files[record_path]).decode())
        assert protection_record["created"] is True
        assert protection_record["target_writes"] == 0
        assert protection_record["error"] == "operation_exception"
        assert protection_record["backup_mutations"] == expected_mutations
    namespace["STATE"] = {}
    fake, _dirs, files, _fds, events, _planned = backup_fake_os("copy")
    namespace["os"] = fake
    copy_code = None
    try:
        namespace["open_backup"](observed)
    except BaseException as error:
        copy_code = (error.code if isinstance(error, namespace["Stop"])
                     else "operation_exception")
    namespace["os"] = real_os
    copy_state = dict(namespace["STATE"])
    copy_record_path = copy_state["backup"] + "/result.json"
    assert copy_code == "operation_exception", copy_code
    assert copy_state["backup_created"] is True
    assert copy_state["writes"] == 0 and copy_state["backup_mutations"] == 3
    assert copy_record_path in files, "partial failure record missing"
    copy_record = json.loads(bytes(files[copy_record_path]).decode())
    assert copy_record["created"] is True and copy_record["target_writes"] == 0
    assert copy_record["backup_mutations"] == 3
    assert copy_state["backup"] + "/before.json" not in files
    namespace["STATE"] = {}
    fake, _dirs, files, _fds, _events, _planned = backup_fake_os()
    namespace["os"] = fake
    good_backup, good_before, good_result = namespace["open_backup"](observed)
    namespace["os"] = real_os
    backup_success_records = (
        namespace["STATE"]["backup_created"] is True
        and namespace["STATE"]["backup_mutations"] == 7
        and good_before["state"] == "backup_complete"
        and len(good_before["targets"]) == 2
        and good_result["state"] == "staging"
    )
    for index, path in enumerate(namespace["TARGETS"]):
        assert bytes(files[good_backup + "/before-" + str(index)]) == observed[path][1]
    assert json.loads(
        bytes(files[good_backup + "/before.json"]).decode())["state"] == "backup_complete"
    namespace["time"] = real_time
    namespace["STATE"] = {}
    print(json.dumps({
        "actual_classify_old_candidate_mixed": True,
        "actual_parse_units_out_of_order_timer_optional_duplicate_missing": True,
        "actual_parse_canaries_active_pid0_duplicate_rejected": True,
        "actual_role_boolean_and_malformed_json_validation": strict_role and malformed_role,
        "actual_root_environment_sanitization": True,
        "actual_directory_vs_file_metadata": directory_vs_file,
        "actual_source_fstat_binding": fstat_binding,
        "actual_shared_deadline": deadline,
        "actual_backup_collision_fail_closed": collision_code == "backup_path_collision",
        "actual_backup_protection_failure_truthful": protection_code == "operation_exception",
        "actual_backup_copy_failure_truthful": copy_code == "operation_exception",
        "actual_backup_success_records": backup_success_records,
        "emitted_root_compile": True,
        "full_promote_flow_mocked": False,
    }, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-root", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.emit_root:
        sys.stdout.write(emit_root())
    elif args.self_test:
        self_test()
    else:
        parser.error("select --emit-root or --self-test")


if __name__ == "__main__":
    main()
