#!/usr/bin/env python3
"""Owner-side transport checks for committed discovery regressions."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from unittest import mock

COMMIT = "ec2fdac275d2a11799871cae65831c29b93a9866"
PATHS = (
    "src/role_radar/discovery/contracts.py",
    "src/role_radar/services/pipeline_discovery.py",
    "tests/integration/test_canary_discovery.py",
    "tests/unit/test_acquired_job_writer_diagnostics.py",
)
HASHES = (
    "6b354b9e87cc65ddd7d62ef13422aa6b8cfe43f9cb5aef9add2d60c2c522807c",
    "6bedf540c02f187d94a9b1777897cdb1da4c561d42a803d8d16d7e6e26dfba90",
    "4c2c3530fd68941702d57ff25286089d7fcf6f191733360612d472a21454927b",
    "41e20957ba8bd20850b01f9c76b89f4c1e2b0dbbf5628a00a99846da21a407ff",
)
BLOBS = dict(zip(PATHS, HASHES, strict=True))
GUARD_NAMES = frozenset([
    "sqlite_alias", "sqlite_reject_before_native", "sqlite_memory_delegates",
    "socket_class", "socket_reject_before_native", "ssl_cached_constructor",
    "ssl_methods_reject", "fake_fd_wrap", "connect_reject", "dns_reject",
    "assertions", "real_packages",
])
CASES = {
    "test_canary_discovery_searches_once_and_verifies_only_one_greenhouse",
    "test_board_verification_diagnostics_are_local_and_preserve_accepted_jobs",
    "test_reused_cycle_preserves_historical_stats_without_verification",
    "test_finalize_persists_bounded_writer_diagnostics_across_zero_accept_writes",
    "test_finalize_sanitizes_board_verification_counts",
    "test_writer_adds_missing_application_url_reason_once",
}
SAFE_ERRORS = frozenset([
    "ArithmeticError", "AssertionError", "AttributeError", "BrokenPipeError",
    "BufferError", "ConnectionError", "ConnectionRefusedError", "DatabaseError",
    "EOFError", "Exception", "FileNotFoundError", "FloatingPointError",
    "ImportError", "IndentationError", "IndexError", "KeyError", "LookupError",
    "MemoryError", "ModuleNotFoundError", "NameError", "NotImplementedError",
    "OSError", "OperationalError", "OverflowError", "PermissionError",
    "ProgrammingError", "RecursionError", "RuntimeError", "SSLError",
    "StopAsyncIteration", "StopIteration", "SyntaxError", "SystemError",
    "TimeoutError", "TypeError", "UnboundLocalError", "ValueError",
    "ZeroDivisionError",
])


def sources():
    result = {}
    for path, digest in BLOBS.items():
        blob = subprocess.check_output(["git", "show", f"{COMMIT}:{path}"])
        if hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError("committed blob hash mismatch")
        result[path] = blob.decode()
    return result


ROLE = r'''import ast, hashlib, importlib, json, os, socket, sqlite3, sys, types, ssl
from unittest import mock
_N = socket.socket
_NATIVE_NEW, _NATIVE_INIT = _N.__new__, _N.__init__
_NAMES = (
    "connect", "connect_ex", "send", "sendall", "sendto", "sendmsg",
    "sendfile", "bind", "listen", "accept", "shutdown",
)
_NATIVE_METHODS = {n: getattr(_N, n) for n in _NAMES if hasattr(_N, n)}
_PAIR = False

def guarded_new(cls, *a, **k):
    family = a[0] if a else k.get("family", socket.AF_INET)
    fd = a[3] if len(a) > 3 else k.get("fileno")
    if cls is not _N or not (_PAIR and family == socket.AF_UNIX and fd is not None):
        raise OSError("socket creation disabled")
    return _NATIVE_NEW(cls, *a, **k)

def guarded_init(self, *a, **k):
    family = a[0] if a else k.get("family", socket.AF_INET)
    fd = a[3] if len(a) > 3 else k.get("fileno")
    if not (_PAIR and family == socket.AF_UNIX and fd is not None):
        raise OSError("socket initialization disabled")
    return _NATIVE_INIT(self, *a, **k)
_N.__new__, _N.__init__ = staticmethod(guarded_new), guarded_init

def blocked(self, *_a, **_k): raise OSError("socket operation disabled")
for n in _NATIVE_METHODS: setattr(_N, n, blocked)
_SSL_CREATE = ssl.SSLSocket._create
def blocked_tls(self, *_a, **_k): raise OSError("TLS socket operation disabled")
for n in (*_NAMES, "_create"):
    if hasattr(ssl.SSLSocket, n): setattr(ssl.SSLSocket, n, blocked_tls)
_PAIR_IMPL = socket.socketpair
def guarded_pair(*a, **k):
    global _PAIR
    _PAIR = True
    try: return _PAIR_IMPL(*a, **k)
    finally: _PAIR = False
socket.socketpair = guarded_pair

def deny(*_a, **_k): raise OSError("network disabled")
deny.__role_radar_denied__ = True
socket.create_connection = deny
for n in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
    setattr(socket, n, deny)
_SQLITE = sqlite3.dbapi2.connect
def memory_connect(database=None, *a, **k):
    if database != ":memory:": raise ValueError("memory database required")
    return _SQLITE(database, *a, **k)
sqlite3.connect = sqlite3.dbapi2.connect = memory_connect
sys.path.insert(0, MODULE_ROOT)
packages = {}
if PAYLOAD["candidate"]:
    for n in ("role_radar", "role_radar.discovery", "role_radar.services"):
        packages[n] = importlib.import_module(n)
    modules = (
        ("role_radar.discovery.contracts", "src/role_radar/discovery/contracts.py"),
        ("role_radar.services.pipeline_discovery", "src/role_radar/services/pipeline_discovery.py"),
    )
    for name, path in modules:
        src = PAYLOAD["sources"][path]
        if hashlib.sha256(src.encode()).hexdigest() != PAYLOAD["hashes"][path]:
            raise ValueError("module hash")
        mod = types.ModuleType(name)
        mod.__file__ = os.path.join(MODULE_ROOT, path.removeprefix("src/"))
        mod.__package__ = name.rpartition(".")[0]
        sys.modules[name] = mod
        setattr(sys.modules[mod.__package__], name.rsplit(".", 1)[1], mod)
        exec(compile(src, mod.__file__, "exec"), mod.__dict__)

def rejected(fn):
    try: fn()
    except (OSError, ValueError): return True
    return False
_db_calls = []
_db_saved = _SQLITE
_marker = object()
_SQLITE = lambda db, *_a, **_k: (_db_calls.append(db), _marker)[1]
db_block = all(rejected(lambda db=db: sqlite3.connect(db)) for db in (None, ""))
db_memory = sqlite3.connect(":memory:") is _marker and _db_calls == [":memory:"]
_SQLITE = _db_saved
_native_calls = []
def native_new(*_a, **_k):
    _native_calls.append("new")
    return object()
def native_init(*_a, **_k): _native_calls.append("init")
_saved_new, _saved_init = _NATIVE_NEW, _NATIVE_INIT
_NATIVE_NEW, _NATIVE_INIT = native_new, native_init
socket_block = all(
    rejected(lambda f=f: _N(f))
    for f in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX)
)
class FakeSocket:
    family, type, proto = socket.AF_INET, socket.SOCK_STREAM, 0
    def getsockopt(self, *_a): return socket.SOCK_STREAM
    def gettimeout(self): return None
    def fileno(self): return 123
try:
    ssl_constructor_block = (
        rejected(lambda: _SSL_CREATE(
            FakeSocket(),
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
            server_hostname="synthetic.invalid",
        ))
        and not _native_calls
    )
    _PAIR = True
    guarded_new(_N, socket.AF_UNIX, socket.SOCK_STREAM, 0, 123)
    guarded_init(FakeSocket(), socket.AF_UNIX, socket.SOCK_STREAM, 0, 123)
    fake_fd = _native_calls == ["new", "init"]
finally:
    _PAIR = False
    _NATIVE_NEW, _NATIVE_INIT = _saved_new, _saved_init
_method_calls = []
_methods = dict(_NATIVE_METHODS)
for n in _NATIVE_METHODS:
    _NATIVE_METHODS[n] = lambda *_a, **_k: _method_calls.append("native")
native_method_block = all(
    rejected(lambda n=n: getattr(_N, n)(object(), "sentinel"))
    for n in _NATIVE_METHODS
)
ssl_method_block = all(
    rejected(lambda n=n: getattr(ssl.SSLSocket, n)(object(), "sentinel"))
    for n in _NAMES
    if hasattr(ssl.SSLSocket, n)
)
method_block = native_method_block and ssl_method_block and not _method_calls
_NATIVE_METHODS.update(_methods)
dns_names = ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo")
dns_block = all(rejected(lambda n=n: getattr(socket, n)("sentinel")) for n in dns_names)
assertions = sum(
    isinstance(a, ast.Assert)
    for p in (
        "tests/integration/test_canary_discovery.py",
        "tests/unit/test_acquired_job_writer_diagnostics.py",
    )
    for f in ast.parse(PAYLOAD["sources"][p]).body
    if isinstance(f, ast.FunctionDef) and f.name.startswith("test_")
    for a in ast.walk(f)
)
guards = {
    "sqlite_alias": sqlite3.connect is sqlite3.dbapi2.connect,
    "sqlite_reject_before_native": db_block,
    "sqlite_memory_delegates": db_memory,
    "socket_class": socket.socket is _N,
    "socket_reject_before_native": socket_block and _native_calls == ["new", "init"],
    "ssl_cached_constructor": ssl_constructor_block,
    "ssl_methods_reject": ssl_method_block,
    "fake_fd_wrap": fake_fd,
    "connect_reject": native_method_block,
    "dns_reject": dns_block and getattr(socket.getaddrinfo, "__role_radar_denied__", False),
    "assertions": assertions == 21,
}
if PAYLOAD["candidate"]:
    guards["real_packages"] = (
        all(p.__file__ and p.__path__ for p in packages.values())
        and callable(packages["role_radar.discovery"].__getattr__)
    )
if not all(guards.values()):
    print(json.dumps({
        "stage": "guard",
        "flags": {n: guards.get(n) is True for n in GUARD_NAMES if n in guards},
    }))
    raise SystemExit(1)

def selected(n):
    return isinstance(n, (ast.Import, ast.ImportFrom)) or (
        isinstance(n, ast.FunctionDef)
        and (n.name.startswith("test_") or n.name == "_profile")
    )
namespace = {"__name__": "transported_committed_tests"}
for path in (
    "tests/integration/test_canary_discovery.py",
    "tests/unit/test_acquired_job_writer_diagnostics.py",
):
    tree = ast.parse(PAYLOAD["sources"][path])
    body = [n for n in tree.body if selected(n)]
    exec(compile(ast.Module(body=body, type_ignores=[]), path, "exec"), namespace)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from role_radar.db.base import Base
class Patcher:
    def __init__(self):
        from contextlib import ExitStack
        self.stack = ExitStack()
    def setattr(self, target, name, value):
        self.stack.enter_context(mock.patch.object(target, name, value))
results = {}
for case in CASES:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    patcher = Patcher()
    try:
        fn = namespace[case]
        names = fn.__code__.co_varnames[:fn.__code__.co_argcount]
        args = {}
        if "db_session" in names: args["db_session"] = session
        if "monkeypatch" in names: args["monkeypatch"] = patcher
        fn(**args)
        results[case] = True
    except Exception as exc:
        results[case] = False
        label = type(exc).__name__ if type(exc).__name__ in SAFE_ERRORS else "ChildCaseError"
        print(json.dumps({"stage": "case", "error": label, "case": case, "results": results}))
        raise SystemExit(1)
    finally:
        patcher.stack.close()
        session.close()
        engine.dispose()
print(json.dumps(
    {
        "stage": "complete", "results": results, "assertions": assertions,
        "guards": {n: guards.get(n) is True for n in GUARD_NAMES if n in guards},
    },
    sort_keys=True,
))
'''


def role_source(candidate=False, module_root="/opt/role-radar/src"):
    payload = {"sources": sources(), "candidate": candidate, "hashes": BLOBS}
    return (
        f"PAYLOAD = {payload!r}\nCASES = {sorted(CASES)!r}\n"
        f"SAFE_ERRORS = {SAFE_ERRORS!r}\nGUARD_NAMES = {GUARD_NAMES!r}\n"
        f"MODULE_ROOT = {module_root!r}\n{ROLE}"
    )


def run_child(candidate, root):
    code = role_source(candidate, root)
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-B", "-"], input=code,
            text=True, capture_output=True, check=False, timeout=40,
        )
    except subprocess.TimeoutExpired:
        return None, {"stage": "timeout", "error": "ChildTimeout"}
    try:
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        labels = (line.split(":", 1)[0] for line in reversed(proc.stderr.splitlines()))
        error = next((n for n in labels if n in SAFE_ERRORS), "ChildExecutionError")
        payload = {"stage": "child", "error": error}
    stages = {"complete", "guard", "case", "child", "imports", "transport"}
    if not isinstance(payload, dict) or payload.get("stage") not in stages:
        payload = {"stage": "child", "error": "ChildExecutionError"}
    elif payload["stage"] == "complete":
        values = payload.get("results", {})
        payload = (
            {
                "stage": "complete",
                "results": {n: values.get(n) is True for n in CASES if n in values},
                "assertions": 21 if payload.get("assertions") == 21 else 0,
                "guards": {
                    n: payload["guards"].get(n) is True
                    for n in GUARD_NAMES if n in payload["guards"]
                } if isinstance(payload.get("guards"), dict) else {},
            }
            if isinstance(values, dict)
            else {"stage": "child", "error": "ChildExecutionError"}
        )
    elif payload["stage"] == "case":
        values = payload.get("results", {})
        values = values if isinstance(values, dict) else {}
        error = payload.get("error")
        payload = {
            "stage": "case",
            "error": error if error in SAFE_ERRORS else "ChildCaseError",
            "case": payload.get("case") if payload.get("case") in CASES else None,
            "results": {n: values.get(n) is True for n in CASES if n in values},
        }
    elif payload["stage"] == "guard":
        values = payload.get("flags", {})
        values = values if isinstance(values, dict) else {}
        payload = {
            "stage": "guard",
            "flags": {n: values.get(n) is True for n in GUARD_NAMES if n in values},
        }
    elif payload["stage"] in {"child", "imports", "transport"}:
        error = payload.get("error")
        payload = {
            "stage": payload["stage"],
            "error": error if error in SAFE_ERRORS else "ChildExecutionError",
        }
    return proc.returncode, payload


def protocol_checks(root):
    code = role_source(False, root)
    fake = subprocess.CompletedProcess([], 9, "", "PrivatePathError: hidden payload")
    with (
        mock.patch.object(sys.modules[__name__], "role_source", return_value=code),
        mock.patch.object(subprocess, "run", return_value=fake),
    ):
        rc, child = run_child(False, root)
        unknown = rc == 9 and child == {"stage": "child", "error": "ChildExecutionError"}
    with (
        mock.patch.object(sys.modules[__name__], "role_source", return_value=code),
        mock.patch.object(
            subprocess, "run", side_effect=subprocess.TimeoutExpired("stdin", 40)
        ),
    ):
        rc, child = run_child(False, root)
        timeout = rc is None and child == {"stage": "timeout", "error": "ChildTimeout"}
    complete = {
        "stage": "complete",
        "results": {name: True for name in CASES},
        "assertions": 21,
        "guards": {
            "sqlite_alias": True,
            "socket_class": 1,
            "unknown_key": "sentinel",
        },
    }
    fake = subprocess.CompletedProcess([], 0, json.dumps(complete), "")
    with (
        mock.patch.object(sys.modules[__name__], "role_source", return_value=code),
        mock.patch.object(subprocess, "run", return_value=fake),
    ):
        rc, child = run_child(False, root)
        complete_projection = (
            rc == 0
            and set(child.get("results", {})) == CASES
            and all(child["results"].values())
            and child.get("assertions") == 21
            and child.get("guards") == {
                "sqlite_alias": True,
                "socket_class": False,
            }
            and all(type(value) is bool for value in child.get("guards", {}).values())
        )
    complete["guards"] = None
    fake = subprocess.CompletedProcess([], 0, json.dumps(complete), "")
    with (
        mock.patch.object(sys.modules[__name__], "role_source", return_value=code),
        mock.patch.object(subprocess, "run", return_value=fake),
    ):
        rc, child = run_child(False, root)
        nondict_guards = rc == 0 and child.get("guards") == {}
    fake = subprocess.CompletedProcess([], 1, "not-json", "private payload")
    with (
        mock.patch.object(sys.modules[__name__], "role_source", return_value=code),
        mock.patch.object(subprocess, "run", return_value=fake),
    ):
        rc, child = run_child(False, root)
        malformed = rc == 1 and child == {"stage": "child", "error": "ChildExecutionError"}
    return {
        "unknown_error": unknown, "timeout": timeout, "malformed_output": malformed,
        "complete_projection": complete_projection, "nondict_guards": nondict_guards,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-role", action="store_true")
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.emit_role:
        sys.stdout.write(role_source(args.candidate))
    elif args.self_test:
        root = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "src"
        )
        protocol = protocol_checks(root)
        if not all(protocol.values()):
            print(json.dumps({"stage": "protocol", "flags": protocol}))
            raise SystemExit(1)
        for candidate in (False, True):
            rc, result = run_child(candidate, root)
            values = result.get("results", {})
            if (
                rc or set(values) != CASES or not all(values.values())
                or result.get("assertions") != 21
            ):
                print(json.dumps({
                    "stage": result.get("stage"),
                    "error": result.get("error"),
                    "flags": result.get("flags"),
                    "cases": sum(values.values()),
                    "total": len(values),
                    "assertions": result.get("assertions"),
                }))
                raise SystemExit(1)
            print(json.dumps({
                "mode": "candidate" if candidate else "normal",
                "cases": len(values),
                "passed": sum(values.values()),
                "assertions": result["assertions"],
                "guards": result["guards"],
                "results": values,
            }, sort_keys=True))
    else:
        parser.error("select --emit-role or --self-test")


main()
