from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from role_radar.acquisition import discovery_policy as policy_files
from role_radar.acquisition.discovery_policy import (
    DiscoveryPolicyFileError,
    DiscoveryPolicyFilePolicy,
)
from role_radar.discovery.policy import DiscoveryPhraseGrammarV1, DiscoveryPolicyV1
from role_radar.domain.profile import canonical_profile_sha256
from scripts import bounded_canary_binding as adapter
from tests.unit.test_discovery_policy import policy_payload

PROFILE_ID = "00000000-0000-0000-0000-000000000001"
PROFILE = {
    "title": "  Backend   Engineer ",
    "years_of_experience": 5,
    "target_roles": ["backend"],
    "target_titles": [],
    "core_skills": ["Python"],
    "secondary_skills": [],
    "regions": [],
    "remote_only": False,
    "employment_preferences": [],
    "languages": {},
    "excluded_roles": [],
    "excluded_technologies": [],
    "hard_constraints": {},
    "soft_preferences": {},
}


def _database(path: Path, *, row=None, table=True) -> bytes:
    db = sqlite3.connect(path)
    if not table:
        db.execute("CREATE TABLE unrelated_fixture (id INTEGER)")
    if table:
        db.execute(
            "CREATE TABLE candidate_profiles (id TEXT, version INTEGER, schema_version INTEGER, "
            "profile_json TEXT, is_active INTEGER)"
        )
        values = row or (PROFILE_ID, 1, 1, json.dumps(PROFILE), 1)
        db.execute("INSERT INTO candidate_profiles VALUES (?, ?, ?, ?, ?)", values)
    db.commit()
    db.close()
    return path.read_bytes()


def _policy_file(path: Path, *, binding=None) -> bytes:
    payload = policy_payload()
    payload["profile_binding"]["canonical_profile_sha256"] = canonical_profile_sha256(PROFILE)
    if binding:
        payload["profile_binding"].update(binding)
    policy = DiscoveryPolicyV1.model_validate(payload)
    grammar = DiscoveryPhraseGrammarV1().model_dump(mode="json")
    grammar_toml = "\n".join(
        f"{key} = {json.dumps(value, ensure_ascii=False)}" for key, value in grammar.items()
    )
    raw = (
        'schema_version = 1\npolicy_version = "gate-a-v1"\n\n'
        "[profile_binding]\n"
        f'profile_id = "{policy.profile_binding.profile_id}"\n'
        f"row_version = {policy.profile_binding.row_version}\n"
        f"schema_version = {policy.profile_binding.schema_version}\n"
        f'canonical_profile_sha256 = "{policy.profile_binding.canonical_profile_sha256}"\n\n'
        f"[phrase_grammar]\n{grammar_toml}\n\n"
        '[groups]\nprimary = ["Backend Engineer"]\n\n'
        "[target_roles.backend]\nprimary_groups = [\"primary\"]\n\n[target_titles]\n"
    ).encode()
    path.write_bytes(raw)
    path.chmod(0o640)
    return raw


def _validate_synthetic_parent(parent, fixture_root):
    assert parent == fixture_root
    assert parent.is_dir() and not parent.is_symlink()


def _validate_synthetic_metadata(policy, descriptor):
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise DiscoveryPolicyFileError("discovery_policy_not_regular")
    if stat.S_IMODE(metadata.st_mode) != policy.mode:
        raise DiscoveryPolicyFileError("discovery_policy_mode_invalid")
    if metadata.st_nlink != 1:
        raise DiscoveryPolicyFileError("discovery_policy_link_invalid")


def _invoke(monkeypatch, db_path: Path, policy_path: Path, *, args=()):
    monkeypatch.setattr(adapter, "DEFAULT_DISCOVERY_POLICY_PATH", policy_path)
    monkeypatch.setattr(policy_files, "DEFAULT_DISCOVERY_POLICY_PATH", policy_path)
    # Keep the real production file-policy factory, but mock root/gid metadata
    # before its official loader validates synthetic unprivileged fixture files.
    monkeypatch.setattr(
        policy_files,
        "_validate_parent_chain",
        lambda parent, _policy: _validate_synthetic_parent(parent, policy_path.parent),
    )
    monkeypatch.setattr(
        DiscoveryPolicyFilePolicy,
        "validate",
        lambda self, fd: _validate_synthetic_metadata(self, fd),
    )
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", adapter._Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", adapter._Capture(stderr))
    argv = ["--database-url", f"sqlite:///{db_path}", *args]
    code = adapter.main(argv)
    return code, "".join(stdout), "".join(stderr)


def test_public_success_uses_official_policy_loader_and_canonical_row(tmp_path, monkeypatch):
    db_path, policy_path = tmp_path / "synthetic.db", tmp_path / "policy.toml"
    db_before = _database(db_path)
    policy_before = _policy_file(policy_path)
    loader_calls = []
    actual_loader = adapter._load_policy

    def checked_loader(path):
        loader_calls.append(path)
        return actual_loader(path)

    monkeypatch.setattr(adapter, "_load_policy", checked_loader)
    result = _invoke(monkeypatch, db_path, policy_path)
    assert result == (
        0,
        "PROFILE_BINDING_GATE: PASS (policy/profile binding only; not overall readiness)\n",
        "",
    )
    assert loader_calls == [str(policy_path), str(policy_path)]
    assert db_path.read_bytes() == db_before
    assert policy_path.read_bytes() == policy_before


@pytest.mark.parametrize(
    ("row", "binding", "code"),
    [
        (("private-other-id", 1, 1, json.dumps(PROFILE), 1), {}, "profile_binding_mismatch"),
        ((PROFILE_ID, 2, 1, json.dumps(PROFILE), 1), {}, "discovery_profile_binding_mismatch"),
        ((PROFILE_ID, 1, 2, json.dumps(PROFILE), 1), {}, "discovery_profile_binding_mismatch"),
        (
            (PROFILE_ID, 1, 1, json.dumps({**PROFILE, "title": "Changed"}), 1),
            {},
            "discovery_profile_binding_mismatch",
        ),
        ((PROFILE_ID, 1, 1, json.dumps(PROFILE), 0), {}, "discovery_profile_binding_mismatch"),
        ((PROFILE_ID, 1, 1, "not-json", 1), {}, "profile_binding_mismatch"),
        (
            (PROFILE_ID, 1, 1, json.dumps({"secret": "private-payload-marker"}), 1),
            {},
            "discovery_profile_invalid",
        ),
        ((PROFILE_ID, 1, 1, json.dumps(PROFILE), 2), {}, "profile_invalid"),
        ((PROFILE_ID, 1, 1, json.dumps(PROFILE), "false"), {}, "profile_invalid"),
        (
            (PROFILE_ID, 1, 1, json.dumps(PROFILE), 1),
            {"profile_id": "00000000-0000-0000-0000-000000000002"},
            "profile_binding_mismatch",
        ),
    ],
    ids=(
        "wrong-id", "wrong-version", "wrong-schema", "wrong-fingerprint", "inactive",
        "invalid-json", "invalid-profile", "noncanonical-active", "text-active",
        "missing-bound-row",
    ),
)
def test_public_binding_mismatches_fail_without_writes(tmp_path, monkeypatch, row, binding, code):
    db_path, policy_path = tmp_path / "synthetic.db", tmp_path / "policy.toml"
    db_before = _database(db_path, row=row)
    policy_before = _policy_file(policy_path, binding=binding)
    result = _invoke(monkeypatch, db_path, policy_path)
    assert result == (1, "", f"PROFILE_BINDING_GATE: FAIL ({code})\n")
    assert db_path.read_bytes() == db_before
    assert policy_path.read_bytes() == policy_before
    assert PROFILE_ID not in result[1] + result[2]
    assert "private-payload-marker" not in result[1] + result[2]


@pytest.mark.parametrize("table", [False, True], ids=("missing-table", "missing-required-column"))
def test_public_profile_schema_failures_are_fixed(tmp_path, monkeypatch, table):
    db_path, policy_path = tmp_path / "synthetic.db", tmp_path / "policy.toml"
    if table:
        db = sqlite3.connect(db_path)
        db.execute("CREATE TABLE candidate_profiles (id TEXT)")
        db.commit()
        db.close()
        db_before = db_path.read_bytes()
    else:
        db_before = _database(db_path, table=False)
    policy_before = _policy_file(policy_path)
    result = _invoke(monkeypatch, db_path, policy_path)
    assert result == (1, "", "PROFILE_BINDING_GATE: FAIL (profile_schema_invalid)\n")
    assert db_path.read_bytes() == db_before
    assert policy_path.read_bytes() == policy_before


@pytest.mark.parametrize("kind,code", [
    ("missing", "discovery_policy_unavailable"),
    ("mode", "discovery_policy_mode_invalid"),
    ("malformed", "discovery_policy_invalid"),
    ("symlink", "discovery_policy_unavailable"),
    ("hardlink", "discovery_policy_link_invalid"),
])
def test_public_policy_file_errors_are_fixed_and_close_database(tmp_path, monkeypatch, kind, code):
    db_path, policy_path = tmp_path / "synthetic.db", tmp_path / "policy.toml"
    _database(db_path)
    if kind == "mode":
        _policy_file(policy_path)
        policy_path.chmod(0o644)
    elif kind == "malformed":
        policy_path.write_text("bad = [", encoding="utf-8")
        policy_path.chmod(0o640)
    elif kind == "symlink":
        target = tmp_path / "target.toml"
        _policy_file(target)
        policy_path.symlink_to(target)
    elif kind == "hardlink":
        _policy_file(policy_path)
        (tmp_path / "second-link.toml").hardlink_to(policy_path)
    else:
        policy_path = tmp_path / "absent.toml"
    result = _invoke(monkeypatch, db_path, policy_path)
    assert result == (1, "", f"PROFILE_BINDING_GATE: FAIL ({code})\n")


def test_bad_arguments_reject_before_policy_or_database_open(tmp_path, monkeypatch):
    db_path, policy_path = tmp_path / "synthetic.db", tmp_path / "policy.toml"
    _database(db_path)
    _policy_file(policy_path)
    opened = []
    monkeypatch.setattr(adapter, "_load_policy", lambda *_: opened.append("policy"))
    monkeypatch.setattr(adapter, "_connect_database", lambda *_: opened.append("database"))
    for argv in (
        ["--database-url", "x", "--database-url", "y"],
        ["--database-url=one", "--database-url", "two"],
        ["--policy-path", "x", "--policy-path=y"],
        ["--database-u", "x"],
        ["--private-argument-marker"],
        ["--database-url"],
    ):
        output, errors = [], []
        monkeypatch.setattr(adapter.sys, "stdout", adapter._Capture(output))
        monkeypatch.setattr(adapter.sys, "stderr", adapter._Capture(errors))
        assert adapter.main(argv) == 1
        assert output == []
        assert "".join(errors) == "PROFILE_BINDING_GATE: FAIL (arguments_invalid)\n"
        assert "private-argument-marker" not in "".join(errors)
    assert opened == []


def test_bad_url_never_opens_policy_or_database(tmp_path, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(adapter, "_load_policy", lambda *_: calls.append("policy"))
    monkeypatch.setattr(adapter, "_connect_database", lambda *_: calls.append("database"))
    result = adapter.main(["--database-url", "postgres://private-marker"])
    assert result == 1
    assert calls == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "PROFILE_BINDING_GATE: FAIL (database_target_invalid)\n"


def test_policy_change_during_inspection_fails_closed(tmp_path, monkeypatch):
    db_path, policy_path = tmp_path / "synthetic.db", tmp_path / "policy.toml"
    db_before = _database(db_path)
    policy_before = _policy_file(policy_path)
    original_connect = adapter._connect_database

    def change_policy_after_first_load(url):
        connection = original_connect(url)
        policy_path.write_bytes(policy_before.replace(b"gate-a-v1", b"gate-a-v2"))
        return connection

    monkeypatch.setattr(adapter, "_connect_database", change_policy_after_first_load)
    result = _invoke(monkeypatch, db_path, policy_path)
    assert result == (1, "", "PROFILE_BINDING_GATE: FAIL (policy_changed)\n")
    assert db_path.read_bytes() == db_before
    assert policy_path.read_bytes() != policy_before


def test_help_returns_without_opening_policy_or_database(monkeypatch):
    opened = []
    monkeypatch.setattr(adapter, "_load_policy", lambda *_: opened.append("policy"))
    monkeypatch.setattr(adapter, "_connect_database", lambda *_: opened.append("database"))
    with pytest.raises(SystemExit) as result:
        adapter.main(["--help"])
    assert result.value.code == 0
    assert opened == []


def test_database_connection_closes_after_profile_schema_failure(tmp_path, monkeypatch):
    from scripts import bounded_canary_database as database_adapter

    db_path, policy_path = tmp_path / "synthetic.db", tmp_path / "policy.toml"
    db_before = _database(db_path, table=False)
    policy_before = _policy_file(policy_path)
    closed = []
    original_close = sqlite3.Connection.close

    def tracked_close(connection):
        closed.append(True)
        original_close(connection)

    monkeypatch.setattr(database_adapter._ReadOnlyConnection, "close", tracked_close)
    result = _invoke(monkeypatch, db_path, policy_path)
    assert result == (1, "", "PROFILE_BINDING_GATE: FAIL (profile_schema_invalid)\n")
    assert closed == [True]
    assert db_path.read_bytes() == db_before
    assert policy_path.read_bytes() == policy_before


def test_hash_only_policy_binding_cannot_skip_row_checks(tmp_path, monkeypatch):
    db_path, policy_path = tmp_path / "synthetic.db", tmp_path / "policy.toml"
    db_before = _database(db_path, row=(PROFILE_ID, 9, 1, json.dumps(PROFILE), 1))
    policy_before = _policy_file(policy_path)
    result = _invoke(monkeypatch, db_path, policy_path)
    assert result == (1, "", "PROFILE_BINDING_GATE: FAIL (discovery_profile_binding_mismatch)\n")
    assert db_path.read_bytes() == db_before
    assert policy_path.read_bytes() == policy_before
