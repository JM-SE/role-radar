from __future__ import annotations

import contextlib
import io
import json
import multiprocessing
import os
import sqlite3

import pytest

from scripts import bounded_canary_supervision as supervision
from tests.unit import test_bounded_canary_binding as binding_tests
from tests.unit import test_bounded_canary_create as create_tests


def _created(tmp_path, monkeypatch):
    recovery, db, writer, _gates = create_tests._ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(create_tests.adapter.os, "geteuid", lambda: 0)
    create_tests._simulate_runuser(
        monkeypatch, binding_tests.PROFILE_ID, [], no_notifications=True
    )
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert create_tests.adapter.main(["--backup", str(recovery), "--no-notifications"]) == 0
    return recovery, db, writer


def _snapshot(db):
    connection = create_tests.backup.database._connect_database(f"sqlite:///{db}")
    try:
        return create_tests.backup.database.snapshot_history(connection)
    finally:
        connection.close()


def test_admission_creates_durable_none_mode_intent_and_retains_context(tmp_path, monkeypatch):
    recovery, db, writer = _created(tmp_path, monkeypatch)
    before = _snapshot(db)
    changes = writer.total_changes
    with supervision.admit(recovery) as permission:
        assert permission.revalidate() is permission
        record = json.loads((recovery / supervision.INTENT_NAME).read_bytes())
        assert record == {
            "schema_version": 1, "state": "attempted", "backup": str(recovery),
            "backup_identity": list(permission.evidence["backup_identity"]),
            "creation_evidence_sha256": supervision.hashlib.sha256(json.dumps(
                permission.evidence["artifact_digests"], sort_keys=True,
                separators=(",", ":"),
            ).encode()).hexdigest(),
            "run_id": permission.evidence["run_id"],
            "profile_id": binding_tests.PROFILE_ID, "notification_mode": "none",
        }
        assert permission.evidence["child_fd"] >= 0
        assert (recovery / supervision.INTENT_NAME).stat().st_mode & 0o777 == 0o600
    assert permission.closed
    assert _snapshot(db) == before
    assert writer.total_changes == changes
    writer.close()


def test_duplicate_any_receipt_state_is_consumed_without_side_effects(tmp_path, monkeypatch):
    recovery, db, writer = _created(tmp_path, monkeypatch)
    for name, data in ((supervision.INTENT_NAME, b"malformed"),
                       (supervision.OUTCOME_NAME, b"uncertain")):
        target = recovery / name
        target.write_bytes(data)
        target.chmod(0o600)
        before = _snapshot(db)
        changes = writer.total_changes
        with pytest.raises(supervision.SupervisionError) as error:
            supervision.admit(recovery)
        assert error.value.code == "supervision_intent_exists"
        assert target.read_bytes() == data
        assert _snapshot(db) == before and writer.total_changes == changes
    writer.close()


def test_live_run_mode_or_state_mismatch_is_rejected_without_intent(tmp_path, monkeypatch):
    recovery, db, writer = _created(tmp_path, monkeypatch)
    connection = sqlite3.connect(db)
    run_id = json.loads((recovery / "creation-outcome.json").read_bytes())["run_id"]
    connection.execute("UPDATE job_search_runs SET notification_mode='match_alerts' WHERE id=?",
                       (run_id,))
    connection.commit()
    before = _snapshot(db)
    changes = writer.total_changes
    with pytest.raises(supervision.SupervisionError) as error:
        supervision.admit(recovery)
    assert error.value.code == "supervision_run_invalid"
    assert not (recovery / supervision.INTENT_NAME).exists()
    assert _snapshot(db) == before and writer.total_changes == changes
    connection.close()
    writer.close()


def test_receipt_reader_accepts_only_exact_new_slots_and_metadata(tmp_path, monkeypatch):
    recovery, _db, writer = _created(tmp_path, monkeypatch)
    monkeypatch.setattr(create_tests.adapter.os, "geteuid", lambda: 0)
    # Reader behavior is checked through its public evidence context.
    # Build valid receipts using the admission's bound evidence.
    permission = supervision.admit(recovery)
    e = permission.evidence
    intent = {"schema_version": 1, "state": "attempted", "backup": str(recovery),
              "backup_identity": list(e["backup_identity"]),
              "creation_evidence_sha256": supervision.hashlib.sha256(json.dumps(
                  e["artifact_digests"], sort_keys=True, separators=(",", ":")
              ).encode()).hexdigest(),
              "run_id": e["run_id"], "profile_id": e["profile_id"],
              "notification_mode": "none"}
    permission.close()
    (recovery / supervision.INTENT_NAME).write_text(json.dumps(intent, sort_keys=True) + "\n")
    (recovery / supervision.INTENT_NAME).chmod(0o600)
    with create_tests.adapter._open_creation_evidence(recovery) as evidence:
        assert evidence["run_id"] == intent["run_id"]
    intent["extra"] = "rejected"
    (recovery / supervision.INTENT_NAME).write_text(json.dumps(intent) + "\n")
    with pytest.raises(create_tests.adapter.CreationError), \
            create_tests.adapter._open_creation_evidence(recovery):
        pytest.fail("unknown supervision metadata was accepted")
    writer.close()


def test_backup_metadata_drift_before_admission_rejects_without_intent(tmp_path, monkeypatch):
    recovery, _db, writer = _created(tmp_path, monkeypatch)
    (recovery / "history.json").chmod(0o640)
    with pytest.raises(supervision.SupervisionError) as error:
        supervision.admit(recovery)
    assert error.value.code == "creation_evidence_invalid"
    assert not (recovery / supervision.INTENT_NAME).exists()
    writer.close()


def test_anchor_drift_during_exclusive_write_is_uncertain_and_never_permission(
    tmp_path, monkeypatch
):
    recovery, _db, writer = _created(tmp_path, monkeypatch)
    original = supervision.artifacts.write_new_at
    def drift(*args, **kwargs):
        result = original(*args, **kwargs)
        os.chmod(recovery, 0o701)
        return result
    monkeypatch.setattr(supervision.artifacts, "write_new_at", drift)
    with pytest.raises(supervision.SupervisionError) as error:
        supervision.admit(recovery)
    assert error.value.code == "supervision_admission_uncertain"
    assert (recovery / supervision.INTENT_NAME).is_file()
    writer.close()


def test_sync_failure_is_uncertain_and_never_returns_dispatch_permission(
    tmp_path, monkeypatch
):
    recovery, db, writer = _created(tmp_path, monkeypatch)
    before = _snapshot(db)
    changes = writer.total_changes
    monkeypatch.setattr(supervision.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError()))
    with pytest.raises(supervision.SupervisionError) as error:
        supervision.admit(recovery)
    assert error.value.code == "supervision_admission_uncertain"
    assert (recovery / supervision.INTENT_NAME).exists()
    assert _snapshot(db) == before and writer.total_changes == changes
    writer.close()


@pytest.mark.parametrize("when", ["before_admission", "before_dispatch"])
def test_changed_live_policy_never_grants_dispatch_permission(tmp_path, monkeypatch, when):
    recovery, _db, writer = _created(tmp_path, monkeypatch)
    policy = create_tests.backup.POLICY_PATH
    if when == "before_admission":
        policy.write_bytes(policy.read_bytes() + b"\n# changed\n")
        with pytest.raises(supervision.SupervisionError):
            supervision.admit(recovery)
        assert not (recovery / supervision.INTENT_NAME).exists()
    else:
        with supervision.admit(recovery) as permission:
            policy.write_bytes(policy.read_bytes() + b"\n# changed\n")
            with pytest.raises(supervision.SupervisionError):
                permission.revalidate()
    writer.close()


@pytest.mark.parametrize("intent_state", ["missing", "wrong_digest", "matching"])
def test_outcome_requires_matching_persisted_intent(tmp_path, monkeypatch, intent_state):
    recovery, _db, writer = _created(tmp_path, monkeypatch)
    with supervision.admit(recovery):
        intent_bytes = (recovery / supervision.INTENT_NAME).read_bytes()
    intent = json.loads(intent_bytes)
    outcome = {**intent, "state": "completed", "result": {"state": "completed"},
               "intent_sha256": supervision.hashlib.sha256(intent_bytes).hexdigest()}
    if intent_state == "missing":
        (recovery / supervision.INTENT_NAME).unlink()
    elif intent_state == "wrong_digest":
        outcome["intent_sha256"] = "0" * 64
    target = recovery / supervision.OUTCOME_NAME
    target.write_text(json.dumps(outcome, sort_keys=True) + "\n")
    target.chmod(0o600)
    if intent_state == "matching":
        with create_tests.adapter._open_creation_evidence(recovery) as evidence:
            assert evidence["run_id"] == intent["run_id"]
    else:
        with pytest.raises(create_tests.adapter.CreationError), \
                create_tests.adapter._open_creation_evidence(recovery):
            pytest.fail("unbound outcome accepted")
    writer.close()


@pytest.mark.parametrize("when", ["before_write", "after_write"])
def test_outcome_never_reports_success_if_intent_changed(tmp_path, monkeypatch, when):
    recovery, _db, writer = _created(tmp_path, monkeypatch)
    with supervision.admit(recovery) as permission:
        record = supervision._outcome(permission.evidence, permission.intent_digest, "completed")
        intent = recovery / supervision.INTENT_NAME
        if when == "before_write":
            intent.write_bytes(b"changed")
        else:
            original = supervision.artifacts.write_new_at
            def tamper(*args, **kwargs):
                identity = original(*args, **kwargs)
                intent.write_bytes(b"changed")
                return identity
            monkeypatch.setattr(supervision.artifacts, "write_new_at", tamper)
        with pytest.raises(supervision.SupervisionError) as error:
            permission._write_outcome(record)
        assert error.value.code == "supervision_outcome_uncertain"
        if when == "before_write":
            assert not (recovery / supervision.OUTCOME_NAME).exists()
    writer.close()


@pytest.mark.parametrize("changed,when", [
    ("source", "before_admission"),
    ("source", "before_dispatch"),
    ("profile", "before_dispatch"),
])
def test_changed_database_inputs_never_grant_dispatch_permission(
    tmp_path, monkeypatch, changed, when
):
    recovery, db, writer = _created(tmp_path, monkeypatch)
    from sqlalchemy.orm import Session

    from role_radar.db.engine import get_engine
    from role_radar.db.models import Source
    from role_radar.domain.enums import SourceType

    def mutate():
        engine = get_engine(f"sqlite:///{db}")
        with Session(engine) as session:
            if changed == "source":
                session.add(Source(type=SourceType.GREENHOUSE, name="synthetic",
                                   source_key="synthetic", enabled=True))
            else:
                session.execute(create_tests.text(
                    "UPDATE candidate_profiles SET name='changed' WHERE id=:id"
                ), {"id": binding_tests.PROFILE_ID})
            session.commit()
        engine.dispose()

    if when == "before_admission":
        mutate()
        with pytest.raises(supervision.SupervisionError):
            supervision.admit(recovery)
        assert not (recovery / supervision.INTENT_NAME).exists()
    else:
        with supervision.admit(recovery) as permission:
            mutate()
            with pytest.raises(supervision.SupervisionError):
                permission.revalidate()
    writer.close()


def test_concurrent_admissions_grant_at_most_one_permission(tmp_path, monkeypatch):
    recovery, _db, writer = _created(tmp_path, monkeypatch)
    ctx = multiprocessing.get_context("fork")
    barrier = ctx.Barrier(2)
    results = ctx.Queue()
    original = supervision.artifacts.write_new_at

    def synchronized_write(*args, **kwargs):
        barrier.wait(timeout=10)
        return original(*args, **kwargs)

    def attempt():
        try:
            with supervision.admit(recovery):
                results.put("admitted")
        except supervision.SupervisionError:
            results.put("rejected")

    monkeypatch.setattr(supervision.artifacts, "write_new_at", synchronized_write)
    processes = [ctx.Process(target=attempt) for _ in range(2)]
    for process in processes:
        process.start()
    try:
        for process in processes:
            process.join(timeout=20)
        assert all(not process.is_alive() and process.exitcode == 0 for process in processes)
        assert sorted(results.get(timeout=2) for _ in processes) == ["admitted", "rejected"]
        assert (recovery / supervision.INTENT_NAME).stat().st_mode & 0o777 == 0o600
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()
        results.close()
        writer.close()


def test_admission_closes_retained_descriptors(tmp_path, monkeypatch):
    recovery, _db, writer = _created(tmp_path, monkeypatch)
    with supervision.admit(recovery) as permission:
        descriptors = [*permission.evidence["root_fds"], permission.evidence["child_fd"]]
        permission.revalidate()
        for fd in descriptors:
            os.fstat(fd)
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
    writer.close()
