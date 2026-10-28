"""Targeted public-boundary T3b1 lifecycle and provenance regressions."""
from __future__ import annotations

import contextlib
import hashlib
import io
import socket

import pytest
from sqlalchemy.orm import Session

from role_radar.db.engine import get_engine
from role_radar.domain.enums import JobSearchRunStatus
from role_radar.repositories.runs import RunRepository
from scripts import bounded_canary_telegram as telegram
from tests.unit import test_bounded_canary_create as creation_tests
from tests.unit import test_bounded_canary_telegram as telegram_tests


def _invoke(argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = telegram.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def _hashes(db):
    paths = (db, db.with_name(db.name + "-wal"))
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths if path.exists()}


@pytest.fixture(name="tx")
def tx_fixture(tmp_path, monkeypatch):
    held = []
    original = creation_tests._ready_backup

    def capture(*args, **kwargs):
        result = original(*args, **kwargs)
        held.append(result)
        return result

    monkeypatch.setattr(creation_tests, "_ready_backup", capture)
    monkeypatch.setattr(socket.socket, "connect", lambda *_a, **_k: pytest.fail("network"))
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_k: pytest.fail("network"))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        backup_path, env_path, run_id = telegram_tests._transaction_fixture(tmp_path, monkeypatch)
    _recovery, db, writer, _gates = held[0]
    writer.rollback()
    assert db.with_name(db.name + "-wal").is_file()
    yield backup_path, env_path, run_id, db, writer
    writer.close()


def _call(tx, action, expected_code, failure_code=None):
    path, _env, _run_id, db, writer = tx
    before_database = (_hashes(db), writer.total_changes)
    result = _invoke([action, "--backup", str(path)])
    after_database = (_hashes(db), writer.total_changes)
    assert after_database == before_database
    assert result[0] == expected_code
    if expected_code == 0:
        expected_stdout = (
            f"TELEGRAM_PROVIDER: PASS ({'prepared' if action == 'prepare' else 'restored'})\n"
        )
        assert result == (0, expected_stdout, "")
    elif failure_code:
        assert result == (
            1, "", f"TELEGRAM_PROVIDER: FAIL ({failure_code}; recovery={path})\n"
        )
    return result


@pytest.mark.parametrize(
    ("end_state", "retained_lease"),
    [("completed", False), ("failed", False), ("deferred", False),
     ("collecting", True)],
)
def test_restore_after_real_run_lifecycle_keeps_unresolved_lease_untouched(
    tx, end_state, retained_lease
):
    _path, env, run_id, db, _writer = tx
    original = env.read_bytes()
    assert _call(tx, "prepare", 0)[0] == 0
    engine = get_engine(f"sqlite:///{db}")
    with Session(engine) as session:
        repo = RunRepository(session)
        assert repo.claim_run(run_id, worker_id="synthetic-worker") is not None
        repo.update_run_status(run_id, JobSearchRunStatus.COLLECTING)
        session.commit()
    if not retained_lease:
        state = JobSearchRunStatus(end_state)
        with Session(engine) as session:
            repo = RunRepository(session)
            repo.update_run_status(run_id, state)
            assert repo.release(run_id, worker_id="synthetic-worker")
            session.commit()
    engine.dispose()
    before = _hashes(db)
    assert _call(tx, "restore", 0)[0] == 0
    assert env.read_bytes() == original
    assert _hashes(db) == before
    if retained_lease:
        connection = creation_tests.backup.database._connect_database(f"sqlite:///{db}")
        try:
            row = connection.execute(
                "SELECT status, claimed_by, lease_expires_at FROM job_search_runs WHERE id=?",
                (run_id,),
            ).fetchone()
            assert row[0] == "collecting" and row[1] == "synthetic-worker"
            assert row[2] is not None
        finally:
            connection.close()


def test_restore_does_not_run_prestart_isolation_gate(tx, monkeypatch):
    _path, env, _run_id, _db, _writer = tx
    original = env.read_bytes()
    assert _call(tx, "prepare", 0)[0] == 0
    monkeypatch.setattr(
        telegram.backup.preflight, "run_gate",
        lambda *_a, **_k: pytest.fail("restore invoked pre-start isolation gate"),
    )
    assert _call(tx, "restore", 0)[0] == 0
    assert env.read_bytes() == original


@pytest.mark.parametrize("phase", ["before-intent", "after-intent"])
@pytest.mark.parametrize("source", ["database", "policy"])
def test_original_database_and_policy_identity_drift_rejects_prepare(
    tx, monkeypatch, phase, source
):
    path, env, _run_id, db, _writer = tx
    original_env, original_hashes = env.read_bytes(), _hashes(db)
    active = [False]
    if source == "database":
        capture = telegram.backup._capture_database_target

        def drift_database(url):
            target = capture(url)
            if active[0]:
                identity = list(target["identity"])
                identity[1] += 1
                target["identity"] = tuple(identity)
            return target

        monkeypatch.setattr(telegram.backup, "_capture_database_target", drift_database)
        expected = "source_database_changed"
    else:
        def drift_policy():
            policy = telegram.backup.POLICY_PATH
            original = policy.read_bytes()
            changed = original.replace(b"gate-a-v1", b"gate-a-v2")
            assert changed != original
            policy.write_bytes(changed)
            assert telegram.backup.binding._load_policy(str(policy)).raw_bytes == changed

        expected = "source_config_changed"
    if phase == "before-intent":
        active[0] = True
        if source == "policy":
            drift_policy()
    else:
        write_receipt = telegram._write_receipt

        def write_then_drift(fd, name, *args, **kwargs):
            result = write_receipt(fd, name, *args, **kwargs)
            if name == telegram.RECEIPT_NAME:
                active[0] = True
                if source == "policy":
                    drift_policy()
            return result

        monkeypatch.setattr(telegram, "_write_receipt", write_then_drift)
    assert _call(tx, "prepare", 1, expected)[0] == 1
    assert env.read_bytes() == original_env
    assert _hashes(db) == original_hashes
    assert not (path / telegram.OUTCOME_NAME).exists()
    assert (path / telegram.RECEIPT_NAME).exists() is (phase == "after-intent")


@pytest.mark.parametrize("drift", ["directory-identity", "history-mode"])
def test_creation_evidence_remains_anchored_after_provider_intent(tx, monkeypatch, drift):
    path, env, _run_id, db, _writer = tx
    original_env, original_hashes = env.read_bytes(), _hashes(db)
    if drift == "directory-identity":
        validate = telegram._validate_creation
        calls = [0]

        def rebound(candidate):
            evidence = validate(candidate)
            calls[0] += 1
            if calls[0] == 2:
                identity = list(evidence["backup_identity"])
                identity[1] += 1
                evidence["backup_identity"] = tuple(identity)
            return evidence

        monkeypatch.setattr(telegram, "_validate_creation", rebound)
        expected = "provider_evidence_changed"
    else:
        write_receipt = telegram._write_receipt

        def chmod_after_intent(fd, name, *args, **kwargs):
            result = write_receipt(fd, name, *args, **kwargs)
            if name == telegram.RECEIPT_NAME:
                (path / "history.json").chmod(0o644)
            return result

        monkeypatch.setattr(telegram, "_write_receipt", chmod_after_intent)
        expected = "creation_evidence_invalid"
    assert _call(tx, "prepare", 1, expected)[0] == 1
    assert env.read_bytes() == original_env
    assert _hashes(db) == original_hashes
    assert not (path / telegram.OUTCOME_NAME).exists()
    assert (path / telegram.RECEIPT_NAME).exists()
