"""Targeted initial-run metadata and repeat-guard T3b1 regressions."""
from __future__ import annotations

import contextlib
import io
import json

import pytest

from scripts import bounded_canary_telegram as telegram
from tests.unit import test_bounded_canary_create as creation_tests
from tests.unit.test_t3b1_independent import _call, tx_fixture  # noqa: F401


@pytest.mark.parametrize("field", ["checkpoint-counts", "notification-mode", "discovery-mode"])
def test_prepare_rejects_consumed_or_noncanary_initial_run_metadata(tx, field):
    path, env, run_id, _db, writer = tx
    if field == "checkpoint-counts":
        row = writer.execute(
            "SELECT canary_checkpoint_json FROM job_search_runs WHERE id=?", (run_id,)
        ).fetchone()
        checkpoint = json.loads(row[0])
        checkpoint["counts"] = {"notification_batches": 1}
        writer.execute(
            "UPDATE job_search_runs SET canary_checkpoint_json=? WHERE id=?",
            (json.dumps(checkpoint), run_id),
        )
    else:
        column = "notification_mode" if field == "notification-mode" else "discovery_mode"
        writer.execute(f"UPDATE job_search_runs SET {column}='none' WHERE id=?", (run_id,))
    writer.commit()
    original = env.read_bytes()
    assert _call(tx, "prepare", 1, "run_state_invalid")[0] == 1
    assert env.read_bytes() == original
    assert not (path / telegram.RECEIPT_NAME).exists()


def test_creation_replay_stays_rejected_after_provider_restore(tx):
    path, env, _run_id, _db, _writer = tx
    assert _call(tx, "prepare", 0)[0] == 0
    assert _call(tx, "restore", 0)[0] == 0
    before = env.read_bytes()
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = creation_tests.adapter.main(["--backup", str(path)])
    assert (result, stdout.getvalue(), stderr.getvalue()) == (
        1, "", f"CANARY_CREATION: FAIL (creation_attempt_exists; recovery={path})\n"
    )
    assert env.read_bytes() == before
