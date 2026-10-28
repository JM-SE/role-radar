from __future__ import annotations

import builtins
import hashlib
import json
import os
import stat

import pytest

from scripts import bounded_canary_telegram as telegram


def test_prepare_provider_bytes_changes_only_canonical_assignment_and_preserves_bytes(
    monkeypatch, capsys
):
    original = (
        b"# private marker: SECRET-DO-NOT-PRINT\r\n"
        b"TOKEN=literal42\r\n"
        b"COUNT=42\r\n"
        b"COMMAND=printf\r\n"
        b"ROLE_RADAR_TELEGRAM_PROVIDER=  disabled  \r\n"
        b"CHAT_ID=0007"
    )
    before = original[:]

    def forbidden(*_args, **_kwargs):
        raise AssertionError("pure byte validation attempted I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    transformed = telegram.prepare_telegram_provider_bytes(original)

    assert transformed == (
        b"# private marker: SECRET-DO-NOT-PRINT\r\n"
        b"TOKEN=literal42\r\n"
        b"COUNT=42\r\n"
        b"COMMAND=printf\r\n"
        b"ROLE_RADAR_TELEGRAM_PROVIDER=  http  \r\n"
        b"CHAT_ID=0007"
    )
    assert type(transformed) is bytes
    assert original == before
    assert transformed.count(b"ROLE_RADAR_TELEGRAM_PROVIDER=") == 1
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert b"SECRET-DO-NOT-PRINT" not in captured.out.encode() + captured.err.encode()


@pytest.mark.parametrize(
    "original",
    [
        b"TOKEN=literal\n",
        b"ROLE_RADAR_TELEGRAM_PROVIDER=disabled\nROLE_RADAR_TELEGRAM_PROVIDER=disabled\n",
        b"ROLE_RADAR_TELEGRAM_PROVIDER=fake\n",
        b"ROLE_RADAR_TELEGRAM_PROVIDER=http\n",
        b"ROLE_RADAR_TELEGRAM_PROVIDER=other\n",
        b"role_radar_telegram_provider=disabled\nROLE_RADAR_TELEGRAM_PROVIDER=disabled\n",
        b"export ROLE_RADAR_TELEGRAM_PROVIDER=disabled\n",
        b"ROLE_RADAR_TELEGRAM_PROVIDER=$(command)\n",
        b"TOKEN=\"unterminated\nROLE_RADAR_TELEGRAM_PROVIDER=disabled\n",
        b"TOKEN=continued\\\nROLE_RADAR_TELEGRAM_PROVIDER=disabled\n",
        b"TOKEN=escaped\\ value\nROLE_RADAR_TELEGRAM_PROVIDER=disabled\n",
        b"TOKEN=\"multi\nline\"\nROLE_RADAR_TELEGRAM_PROVIDER=disabled\n",
        b"not an assignment\nROLE_RADAR_TELEGRAM_PROVIDER=disabled\n",
        b"ROLE_RADAR_TELEGRAM_PROVIDER =disabled\n",
        b"ROLE_RADAR_TELEGRAM_PROVIDER=disabled\rvalue\n",
        b"ROLE_RADAR_TELEGRAM_PROVIDER=disabled\r",
        b"ROLE_RADAR_TELEGRAM_PROVIDER=disabled\n# comment\r",
    ],
)
def test_prepare_provider_bytes_rejects_unsupported_or_ambiguous_input(original, capsys):
    with pytest.raises(telegram.ProviderBytesError) as error:
        telegram.prepare_telegram_provider_bytes(original)
    assert error.value.code == "provider_config_invalid"
    assert str(error.value) == "provider_config_invalid"
    assert "SECRET" not in str(error.value)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""])
def test_prepare_provider_bytes_preserves_provider_line_ending(ending):
    original = b"ROLE_RADAR_TELEGRAM_PROVIDER=disabled" + ending
    assert telegram.prepare_telegram_provider_bytes(original) == (
        b"ROLE_RADAR_TELEGRAM_PROVIDER=http" + ending
    )


@pytest.mark.parametrize("value", [None, "ROLE_RADAR_TELEGRAM_PROVIDER=disabled", bytearray()])
def test_prepare_provider_bytes_rejects_non_bytes_without_repr(value, capsys):
    with pytest.raises(telegram.ProviderBytesError) as error:
        telegram.prepare_telegram_provider_bytes(value)
    assert error.value.code == "provider_config_invalid"
    assert str(error.value) == "provider_config_invalid"
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_prepare_transaction_requires_live_pending_creation_and_writes_protected_atomic_file(
    tmp_path, monkeypatch, capsys
):
    backup_path, env_path, run_id = _transaction_fixture(tmp_path, monkeypatch)
    capsys.readouterr()
    before = env_path.read_bytes()
    assert telegram.main(["prepare", "--backup", str(backup_path)]) == 0
    result = capsys.readouterr()
    assert result.out == "TELEGRAM_PROVIDER: PASS (prepared)\n"
    assert result.err == ""
    changed = env_path.read_bytes()
    assert changed == before.replace(
        b"ROLE_RADAR_TELEGRAM_PROVIDER=disabled", b"ROLE_RADAR_TELEGRAM_PROVIDER=http"
    )
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    receipt = json.loads((backup_path / telegram.RECEIPT_NAME).read_text())
    assert set(receipt) == {
        "schema_version", "state", "run_id", "profile_id", "backup",
        "backup_identity", "original_identity", "prepared_identity",
        "original_sha256", "prepared_sha256", "source_proof_sha256",
    }
    assert receipt["schema_version"] == 1 and receipt["state"] == "prepared"
    assert receipt["run_id"] == run_id and receipt["backup"] == str(backup_path)
    assert receipt["original_sha256"] == hashlib.sha256(before).hexdigest()
    assert receipt["prepared_sha256"] == hashlib.sha256(changed).hexdigest()
    assert all(type(value) is int for value in receipt["original_identity"])
    assert all(type(value) is int for value in receipt["prepared_identity"])
    assert stat.S_IMODE((backup_path / telegram.RECEIPT_NAME).stat().st_mode) == 0o600
    assert telegram.main(["prepare", "--backup", str(backup_path)]) == 1
    failure = capsys.readouterr()
    assert failure.out == ""
    assert failure.err == f"TELEGRAM_PROVIDER: FAIL (transaction_exists; recovery={backup_path})\n"
    assert env_path.read_bytes() == changed


def test_stage_is_protected_before_any_payload_write_and_transaction_fds_close(
    tmp_path, monkeypatch, capsys
):
    backup_path, env_path, _run_id = _transaction_fixture(tmp_path, monkeypatch)
    capsys.readouterr()
    opened_stage = []
    written = []
    original_open = os.open
    original_write = os.write
    original_chain = telegram.backup._open_chain
    descriptors = []

    def track_chain(*args, **kwargs):
        fds, identities = original_chain(*args, **kwargs)
        descriptors.extend(fds)
        return fds, identities

    def track_open(name, flags, *args, **kwargs):
        fd = original_open(name, flags, *args, **kwargs)
        if type(name) is str and name.startswith(".role-radar-provider-"):
            opened_stage.append(fd)
        return fd

    def check_write(fd, data):
        if fd in opened_stage:
            info = os.fstat(fd)
            assert stat.S_IMODE(info.st_mode) == 0o600
            assert info.st_nlink == 1 and info.st_size == 0
            assert info.st_uid == os.getuid()
            written.append(bytes(data))
        return original_write(fd, data)

    monkeypatch.setattr(telegram.backup, "_open_chain", track_chain)
    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "write", check_write)
    original = env_path.read_bytes()
    assert telegram.main(["prepare", "--backup", str(backup_path)]) == 0
    capsys.readouterr()
    assert opened_stage and written
    assert all(_fd_is_closed(fd) for fd in opened_stage)
    assert b"".join(written) == original.replace(
        b"ROLE_RADAR_TELEGRAM_PROVIDER=disabled", b"ROLE_RADAR_TELEGRAM_PROVIDER=http"
    )
    assert descriptors and all(_fd_is_closed(fd) for fd in descriptors)


def _fd_is_closed(fd):
    try:
        os.fstat(fd)
        return False
    except OSError:
        return True


def test_prepare_transaction_rejection_leaves_configuration_and_attempt_counters_unchanged(
    tmp_path, monkeypatch, capsys
):
    backup_path, env_path, _run_id = _transaction_fixture(tmp_path, monkeypatch)
    capsys.readouterr()
    original = env_path.read_bytes()
    monkeypatch.setattr(
        telegram.backup.preflight, "run_gate",
        lambda *_a, **_k: (_ for _ in ()).throw(telegram.ProviderError("gate_unavailable")),
    )
    assert telegram.main(["prepare", "--backup", str(backup_path)]) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == f"TELEGRAM_PROVIDER: FAIL (gate_unavailable; recovery={backup_path})\n"
    assert env_path.read_bytes() == original
    assert not (backup_path / telegram.RECEIPT_NAME).exists()
    assert not list(env_path.parent.glob(".role-radar-provider-*"))


def test_restore_successfully_restores_only_the_bound_prepared_bytes(tmp_path, monkeypatch, capsys):
    backup_path, env_path, _run_id = _transaction_fixture(tmp_path, monkeypatch)
    original = env_path.read_bytes()
    capsys.readouterr()
    assert telegram.main(["prepare", "--backup", str(backup_path)]) == 0
    capsys.readouterr()
    assert env_path.read_bytes() != original
    assert telegram.main(["restore", "--backup", str(backup_path)]) == 0
    result = capsys.readouterr()
    assert result.out == "TELEGRAM_PROVIDER: PASS (restored)\n"
    assert result.err == ""
    assert env_path.read_bytes() == original
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    outcome = json.loads((backup_path / telegram.RESTORE_OUTCOME_NAME).read_text())
    assert outcome["state"] == "restored" and outcome["run_id"]
    assert stat.S_IMODE((backup_path / telegram.RESTORE_OUTCOME_NAME).stat().st_mode) == 0o600
    assert telegram.main(["restore", "--backup", str(backup_path)]) == 1
    failed = capsys.readouterr()
    assert failed.out == ""
    assert failed.err == f"TELEGRAM_PROVIDER: FAIL (transaction_exists; recovery={backup_path})\n"
    assert env_path.read_bytes() == original


def test_intent_persists_and_config_drift_after_intent_is_never_retried(
    tmp_path, monkeypatch, capsys
):
    backup_path, env_path, _run_id = _transaction_fixture(tmp_path, monkeypatch)
    capsys.readouterr()
    original = env_path.read_bytes()
    real_write = telegram._write_receipt
    changed = original + b"HUMAN=preserved\n"

    def write_then_drift(child_fd, name, record, *args):
        result = real_write(child_fd, name, record, *args)
        if name == telegram.RECEIPT_NAME:
            env_path.write_bytes(changed)
        return result

    monkeypatch.setattr(telegram, "_write_receipt", write_then_drift)
    assert telegram.main(["prepare", "--backup", str(backup_path)]) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == (
        f"TELEGRAM_PROVIDER: FAIL (provider_config_changed; recovery={backup_path})\n"
    )
    assert env_path.read_bytes() == changed
    assert (backup_path / telegram.RECEIPT_NAME).is_file()
    assert not (backup_path / telegram.OUTCOME_NAME).exists()
    assert telegram.main(["prepare", "--backup", str(backup_path)]) == 1
    retry = capsys.readouterr()
    assert retry.out == ""
    assert retry.err == f"TELEGRAM_PROVIDER: FAIL (transaction_exists; recovery={backup_path})\n"
    assert env_path.read_bytes() == changed


def test_restore_is_conditional_and_preserves_later_human_change(tmp_path, monkeypatch, capsys):
    backup_path, env_path, _run_id = _transaction_fixture(tmp_path, monkeypatch)
    assert telegram.main(["prepare", "--backup", str(backup_path)]) == 0
    capsys.readouterr()
    prepared = env_path.read_bytes()
    human = prepared + b"OPERATOR_NOTE=kept\n"
    env_path.write_bytes(human)
    assert telegram.main(["restore", "--backup", str(backup_path)]) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == (
        f"TELEGRAM_PROVIDER: FAIL (provider_config_changed; recovery={backup_path})\n"
    )
    assert env_path.read_bytes() == human


def _transaction_fixture(tmp_path, monkeypatch):
    from tests.unit import test_bounded_canary_create as creation_tests

    backup_path, _db, writer, _gates = creation_tests._ready_backup(
        tmp_path, monkeypatch, compose_t1_gates=True
    )
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    run_id = "00000000-0000-4000-8000-000000000099"
    from scripts import bounded_canary_backup as backup_module
    from scripts import bounded_canary_create as create_module
    env_path = backup_module.ENV_PATH
    env_path.write_bytes(b"TOKEN=private\nROLE_RADAR_TELEGRAM_PROVIDER=disabled\n")
    env_path.chmod(0o600)
    proof_path = backup_path / "source-proof.json"
    proof = json.loads(proof_path.read_text())
    env_copy = backup_path / "role-radar.env"
    env_copy.write_bytes(env_path.read_bytes())
    env_data, env_identity, env_chain = backup_module._fixed_file(
        env_path, mode=0o600, gid=0
    )
    env_digest = hashlib.sha256(env_data).hexdigest()
    proof["source"]["environment"].update(
        identity=list(env_identity), parent_identities=[list(x) for x in env_chain],
        sha256=env_digest,
    )
    proof["backup"]["environment_sha256"] = env_digest
    proof_path.write_text(json.dumps(proof, sort_keys=True) + "\n")
    from tests.unit.test_bounded_canary_create import binding_tests
    creation_tests._simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, [])
    assert create_module.main(["--backup", str(backup_path)]) == 0
    run_id = json.loads((backup_path / "creation-outcome.json").read_text())["run_id"]
    # Hold an uncommitted synthetic WAL frame so the gate sees existing sidecars.
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("UPDATE alembic_version SET version_num=version_num")
    return backup_path, env_path, run_id
