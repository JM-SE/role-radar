"""CLI execution-fence coverage with explicit guard doubles."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import pytest

import role_radar.cli.main as cli
from role_radar.fence_runtime import FenceError


@contextmanager
def _contention() -> Any:
    raise FenceError()
    yield


def test_fence_contention_skips_early_command_effect(capsys, monkeypatch) -> None:
    effect = pytest.fail
    monkeypatch.setattr(cli, "producer_guard", _contention)
    monkeypatch.setattr(cli, "_run_legacy_discovery_deprecated", effect)

    result = cli.main(["continuous-discovery", "run"])

    assert result == 1
    assert capsys.readouterr().err == "execution_fence_unavailable\n"


def test_producer_guard_is_held_for_full_execution(monkeypatch) -> None:
    held = False
    calls: list[tuple[object, bool]] = []

    @contextmanager
    def producer() -> Any:
        nonlocal held
        held = True
        try:
            yield
        finally:
            held = False

    class Settings:
        pass

    def effect(_settings: object, _fixtures: object) -> int:
        calls.append((_settings, held))
        return 7

    monkeypatch.setattr(cli, "producer_guard", producer)
    monkeypatch.setattr(cli, "Settings", Settings)
    monkeypatch.setattr(cli, "_seed_boards", effect)

    assert cli.main(["seed-boards"]) == 7
    assert len(calls) == 1
    assert calls[0][1] is True
    assert held is False


def test_worker_guard_receives_none_and_is_held_for_worker(monkeypatch) -> None:
    held = False
    guard_run_ids: list[object] = []
    worker_calls: list[tuple[object, object, bool]] = []

    @contextmanager
    def worker(run_id: object) -> Any:
        nonlocal held
        guard_run_ids.append(run_id)
        held = True
        try:
            yield
        finally:
            held = False

    class Settings:
        pass

    monkeypatch.setattr(cli, "worker_guard", worker)
    monkeypatch.setattr(cli, "Settings", Settings)

    import role_radar.worker.main as worker_module

    def run_worker(settings: object, *, run_id: object) -> None:
        worker_calls.append((settings, run_id, held))

    monkeypatch.setattr(worker_module, "run_worker", run_worker)

    assert cli.main(["worker"]) == 0
    assert guard_run_ids == [None]
    assert len(worker_calls) == 1
    assert worker_calls[0][1:] == (None, True)
    assert held is False


def test_parser_help_does_not_acquire_guard(monkeypatch) -> None:
    def fail_guard() -> Any:
        pytest.fail("--help must terminate before acquiring the execution fence")

    monkeypatch.setattr(cli, "producer_guard", fail_guard)

    with pytest.raises(SystemExit) as result:
        cli.main(["--help"])

    assert result.value.code == 0
