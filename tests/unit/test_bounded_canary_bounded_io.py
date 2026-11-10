from __future__ import annotations

import os
import sys
import time

import pytest

from scripts.bounded_canary_bounded_io import (
    MAX_RESULT_BYTES,
    BoundedIOError,
    call_bounded,
)

_SECRET = "bounded-private-child-output-9e2f"


def _small_result():
    return {"ok": True, "items": [1, "two", None]}


def _raise_after_private_output():
    print(_SECRET, flush=True)
    print(_SECRET, file=sys.stderr, flush=True)
    raise RuntimeError("private exception detail")


def _block():
    time.sleep(30.0)
    return {"unreachable": True}


def _large_result():
    return "x" * MAX_RESULT_BYTES


def _report_process_group():
    return {"pid": os.getpid(), "pgid": os.getpgrp()}


def _exit_with_pipe_descendant():
    """Exit without a frame while a real descendant retains the write end."""
    child = os.fork()
    if child == 0:
        time.sleep(30.0)
        os._exit(0)
    os._exit(0)


def test_returns_only_small_json_result_from_real_fork_child():
    result = call_bounded(_small_result, deadline=time.monotonic() + 2.0)
    assert result == {"ok": True, "items": [1, "two", None]}


def test_exception_is_sanitized_and_child_stdout_stderr_do_not_leak(capsys):
    with pytest.raises(BoundedIOError) as error:
        call_bounded(_raise_after_private_output, deadline=time.monotonic() + 2.0)
    assert error.value.code == "child_exception"
    captured = capsys.readouterr()
    assert _SECRET not in captured.out
    assert _SECRET not in captured.err
    assert "private exception detail" not in str(error.value)


def test_large_json_result_is_rejected_at_bounded_wire_limit():
    with pytest.raises(BoundedIOError) as error:
        call_bounded(_large_result, deadline=time.monotonic() + 2.0)
    assert error.value.code == "output_too_large"


def test_blocking_child_uses_wall_clock_deadline_and_is_reaped_boundedly():
    started = time.monotonic()
    with pytest.raises(BoundedIOError) as error:
        call_bounded(_block, deadline=started + 0.12)
    elapsed = time.monotonic() - started
    assert error.value.code == "timeout"
    # Includes the bounded cleanup grace, but not the callable's 30-second sleep.
    assert elapsed < 1.5


def test_child_runs_in_a_new_process_group():
    result = call_bounded(_report_process_group, deadline=time.monotonic() + 2.0)
    assert result["pid"] == result["pgid"]


def test_partial_channel_with_pipe_retaining_descendant_does_not_wait_for_eof():
    started = time.monotonic()
    with pytest.raises(BoundedIOError) as error:
        call_bounded(_exit_with_pipe_descendant, deadline=started + 2.0)
    elapsed = time.monotonic() - started
    assert error.value.code == "channel_incomplete"
    assert elapsed < 1.5


def test_expired_absolute_deadline_is_rejected_before_fork():
    with pytest.raises(BoundedIOError) as error:
        call_bounded(_small_result, deadline=time.monotonic() - 0.001)
    assert error.value.code == "deadline_expired"
