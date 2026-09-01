"""Offline Gate C authorization and pre-effect boundary checks."""

from __future__ import annotations

from argparse import Namespace

import pytest

from role_radar.cli import evaluation_f10_1f
from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
    GateCAuthorizationError,
    parse_gate_c_authorization,
)


def test_gate_c_authorization_parser_forbids_unknown_fields() -> None:
    with pytest.raises(GateCAuthorizationError) as error:
        parse_gate_c_authorization({"schema_version": "wrong", "unexpected": True})
    assert error.value.code == "authorization_fields_invalid"


def test_gate_c_cli_missing_authorization_is_block_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert evaluation_f10_1f.run(Namespace(f10_1f_command="run-report-only")) == 2
    assert '"code":"gate_c_authorization_required"' in capsys.readouterr().out
