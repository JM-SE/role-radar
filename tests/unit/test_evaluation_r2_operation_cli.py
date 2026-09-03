import json

import pytest

from role_radar.cli.evaluation_r2_operation import validate_confirmation
from role_radar.cli.main import main


def test_r2_operation_is_blocked_without_settings(capsys) -> None:
    assert main(["evaluation", "r2-operation", "execute-c", "--packet-ref", "/secret"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "schema_version": "r2-operation-cli-v1",
        "command": "execute-c",
        "result": "blocked",
        "code": "BLOCK-0",
    }


def test_supplied_confirmation_is_not_ignored(capsys) -> None:
    assert main(["evaluation", "r2-operation", "status", "--confirmation", "0" * 64]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "confirmation_invalid"


def test_confirmation_uses_exact_constant_time_comparison() -> None:
    with pytest.raises(ValueError, match="confirmation_invalid"):
        validate_confirmation(supplied="a" * 64, expected="b" * 64)
