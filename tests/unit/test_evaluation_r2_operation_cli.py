import json

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
