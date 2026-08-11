"""F9.1 CLI safety boundary tests."""

import json

from role_radar.cli.main import main


def test_head_resolution_ack_fails_before_settings_or_database(capsys) -> None:
    assert main(["mailbox", "linkedin-head-resolution", "source-id"]) == 4
    output = json.loads(capsys.readouterr().out)

    assert output == {
        "schema_version": "linkedin-head-resolution-v1",
        "policy_version": "linkedin-head-resolution-v1",
        "mode": "report_only",
        "source_state": "disabled",
        "proposal_state": "authenticated_linkedin",
        "result": "review",
        "request_count": 0,
        "redirect_count": 0,
        "final_ats": None,
        "terminal_code": "live_ack_required",
    }
