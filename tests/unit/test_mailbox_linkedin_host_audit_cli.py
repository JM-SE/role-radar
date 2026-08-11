"""F9.0 CLI safety boundary tests."""

import json

from role_radar.cli.main import main


def test_linkedin_host_audit_ack_fails_before_settings_or_database(capsys) -> None:
    assert main(["mailbox", "linkedin-host-audit", "source-id"]) == 4
    output = json.loads(capsys.readouterr().out)
    assert set(output) == {
        "schema_version",
        "policy_version",
        "validated",
        "selected",
        "fetched",
        "parser",
        "template",
        "total_url_count",
        "distinct_host_count",
        "host_summaries",
        "terminal_code",
    }
    assert output["terminal_code"] == "live_ack_required"
