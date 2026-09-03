from role_radar.cli.main import main


def test_historical_routes_remain_blocked(capsys) -> None:
    assert (
        main(
            [
                "evaluation",
                "f10-1",
                "acquire",
                "--file",
                "x",
                "--plan-sha256",
                "a" * 64,
                "--acknowledgement",
                "x",
            ]
        )
        == 2
    )
    assert "historical_command_non_executable" in capsys.readouterr().out
