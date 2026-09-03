import ast
from pathlib import Path

from role_radar.cli.main import main


def test_r2_operational_surface_has_no_live_or_legacy_edges() -> None:
    root = Path(__file__).parents[2]
    files = (
        *(root / "src/role_radar/evaluation").glob("r2_operational*.py"),
        root / "src/role_radar/cli/evaluation_r2_operation.py",
    )
    forbidden = {
        "Settings",
        "DB",
        "LiveAcquisition",
        "F10.1C",
        "historical",
        "holdout",
        "R3",
        "scheduler",
        "network",
        "requests",
        "httpx",
        "sqlalchemy",
        "run_all",
        "coordinator",
        "write_artifact",
        "open",
        "urlopen",
    }
    for path in files:
        tree = ast.parse(path.read_text())
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        assert not (names | imports) & forbidden, path


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
