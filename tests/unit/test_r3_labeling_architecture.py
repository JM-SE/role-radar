import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
R3 = ROOT / "src" / "role_radar" / "evaluation"


def test_r3_modules_have_no_executable_integration_edges() -> None:
    paths = tuple(R3.glob("r3_labeling*.py"))
    assert paths
    forbidden = (
        "settings",
        "sqlalchemy",
        "database",
        "network",
        "httpx",
        "provider",
        "broker",
        "holdout",
        "historical",
        "f10_1c",
        "freeze_runtime",
        "materializer",
        "gate_f_service",
    )
    for path in paths:
        tree = ast.parse(path.read_text(), filename=str(path))
        imports = [
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        ] + [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        ]
        assert not any(
            any(token in imported.lower() for token in forbidden) for imported in imports
        ), path


def test_r3_has_no_cli_module_or_main_guard() -> None:
    assert not tuple(R3.glob("r3_labeling_cli.py"))
    for path in R3.glob("r3_labeling*.py"):
        source = path.read_text()
        assert 'if __name__ == "__main__"' not in source
        assert "argparse" not in source
