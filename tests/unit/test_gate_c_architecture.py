"""Gate C remains an isolated offline report-only seam."""

import ast
import pathlib

GATE_C_MODULES = (
    "gate_c_authorization.py",
    "gate_c_service.py",
    "discovery_runtime.py",
)
FORBIDDEN_REFERENCE_PARTS = (
    "gate_d",
    "gate_e",
    "gate_f",
    "post_c",
    "materialization",
    "freeze_runtime",
    "sqlalchemy",
    "SourceRepository",
    "JobRepository",
    "register_source",
    "persist_source",
    "persist_job",
)


def test_gate_c_modules_have_no_successor_or_product_writer_dependencies() -> None:
    root = pathlib.Path(__file__).parents[2] / pathlib.Path(
        "src/role_radar/evaluation/profile_relevant_acquisition"
    )
    for filename in GATE_C_MODULES:
        path = root / filename
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imports = [
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        ] + [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        ]
        assert not any(
            any(part.lower() in imported.lower() for part in FORBIDDEN_REFERENCE_PARTS)
            for imported in imports
        )
        assert not any(part.lower() in source.lower() for part in FORBIDDEN_REFERENCE_PARTS)
