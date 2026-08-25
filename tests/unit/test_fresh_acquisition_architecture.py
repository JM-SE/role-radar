"""AST guardrails for the F10.1F one-way Gate E -> Gate F -> freeze DAG."""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path("src/role_radar/evaluation/fresh_acquisition")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            values.add(node.module)
    return values


def test_gate_e_has_no_materialization_import_or_call() -> None:
    path = PACKAGE / "gate_e.py"
    source = path.read_text(encoding="utf-8")
    imports = _imports(path)

    assert not any("materialization" in value or value.endswith("gate_f") for value in imports)
    tree = ast.parse(source, filename=str(path))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert "materialize_payload_bytes" not in names
    assert "MaterializedPayloads" not in names
    assert "run_gate_f_materialization" not in names


def test_freeze_has_no_gate_or_materialization_dependency() -> None:
    path = PACKAGE / "freeze.py"
    source = path.read_text(encoding="utf-8")
    imports = _imports(path)

    assert not any(
        value.endswith(("gate_e", "gate_f")) or value.endswith("profile_relevance.materialization")
        for value in imports
    )
    tree = ast.parse(source, filename=str(path))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert "materialize_payload_bytes" not in names
    assert "run_gate_e_preview" not in names
    assert "run_gate_f_materialization" not in names


def test_fresh_package_does_not_import_historical_or_normal_persistence_paths() -> None:
    forbidden_imports = (
        "role_radar.evaluation.cohort_freeze",
        "role_radar.evaluation.blind_labeling",
        "role_radar.services.job_service",
        "role_radar.repositories.observation_writer",
    )
    for path in PACKAGE.glob("*.py"):
        imports = _imports(path)
        assert not any(
            any(value.startswith(prefix) for prefix in forbidden_imports) for value in imports
        ), path


def test_only_gate_f_calls_profile_relevance_materializer() -> None:
    callers: set[str] = set()
    for path in PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(
            isinstance(node, ast.Name)
            and node.id == "materialize_payload_bytes"
            and isinstance(getattr(node, "ctx", None), ast.Load)
            for node in ast.walk(tree)
        ):
            callers.add(path.name)
    assert callers == {"gate_f.py"}
