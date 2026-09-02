"""Criterion 7: Gate F authority stays a bounded materialize-then-freeze seam."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from role_radar.cli import evaluation_f10_1f

ROOT = Path(__file__).parents[2]
GATE_F_ROOT = ROOT / "src/role_radar/evaluation/profile_relevant_acquisition"
GATE_F_MODULES = (
    "gate_f_authorization.py",
    "gate_f_input_adapter.py",
    "gate_f_service.py",
)

# These are architecture edges, rather than a ban on words in comments or
# documentation.  AST names/imports keep the guard stable as prose evolves.
FORBIDDEN_IMPORT_PARTS = (
    "successor",
    "r3",
    "provider",
    "network",
    "httpx",
    "requests",
    "urllib",
    "socket",
    "f10_1c",
    "cohort_freeze",
    "coordinator",
    "dispatcher",
    "sqlalchemy",
    "role_radar.db",
    "role_radar.repositories",
    "scheduler",
    "systemd",
)
FORBIDDEN_REFERENCE_PARTS = (
    "successor",
    "r3",
    "provider",
    "network",
    "f10_1c",
    "coordinator",
    "dispatcher",
    "all_gate",
    "store",
    "repository",
    "session",
    "systemd",
    "scheduler",
    "capabilitywriter",
    "write",
    "publish",
    "persist",
    "register_source",
    "register_job",
)


def _tree_and_imports(path: Path) -> tuple[ast.AST, set[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return tree, imports


def _references(tree: ast.AST) -> set[str]:
    return {
        name.lower()
        for node in ast.walk(tree)
        for name in (
            [node.id]
            if isinstance(node, ast.Name)
            else [node.attr]
            if isinstance(node, ast.Attribute)
            else []
        )
    }


def test_gate_f_authority_has_no_forbidden_architecture_edges() -> None:
    for filename in GATE_F_MODULES:
        path = GATE_F_ROOT / filename
        tree, imports = _tree_and_imports(path)
        assert not any(
            any(part in imported.lower() for part in FORBIDDEN_IMPORT_PARTS) for imported in imports
        ), path

        references = _references(tree)
        assert not any(
            any(part in reference for part in FORBIDDEN_REFERENCE_PARTS) for reference in references
        ), path

        calls = {
            node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute))
        }
        assert not any(
            any(part in call.lower() for part in FORBIDDEN_REFERENCE_PARTS) for call in calls
        ), path


def test_gate_f_authority_preserves_only_typed_materialization_and_freeze_seams() -> None:
    tree, _imports = _tree_and_imports(GATE_F_ROOT / "gate_f_service.py")
    references = _references(tree)
    assert {"run_gate_f_materialization", "run_freeze_transaction"} <= references
    assert not references.intersection({"run_gate_e_preview", "run_gate_e_offline_preview"})


def test_f10_1f_cli_freeze_remains_block_0() -> None:
    assert evaluation_f10_1f.run(SimpleNamespace(f10_1f_command="freeze")) == 2
