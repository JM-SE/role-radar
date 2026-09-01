"""AST guardrails for the F10.1F one-way Gate E -> Gate F -> freeze DAG."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

PACKAGE = Path("src/role_radar/evaluation/profile_relevant_acquisition")
EXPECTED_MODULES = {
    "contracts.py",
    "policy.py",
    "canonical.py",
    "input_adapters.py",
    "preflight.py",
    "preflight_runtime.py",
    "challenge_loader.py",
    "provenance_loader.py",
    "decision_status.py",
    "provenance.py",
    "historical_exclusion.py",
    "discovery_runtime.py",
    "gate_c_runtime.py",
    "post_c_preregistration_runtime.py",
    "source_plan.py",
    "acquisition_preregistration.py",
    "journal.py",
    "journaled_transport.py",
    "acquisition_runtime.py",
    "gate_d_runtime.py",
    "parent_pool.py",
    "gate_e_preview.py",
    "gate_e_runtime.py",
    "gate_f_materialization.py",
    "gate_f_runtime.py",
    "manifest.py",
    "store.py",
    "capability_seal.py",
    "freeze_runtime.py",
    "gate_b_preflight.py",
    "gate_c_authorization.py",
    "gate_c_service.py",
    "output.py",
    "__init__.py",
}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            values.add(node.module)
    return values


def test_profile_relevant_package_has_exact_spec_modules() -> None:
    assert {path.name for path in PACKAGE.glob("*.py")} == EXPECTED_MODULES


def test_product_has_no_all_gate_coordinator_or_dispatcher() -> None:
    assert not (PACKAGE / "coordinator.py").exists()
    for path in PACKAGE.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "run_authoritative_f10_1f" not in source
        assert "CoordinatorSteps" not in source


def test_gate_e_has_no_materialization_import_or_call() -> None:
    path = PACKAGE / "gate_e_preview.py"
    source = path.read_text(encoding="utf-8")
    imports = _imports(path)

    assert not any(
        "materialization" in value or value.endswith(("gate_f", "gate_f_materialization"))
        for value in imports
    )
    tree = ast.parse(source, filename=str(path))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert "materialize_payload_bytes" not in names
    assert "MaterializedPayloads" not in names
    assert "run_gate_f_materialization" not in names


def test_gate_e_cannot_reach_gate_f_or_materialization_transitively() -> None:
    path = PACKAGE / "gate_e_preview.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    imports = _imports(path)
    assert not any("gate_f_materialization" in value for value in imports)
    assert not names.intersection(
        {
            "materialize_payload_bytes",
            "MaterializedPayloads",
            "CanonicalPayload",
            "ApprovedPreview",
            "MaterializationContext",
            "run_gate_f_materialization",
        }
    )


def test_f10_1f_has_no_historical_root_or_holdout_runtime_access() -> None:
    forbidden_imports = (
        "role_radar.evaluation.cohort_freeze",
        "role_radar.evaluation.blind_labeling",
        "role_radar.repositories",
        "role_radar.db",
    )
    for path in PACKAGE.glob("*.py"):
        imports = _imports(path)
        assert not any(
            any(value.startswith(prefix) for prefix in forbidden_imports) for value in imports
        ), path

    # LIVE_HOLDOUT is an aggregate preregistration target, not a holdout read.
    for path in PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        assert not any(
            isinstance(node, ast.Name) and node.id in {"open_holdout", "read_holdout"}
            for node in ast.walk(tree)
        ), path


def test_f10_1f_cli_has_no_generic_acknowledgement_switch() -> None:
    source = Path("src/role_radar/cli/evaluation_f10_1f.py").read_text(encoding="utf-8")
    assert 'add_argument("--ack")' not in source


def test_freeze_has_no_gate_or_materialization_dependency() -> None:
    path = PACKAGE / "freeze_runtime.py"
    source = path.read_text(encoding="utf-8")
    imports = _imports(path)

    assert not any(
        value.endswith(("gate_e", "gate_f", "gate_e_preview", "gate_f_materialization"))
        or value.endswith("profile_relevance.materialization")
        for value in imports
    )
    tree = ast.parse(source, filename=str(path))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert "materialize_payload_bytes" not in names
    assert "run_gate_e_preview" not in names
    assert "run_gate_f_materialization" not in names


def test_profile_relevant_package_does_not_import_historical_or_normal_persistence_paths() -> None:
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
    assert callers == {"gate_f_materialization.py"}


def test_journal_transport_is_extracted_to_transport_module() -> None:
    journal = ast.parse((PACKAGE / "journal.py").read_text(encoding="utf-8"))
    transport = ast.parse((PACKAGE / "journaled_transport.py").read_text(encoding="utf-8"))
    journal_classes = {node.name for node in journal.body if isinstance(node, ast.ClassDef)}
    transport_classes = {node.name for node in transport.body if isinstance(node, ast.ClassDef)}
    assert "JournaledAsyncTransport" not in journal_classes
    assert "JournaledAsyncTransport" in transport_classes


def test_execution_capable_seams_have_typed_authorization_and_no_boolean_escape() -> None:
    guarded = {
        "acquisition_runtime.py": (
            "build_collector_context",
            "build_ephemeral_tasks",
            "run_broad_acquisition_scaffold",
            "run_gate_d_broad_acquisition",
        ),
        "freeze_runtime.py": ("run_freeze_transaction", "verify_frozen_publication"),
        "gate_f_materialization.py": ("run_gate_f_materialization",),
    }
    for filename, names in guarded.items():
        module = __import__(
            f"role_radar.evaluation.profile_relevant_acquisition.{filename.removesuffix('.py')}",
            fromlist=list(names),
        )
        source = (PACKAGE / filename).read_text(encoding="utf-8")
        assert "offline_harness" not in source
        for name in names:
            parameters = inspect.signature(getattr(module, name)).parameters
            assert "test_only_adapter" in parameters
            assert "approval" in parameters
            assert "approval_verifier" in parameters
            assert "require_execution_boundary" in source


def test_f10_1f_has_no_stale_date_or_default_execution_values() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in PACKAGE.glob("*.py"))
    assert "2026-08-25" not in source
    assert "20260825" not in source
    assert "CollectionRunBudget(maximum=100)" not in source
    assert "Path.cwd()" not in source


def test_f10_1f_source_plan_is_not_the_legacy_defaulted_model() -> None:
    source = (PACKAGE / "source_plan.py").read_text(encoding="utf-8")
    assert "controlled_acquisition.source_plan" not in source
    assert "from role_radar.evaluation.controlled_acquisition.source_plan" not in source
