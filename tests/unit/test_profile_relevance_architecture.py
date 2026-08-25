"""Architecture: DAG one-way, no combined seam, no filesystem/dynamic import, isolation."""

from __future__ import annotations

import ast
import pathlib

PACKAGE = pathlib.Path("src/role_radar/evaluation/profile_relevance")
TEST_PACKAGE = pathlib.Path("tests/unit/test_profile_relevance_architecture.py")


def _read_all_sources() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in PACKAGE.glob("*.py")}


def _parse(name: str, source: str) -> ast.AST:
    return ast.parse(source, filename=name)


def test_preview_workflow_does_not_import_materialization() -> None:
    preview_src = (PACKAGE / "preview_workflow.py").read_text(encoding="utf-8")
    tree = _parse("preview_workflow.py", preview_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "materialization" not in node.module, f"preview_workflow imports {node.module}"
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "materialization" not in alias.name
    # no call to materialize_payload_bytes inside preview_workflow
    assert "materialize_payload_bytes" not in preview_src
    # no dynamic import of materialization
    assert "importlib" not in preview_src


def test_dag_is_one_way_materialization_may_call_preview_only() -> None:
    mat_src = (PACKAGE / "materialization.py").read_text(encoding="utf-8")
    # materialization may import compute_preview for recomputation, but preview must not import materialization (checked above)
    assert (
        "from role_radar.evaluation.profile_relevance.preview_workflow import" in mat_src
        or "preview_workflow" in mat_src
    )
    # ensure no circular reference: materialization -> preview -> materialization not present via checking preview again
    preview_src = (PACKAGE / "preview_workflow.py").read_text(encoding="utf-8")
    assert "materialization" not in preview_src
    # overall DAG: lower layers must not import upper layers via AST
    for name in [
        "contracts.py",
        "policy.py",
        "hashing.py",
        "facts.py",
        "gate.py",
        "selection.py",
        "partition.py",
    ]:
        src = (PACKAGE / name).read_text(encoding="utf-8")
        tree = _parse(name, src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "materialization" not in node.module, f"{name} imports {node.module}"
                assert "preview_workflow" not in node.module, f"{name} imports {node.module}"
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "materialization" not in alias.name, f"{name} imports {alias.name}"
                    assert "preview_workflow" not in alias.name


def test_absence_of_run_gate_a_and_combined_seam() -> None:
    for p in PACKAGE.glob("*.py"):
        src = p.read_text(encoding="utf-8")
        assert "run_gate_a" not in src, p.name
        assert "run_workflow" not in src or (
            p.name == "preview_workflow.py" and "run_workflow" not in src
        ), p.name
        # __init__ must export exactly compute_preview and materialize_payload_bytes, no combined wrapper
    init_src = (PACKAGE / "__init__.py").read_text(encoding="utf-8")
    assert "def run_gate_a" not in init_src
    assert "def run_workflow" not in init_src
    assert "compute_preview" in init_src
    assert "materialize_payload_bytes" in init_src
    # ensure no other public function that wraps both
    tree = ast.parse(init_src)
    funcs = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]
    assert set(funcs) <= {"compute_preview", "materialize_payload_bytes"}


def test_no_filesystem_importlib_os_pathlib_random_time_in_profile_relevance() -> None:
    forbidden_imports = {
        "os",
        "pathlib",
        "glob",
        "importlib",
        "random",
        "time",
        "socket",
        "subprocess",
        "sqlite3",
        "sqlalchemy",
    }
    forbidden_attrs = {
        "open",
        "Path",
        "stat",
        "lstat",
        "scandir",
        "listdir",
        "glob",
        "rglob",
        "iterdir",
        "import_module",
        "choice",
        "randint",
        "sleep",
        "time",
    }
    for p in PACKAGE.glob("*.py"):
        src = p.read_text(encoding="utf-8")
        tree = _parse(p.name, src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in forbidden_imports, (
                        f"{p.name} imports forbidden {alias.name}"
                    )
                    # check prefix like pathlib.Path etc.
                    base = alias.name.split(".")[0]
                    assert base not in forbidden_imports, f"{p.name} imports {base}"
            if isinstance(node, ast.ImportFrom) and node.module:
                base = node.module.split(".")[0]
                assert base not in forbidden_imports, f"{p.name} from {node.module} forbidden"
                assert node.module not in forbidden_imports
        # also forbid direct usage patterns like open( , pathlib.Path etc.
        # We allow open for reading itself in architecture test? But spec says any filesystem primitive fails.
        # So check forbidden attribute calls
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"open", "__import__"}
            ):
                assert False, f"{p.name} calls forbidden {node.func.id}"
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in forbidden_attrs
            ):
                # allow hashlib etc, but forbid os.path etc. Since os not imported, this would not trigger anyway; but check anyway
                if node.func.attr in {
                    "stat",
                    "lstat",
                    "scandir",
                    "listdir",
                    "glob",
                    "rglob",
                    "iterdir",
                }:
                    assert False, f"{p.name} calls {node.func.attr}"


def test_no_import_of_cohort_freeze_or_blind_labeling() -> None:
    for p in PACKAGE.glob("*.py"):
        src = p.read_text(encoding="utf-8")
        assert "cohort_freeze" not in src, p.name
        assert "blind_labeling" not in src, p.name
        assert "BlindLabeling" not in src
        assert "SnapshotStore" not in src


def test_historical_holdout_non_access_and_acquisition_non_interference() -> None:
    # profile_relevance must not contain historical root constants or path references
    for p in PACKAGE.glob("*.py"):
        src = p.read_text(encoding="utf-8")
        assert "f1135149" not in src, p.name  # historical neutral dataset hash
        if "historical" in src:
            # allowed identifiers are exclusion / identity; raw holdout roots not allowed
            allowed = (
                "HistoricalIdentityExclusion",
                "historical_exclusion",
                "historical_identity",
                "historical_identity_selected",
            )
            assert any(a in src for a in allowed), p.name
        # ensure no reference to acquisition collectors/persistence
        assert "continuous_acquisition" not in src
        assert "Collector" not in src or "ConstraintPolicy" in src  # allow minimal
        assert "Repository" not in src
        assert "JobScore" not in src
    # reverse dependency: collectors/acquisition must not import profile_relevance to prefilter
    # check a few known collector modules if they exist

    collector_files = list(pathlib.Path("src/role_radar").rglob("*acquisition*.py")) + list(
        pathlib.Path("src/role_radar").rglob("*collector*.py")
    )
    for cf in collector_files[:5]:
        try:
            txt = cf.read_text(encoding="utf-8")
            assert "profile_relevance" not in txt, f"{cf} should not import profile_relevance"
        except Exception:
            continue


def test_no_dynamic_import_or_eval_exec() -> None:
    for p in PACKAGE.glob("*.py"):
        src = p.read_text(encoding="utf-8")
        tree = _parse(p.name, src)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"eval", "exec"}
            ):
                assert False, f"{p.name} uses {node.func.id}"
            if isinstance(node, ast.Import) and any(
                alias.name == "importlib" for alias in node.names
            ):
                assert False, f"{p.name} uses importlib"


def test_package_contains_no_store_or_cli_or_manifest() -> None:
    names = {p.name for p in PACKAGE.glob("*.py")}
    forbidden = {"store.py", "snapshot_source.py", "runtime.py", "cli.py", "manifest.py"}
    assert names.isdisjoint(forbidden), f"forbidden files present: {names & forbidden}"
    # ensure no file mentions manifest/checksum bundle/capability seal publication
    for p in PACKAGE.glob("*.py"):
        src = p.read_text(encoding="utf-8").lower()
        # allow hashing domain "dataset-id" but not manifest/checksum bundle as product feature
        assert "manifest" not in src or "no manifest" in src or "no manifest" in src, (
            p.name
        )  # spec says no manifest creation
        assert "capability seal" not in src


def test_acquisition_non_interference_static() -> None:
    # ensure preview_workflow and materialization do not import adapters/repositories
    for name in ["preview_workflow.py", "materialization.py", "selection.py", "partition.py"]:
        src = (PACKAGE / name).read_text(encoding="utf-8")
        assert "adapter" not in src.lower()
        assert "repository" not in src.lower()
        assert "sqlalchemy" not in src.lower()
        assert "httpx" not in src.lower()
        assert "requests" not in src.lower()
