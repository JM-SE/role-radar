"""Static architecture guards for F10.2 offline isolation."""

import ast
from pathlib import Path

PACKAGE = Path("src/role_radar/evaluation/blind_labeling")

DISPLAY_MODULES = (
    "display_policy.py",
    "_display_entities.py",
    "_display_html.py",
    "_display_safety.py",
    "display.py",
)
ALLOWED_IMPORTS = {
    "display_policy.py": {"hashlib", "json", "re", "types", "typing", "collections.abc"},
    "_display_entities.py": {
        "hashlib",
        "html.entities",
        "json",
        "re",
        "collections.abc",
        "types",
        "role_radar.evaluation.blind_labeling.display_policy",
    },
    "_display_html.py": {
        "dataclasses",
        "html.parser",
        "role_radar.evaluation.blind_labeling.display_policy",
    },
    "_display_safety.py": {
        "unicodedata",
        "role_radar.evaluation.blind_labeling.display_policy",
    },
    "display.py": {
        "hashlib",
        "collections.abc",
        "dataclasses",
        "typing",
        "role_radar.evaluation.blind_labeling._display_entities",
        "role_radar.evaluation.blind_labeling._display_html",
        "role_radar.evaluation.blind_labeling._display_safety",
        "role_radar.evaluation.blind_labeling.contracts",
        "role_radar.evaluation.blind_labeling.display_policy",
    },
}


def test_blind_labeling_package_does_not_reference_forbidden_runtime_integrations() -> None:
    forbidden = (
        "V2BundleStore",
        "SnapshotStore",
        "sqlalchemy",
        "requests",
        "httpx",
        "socket",
        "subprocess",
        "Broker",
        "llama",
    )
    for path in PACKAGE.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert not any(token in source for token in forbidden), path


def test_cli_registers_f10_2_without_application_settings_in_dispatch_path() -> None:
    source = Path("src/role_radar/cli/main.py").read_text(encoding="utf-8")
    assert 'evaluation_command == "f10-2"' in source
    dispatch = source[
        source.index('if args.evaluation_command == "f10-2"') : source.index(
            'if args.evaluation_command != "f10-1"'
        )
    ]
    assert "Settings()" not in dispatch


def test_v1_policy_and_contracts_do_not_know_about_display_v2() -> None:
    for name in ("policy.py", "contracts.py"):
        source = (PACKAGE / name).read_text(encoding="utf-8")
        assert "display" not in source.lower()


def test_display_modules_have_pure_import_and_call_boundaries() -> None:
    display_modules = {
        "display_policy.py",
        "_display_entities.py",
        "_display_html.py",
        "_display_safety.py",
        "display.py",
    }
    forbidden_modules = {
        "role_radar.evaluation.blind_labeling.policy",
        "role_radar.evaluation.blind_labeling.session",
        "role_radar.evaluation.blind_labeling.runtime",
        "role_radar.evaluation.blind_labeling.store",
        "role_radar.evaluation.blind_labeling.pilot_source",
    }
    forbidden_calls = {"open", "Path", "socket", "urlopen", "system", "Popen", "run"}
    for name in display_modules:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden_modules, (name, node.module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_calls, (name, node.func.id)


def test_display_modules_use_only_the_approved_import_sets() -> None:
    for name in DISPLAY_MODULES:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"), filename=name)
        imported: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
                assert node.module is not None
                imported.add(node.module)
        assert imported <= ALLOWED_IMPORTS[name], (name, imported - ALLOWED_IMPORTS[name])


def test_display_modules_have_no_io_network_process_or_generic_entity_decoder_calls() -> None:
    forbidden_attributes = {
        "open",
        "Path",
        "socket",
        "urlopen",
        "system",
        "Popen",
        "run",
        "getenv",
        "environ",
        "request",
        "create_connection",
        "unescape",
    }
    for name in DISPLAY_MODULES:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden_attributes, (name, node.func.attr)


def test_rendered_evidence_has_one_factory_constructor_call() -> None:
    tree = ast.parse((PACKAGE / "display.py").read_text(encoding="utf-8"))
    render_function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "render_pilot_item"
    )
    constructors = [
        node
        for node in ast.walk(render_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "RenderedEvidence"
    ]
    assert len(constructors) == 1
    for path in PACKAGE.glob("*.py"):
        if path.name != "display.py":
            assert "RenderedEvidence(" not in path.read_text(encoding="utf-8")


def test_composer_is_selection_only_and_v1_paths_are_not_rewired() -> None:
    source = (PACKAGE / "interaction.py").read_text(encoding="utf-8")
    assert "from role_radar.evaluation.blind_labeling.display import RenderedEvidence" in source
    assert "render_evidence" not in source
    assert "display_policy" not in source
    assert "_display_" not in source
    assert "render_pilot_item" not in source
    assert "def render_item(" in source
