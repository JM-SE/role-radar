import ast
import builtins
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from role_radar.evaluation.r3_labeling_authorization import (
    R3Authorization,
    R3AuthorizationError,
    R3BlockCode,
    R3Operation,
)
from role_radar.evaluation.r3_labeling_service import R3LabelingService

from .test_r3_labeling import _fixture

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
        "requests",
        "urllib",
        "socket",
        "scheduler",
        "systemd",
        "terminal",
        "session",
        "writer",
        "f10_1c",
        "f10_2",
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


def test_r3_modules_have_no_forbidden_calls() -> None:
    forbidden_calls = {
        "Settings",
        "create_engine",
        "Session",
        "Broker",
        "LLM",
        "urlopen",
        "request",
        "freeze",
        "materialize",
        "write",
        "save",
        "commit",
        "systemd",
    }
    for path in R3.glob("r3_labeling*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        calls |= {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert not calls & forbidden_calls, (path, calls & forbidden_calls)


def test_r3_has_no_cli_module_or_main_guard() -> None:
    assert not tuple(R3.glob("r3_labeling_cli.py"))
    for path in R3.glob("r3_labeling*.py"):
        source = path.read_text()
        assert 'if __name__ == "__main__"' not in source
        assert "argparse" not in source


def test_r3_has_no_executable_cli_path_and_legacy_f10_2_remains_separate() -> None:
    cli = ROOT / "src" / "role_radar" / "cli"
    assert not any("r3" in path.read_text().lower() for path in cli.glob("*.py"))

    legacy = (cli / "evaluation_f10_2.py").read_text()
    assert "BlindLabelingRuntime" in legacy
    assert "LabelingStore" in legacy
    assert "StdTerminalIO" in legacy
    assert "r3" not in legacy.lower()

    main = (cli / "main.py").read_text()
    assert 'add_parser("f10-2")' in main
    assert "evaluation_f10_2" in main


@pytest.mark.parametrize(
    "authorization",
    [
        (lambda binding: R3Authorization(R3Operation.REAL, binding, synthetic_fixture=True)),
        lambda binding: R3Authorization(R3Operation.SYNTHETIC_OFFLINE, binding),
    ],
)
def test_rejected_authorization_never_constructs_or_loads_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authorization: object,
) -> None:
    binding, publication = _fixture()
    calls: list[str] = []

    class Forbidden:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            calls.append("forbidden")
            raise AssertionError("rejected R3 input reached an effectful boundary")

    monkeypatch.setattr("role_radar.evaluation.r3_labeling_service.LabelingStore", Forbidden)
    monkeypatch.setattr("role_radar.evaluation.r3_labeling_service.BlindLabelingRuntime", Forbidden)
    monkeypatch.setattr("role_radar.evaluation.r3_labeling_service.adapt_pilot_view", Forbidden)

    forbidden_imports = (
        "role_radar.config",
        "sqlalchemy",
        "httpx",
        "requests",
        "role_radar.broker",
        "role_radar.llm",
        "role_radar.evaluation.profile_relevant_acquisition.freeze_runtime",
        "role_radar.evaluation.profile_relevant_acquisition.gate_f_service",
        "role_radar.evaluation.blind_labeling.session",
        "role_radar.scheduler",
    )
    original_import = builtins.__import__

    def is_forbidden(name: str) -> bool:
        for forbidden in forbidden_imports:
            if name == forbidden or name.startswith(f"{forbidden}."):
                return True
        return False

    def deny_forbidden_import(name: str, *args: object, **kwargs: object) -> object:
        if is_forbidden(name):
            calls.append(f"import:{name}")
            raise AssertionError(f"rejected R3 input reached forbidden import: {name}")
        return original_import(name, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(builtins, "__import__", deny_forbidden_import)

    authorization = authorization(binding)  # type: ignore[operator]

    with pytest.raises(R3AuthorizationError) as error:
        R3LabelingService(authorization, publication, root=tmp_path)  # type: ignore[arg-type]
    assert error.value.code == R3BlockCode.AUTHORIZATION_REQUIRED.value
    assert calls == []
    assert not list(tmp_path.iterdir())


def test_expired_and_unknown_trust_inputs_fail_before_any_effect(tmp_path: Path) -> None:
    binding, publication = _fixture()
    now = datetime(2026, 1, 1, tzinfo=UTC)

    class ExplodingPublication:
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError("rejected trust input loaded publication")

    for authorization, expected_code, supplied_publication in (
        (
            R3Authorization(
                R3Operation.SYNTHETIC_OFFLINE,
                binding,
                expires_at=now - timedelta(seconds=1),
                synthetic_fixture=True,
            ),
            R3BlockCode.EXPIRED.value,
            ExplodingPublication(),
        ),
        (
            R3Authorization(
                R3Operation.SYNTHETIC_OFFLINE,
                replace(binding, dataset_id="e" * 64),
                synthetic_fixture=True,
            ),
            R3BlockCode.BINDING_INVALID.value,
            replace(publication, binding=replace(binding, dataset_id="e" * 64)),
        ),
    ):
        with pytest.raises(R3AuthorizationError) as error:
            R3LabelingService(
                authorization,
                supplied_publication,  # type: ignore[arg-type]
                root=tmp_path,
                clock=lambda: now.isoformat().replace("+00:00", "Z"),
                runtime_factory=lambda **_kwargs: (_ for _ in ()).throw(
                    AssertionError("rejected trust input constructed runtime")
                ),
            )
        assert error.value.code == expected_code
        assert not list(tmp_path.iterdir())
