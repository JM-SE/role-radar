"""Isolation guards for the current product feedback loop (Slice A)."""

from __future__ import annotations

import ast
from pathlib import Path

MODULES = (
    "src/role_radar/cli/feedback.py",
    "src/role_radar/services/feedback_service.py",
    "src/role_radar/services/feedback_refinement.py",
    "src/role_radar/discovery/relevance.py",
    "src/role_radar/repositories/feedback.py",
)

FORBIDDEN_TOKENS = (
    "evaluation_f10_2",
    "SOURCE_ROOT",
    "OUTPUT_ROOT",
    "pilot_source",
    "materialization",
    "holdout",
    "cohort_freeze",
    "sealed",
    "broker",
    "openai",
    "anthropic",
    "create_llm_provider",
    "create_deep_llm_provider",
)

ALLOWED_BLIND_SUBMODULES = frozenset(
    {"contracts", "display", "interaction", "policy", "validation"}
)


def _source(relative: str) -> str:
    return Path(relative).read_text(encoding="utf-8")


def test_feedback_modules_avoid_historical_and_model_paths() -> None:
    for relative in MODULES:
        text = _source(relative)
        for token in FORBIDDEN_TOKENS:
            assert token not in text, f"{relative} must not reference {token}"


def test_feedback_modules_use_only_the_display_seam() -> None:
    for relative in MODULES:
        tree = ast.parse(_source(relative))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                if "blind_labeling" not in name:
                    continue
                submodule = name.rsplit(".", 1)[-1]
                assert submodule in ALLOWED_BLIND_SUBMODULES, (
                    f"{relative} imports unexpected blind_labeling submodule {submodule}"
                )


def test_feedback_service_uses_display_v2() -> None:
    text = _source("src/role_radar/services/feedback_service.py")
    assert "render_pilot_item" in text
    assert "compose_rendered_item" in text


def test_relevance_is_dependency_free() -> None:
    tree = ast.parse(_source("src/role_radar/discovery/relevance.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in {"sqlalchemy", "role_radar"}, (
                "relevance must stay pure"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in {"sqlalchemy", "role_radar"}, (
                    "relevance must stay pure"
                )
