from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).parents[2] / "src" / "role_radar" / "evaluation" / "controlled_acquisition"
FORBIDDEN_IMPORT_PARTS = (
    "role_radar.worker",
    "role_radar.broker",
    "role_radar.services.pipeline",
    "role_radar.services.acquired_job_writer",
    "role_radar.services.extraction",
    "role_radar.services.scoring",
    "role_radar.notifications",
)
FORBIDDEN_NAMES = {
    "Pipeline",
    "WorkerRunner",
    "PipelineCollectionService",
    "AcquiredJobWriter",
    "LLMProvider",
    "JobSearchRun",
    "RunJob",
    "JobScore",
    "JobExtraction",
}


def test_controlled_package_has_no_normal_pipeline_imports() -> None:
    for path in PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported = [node.module or ""]
            else:
                continue
            assert not any(
                any(forbidden in value for forbidden in FORBIDDEN_IMPORT_PARTS)
                for value in imported
            ), f"forbidden import in {path}: {imported}"


def test_controlled_package_has_no_forbidden_pipeline_symbols() -> None:
    for path in PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert not names.intersection(FORBIDDEN_NAMES), path
