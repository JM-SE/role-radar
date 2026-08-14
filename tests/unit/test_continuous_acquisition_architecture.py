"""Import-boundary checks for the isolated F10.1B bounded context."""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).parents[2] / "src" / "role_radar" / "continuous_acquisition"
FORBIDDEN_IMPORTS = (
    "role_radar.worker",
    "role_radar.broker",
    "role_radar.evaluation",
    "role_radar.services.pipeline",
    "role_radar.services.acquired_job_writer",
    "role_radar.services.extraction",
    "role_radar.services.scoring",
    "role_radar.notifications",
)
FORBIDDEN_NAMES = {
    "Pipeline", "LLMProvider", "WorkerRunner", "AcquiredJobWriter",
    "JobSearchRun", "RunJob", "JobScore", "JobExtraction",
}


def test_continuous_acquisition_has_no_pipeline_llm_or_downstream_imports() -> None:
    for path in PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(item.name for item in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        assert not any(
            any(forbidden in value for forbidden in FORBIDDEN_IMPORTS) for value in imports
        ), path
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert not names.intersection(FORBIDDEN_NAMES), path
