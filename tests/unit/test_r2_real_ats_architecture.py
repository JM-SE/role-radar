import ast
import asyncio
from pathlib import Path

import httpx
import pytest

from role_radar.evaluation.r2_real_ats_transport import (
    RealATSTransportError,
    make_test_real_ats_transport,
)
from tests.integration.test_r2_greenhouse_lever_gate_d_bridge import _operational_fixture


def test_real_ats_boundary_has_no_forbidden_effectful_edges(tmp_path) -> None:
    project = Path(__file__).parents[2]
    evaluation = project / "src/role_radar/evaluation"
    files = (
        *evaluation.glob("r2_real_ats_*.py"),
        evaluation / "r2_greenhouse_lever_factory.py",
        evaluation / "r2_operational_artifacts.py",
        evaluation / "r2_operational_gate_d_adapter.py",
        evaluation / "profile_relevant_acquisition" / "acquisition_runtime.py",
        evaluation / "profile_relevant_acquisition" / "post_c_preregistration_contracts.py",
    )
    forbidden = {
        "credential",
        "credentials",
        "jobicy",
        "successor",
        "holdout",
        "r3",
        "database",
        "db",
        "sqlalchemy",
        "scheduler",
        "systemd",
        "liveacquisition",
    }

    def normalized(value: str) -> str:
        return value.removeprefix("_").lower()

    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        identifiers = {
            normalized(node.id) for node in ast.walk(tree) if isinstance(node, ast.Name)
        } | {normalized(node.attr) for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        imports = {
            part.lower()
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
            for part in node.module.split(".")
        } | {
            part.lower()
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            for part in alias.name.split(".")
        }
        calls = {
            normalized(call.func.id)
            for call in ast.walk(tree)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        } | {
            normalized(call.func.attr)
            for call in ast.walk(tree)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
        }
        assert (
            not (imports | calls | {item for item in identifiers if item in forbidden}) & forbidden
        ), path


@pytest.mark.parametrize(
    ("method", "url", "headers"),
    (
        ("POST", "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true", {}),
        ("GET", "http://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true", {}),
        ("GET", "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=false", {}),
        (
            "GET",
            "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true",
            {"Authorization": "Bearer secret"},
        ),
    ),
)
def test_fake_ats_boundary_rejects_escape_before_response(
    tmp_path, method: str, url: str, headers: dict[str, str]
) -> None:
    packet, resolved, _factory, _approval = _operational_fixture(tmp_path)
    capability = resolved.operational_capability
    assert capability is not None
    transport = make_test_real_ats_transport({})
    transport._seal_hosts(
        capability.claims.allowed_hosts,
        capability.claims.source_configs,
        budget=capability.claims.budget,
        timeout_seconds=capability.claims.timeout_seconds,
        window_start=capability.claims.window_start,
        window_cutoff=capability.claims.window_cutoff,
        expires_at=capability.claims.expires_at,
        current_time=packet.window_start,
    )
    request = httpx.Request(
        method,
        url,
        headers=headers,
        extensions={"timeout": {"connect": 10, "read": 30, "write": 10, "pool": 10}},
    )
    with pytest.raises(RealATSTransportError):
        asyncio.run(transport.handle_async_request(request))
    assert transport.calls == 1
