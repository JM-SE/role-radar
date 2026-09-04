"""Architecture pins for real Gate C discovery.

- The offline Gate C path still requires an offline provider.
- The real discovery input schema carries no board/config/plan field.
- Real discovery modules never import persistence, registration, successor
  gates, scheduler, credentials-at-rest, or live defaults.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import role_radar.evaluation.profile_relevant_acquisition.gate_c_service as service
from role_radar.evaluation.profile_relevant_acquisition import (
    real_discovery_capability as capability_module,
)
from role_radar.evaluation.profile_relevant_acquisition import (
    real_gate_c_discovery as discovery_module,
)

FORBIDDEN_FRAGMENTS = (
    "from role_radar.db",
    "import role_radar.db",
    "from role_radar.repositories",
    "acquisition_runtime",
    "post_c_preregistration",
    "gate_d_service",
    "gate_e_service",
    "gate_f_service",
    "run_all",
    "coordinator",
    "scheduler",
    "systemd",
    "LiveAcquisition",
    "register_source",
    "holdout",
    "label",
    "r3",
    "r4",
)

REAL_MODULES = (capability_module, discovery_module)


def _source(module: object) -> str:
    path = Path(str(module.__file__))
    return path.read_text(encoding="utf-8").lower()


def test_real_modules_have_no_forbidden_dependencies() -> None:
    for module in REAL_MODULES:
        text = _source(module)
        for fragment in FORBIDDEN_FRAGMENTS:
            assert fragment not in text, (module.__name__, fragment)


def test_real_discovery_signature_carries_no_boards() -> None:
    parameters = inspect.signature(discovery_module.run_real_gate_c_discovery).parameters
    lowered = {name.lower() for name in parameters}
    for forbidden in (
        "boards",
        "board_identities",
        "board_tokens",
        "source_configs",
        "source_plan",
        "plan_input",
        "known_boards",
    ):
        assert forbidden not in lowered
    assert "credential" not in lowered and "secret" not in lowered
    assert "api_key" not in lowered


def test_service_runner_takes_no_board_argument() -> None:
    parameters = inspect.signature(service.execute_gate_c_real_discovery).parameters
    lowered = {name.lower() for name in parameters}
    assert "boards" not in lowered
    assert "source_configs" not in lowered
    assert "source_plan" not in lowered


def test_offline_path_still_requires_offline_provider() -> None:
    parameters = inspect.signature(service.execute_gate_c_report_only).parameters
    assert "provider" in parameters
    source = Path(str(service.__file__)).read_text(encoding="utf-8")
    assert "offline_provider_required" in source


def test_no_successor_import_in_real_discovery() -> None:
    text = _source(discovery_module)
    assert "post_c" not in text
    assert "gate_d" not in text
    assert "gate_e" not in text
    assert "gate_f" not in text
