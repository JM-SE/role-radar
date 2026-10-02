"""Compatibilidad consumer-compat/v1 contra el fixture dual-route (Slice B).

Réplica offline de las reglas `EvaluateDesired` del tooling Go mediante
`broker.compat_check`; la validación autoritativa con `compat desired`
queda diferida a las precondiciones T3 (sin toolchain Go en este entorno).
"""

from __future__ import annotations

import copy
from pathlib import Path

from role_radar.broker.compat_check import (
    COMPATIBLE,
    INCOMPATIBLE,
    check_desired_compat,
    load_json,
)

BASE = Path("src/role_radar/broker/consumer-compat/v1")
EXTRACTION_MANIFEST = BASE / "structured-extraction.json"
DEEP_MANIFEST = BASE / "deep-job-evaluation.json"
DUAL_ROUTE_CONFIG = BASE / "broker-dual-route-config.json"


def _manifests() -> dict[str, dict]:
    return {
        "structured-extraction": load_json(EXTRACTION_MANIFEST),
        "deep-job-evaluation": load_json(DEEP_MANIFEST),
    }


def _codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


def test_both_manifests_are_compatible_with_the_dual_route_fixture() -> None:
    config = load_json(DUAL_ROUTE_CONFIG)
    for name, manifest in _manifests().items():
        assert isinstance(manifest.get("generation"), dict), name
        result = check_desired_compat(manifest, config)
        assert result.status == COMPATIBLE, (name, result.findings)
        assert result.findings == ()


def test_manifests_target_distinct_backends() -> None:
    config = load_json(DUAL_ROUTE_CONFIG)
    capabilities = config["capabilities"]
    instruct = capabilities["structured-extraction"]["backend"]
    thinking = capabilities["deep-job-evaluation"]["backend"]
    assert instruct != thinking
    assert config["backends"][instruct]["type"] == "fake"
    assert config["backends"][thinking]["type"] == "fake"


def _strip_structured_output(config: dict, backend: str) -> None:
    # Fake backends are trusted for structured output by rule, so the
    # negative needs a non-fake backend without the feature.
    config["backends"][backend] = {
        "type": "openai_compatible",
        "base_url": "https://example.invalid",
        "features": [],
    }


def test_crossed_route_onto_backend_without_structured_output_fails() -> None:
    config = load_json(DUAL_ROUTE_CONFIG)
    config["capabilities"]["deep-job-evaluation"]["backend"] = "role-radar-instruct"
    _strip_structured_output(config, "role-radar-instruct")
    manifest = load_json(DEEP_MANIFEST)
    result = check_desired_compat(manifest, config)
    assert result.status == INCOMPATIBLE
    assert "structured_output_unsupported" in _codes(result)


def test_backend_without_structured_output_feature_fails() -> None:
    config = load_json(DUAL_ROUTE_CONFIG)
    _strip_structured_output(config, "role-radar-thinking")
    manifest = load_json(DEEP_MANIFEST)
    result = check_desired_compat(manifest, config)
    assert result.status == INCOMPATIBLE
    assert "structured_output_unsupported" in _codes(result)


def test_capability_missing_from_workload_grant_fails() -> None:
    config = load_json(DUAL_ROUTE_CONFIG)
    config["workloads"]["role-radar"]["allowed_capabilities"] = ["structured-extraction"]
    manifest = load_json(DEEP_MANIFEST)
    result = check_desired_compat(manifest, config)
    assert result.status == INCOMPATIBLE
    assert "capability_not_granted" in _codes(result)


def test_capability_pointing_to_unknown_backend_fails() -> None:
    config = load_json(DUAL_ROUTE_CONFIG)
    config["capabilities"]["structured-extraction"]["backend"] = "role-radar-missing"
    manifest = load_json(EXTRACTION_MANIFEST)
    result = check_desired_compat(manifest, config)
    assert result.status == INCOMPATIBLE
    assert "unknown_backend" in _codes(result)


def test_missing_or_null_generation_fails() -> None:
    config = load_json(DUAL_ROUTE_CONFIG)
    for generation in (None, "missing"):
        manifest = load_json(EXTRACTION_MANIFEST)
        if generation == "missing":
            manifest.pop("generation")
        else:
            manifest["generation"] = generation
        result = check_desired_compat(manifest, config)
        assert result.status == INCOMPATIBLE
        assert "generation_invalid" in _codes(result)


def test_generation_above_allowed_range_fails() -> None:
    manifest = load_json(DEEP_MANIFEST)
    manifest = copy.deepcopy(manifest)
    manifest["generation"]["max_tokens"] = 4096
    config = load_json(DUAL_ROUTE_CONFIG)
    result = check_desired_compat(manifest, config)
    assert result.status == INCOMPATIBLE
    assert "generation_out_of_range" in _codes(result)
