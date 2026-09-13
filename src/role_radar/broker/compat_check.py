"""Verificación offline de compatibilidad consumer-compat/v1 (réplica Python).

Replica las reglas documentadas de `EvaluateDesired` del tooling Go de
LLM Broker (`compat desired`), que no es ejecutable en este entorno (sin
toolchain Go y binario precompilado sin subcomando `compat`). La validación
autoritativa con el tooling Go queda como gap offline explícito, cubierto
por las T3 preconditions del spec de Slice B.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

MAX_COMBINED_MESSAGE_BYTES: Final = 256 * 1024

COMPATIBLE: Final = "compatible"
INCOMPATIBLE: Final = "incompatible"


@dataclass(frozen=True, slots=True)
class CompatFinding:
    code: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CompatResult:
    status: str
    findings: tuple[CompatFinding, ...]


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def check_desired_compat(manifest: dict[str, Any], config: dict[str, Any]) -> CompatResult:
    """Aplica las reglas documentadas de `EvaluateDesired` sin efectos externos."""

    findings: list[CompatFinding] = []
    workloads = config.get("workloads", {})
    capabilities = config.get("capabilities", {})
    backends = config.get("backends", {})

    workload_name = manifest.get("workload")
    capability_name = manifest.get("capability")
    workload = workloads.get(workload_name) if isinstance(workloads, dict) else None
    if not isinstance(workload, dict):
        return CompatResult(INCOMPATIBLE, (CompatFinding("unknown_workload"),))
    allowed = workload.get("allowed_capabilities")
    if not isinstance(allowed, list) or capability_name not in allowed:
        findings.append(CompatFinding("capability_not_granted"))

    capability = capabilities.get(capability_name) if isinstance(capabilities, dict) else None
    backend_name = capability.get("backend") if isinstance(capability, dict) else None
    backend = backends.get(backend_name) if isinstance(backends, dict) else None
    if not isinstance(backend, dict):
        findings.append(CompatFinding("unknown_backend"))
        backend = {}
    backend_features = backend.get("features", [])
    if not isinstance(backend_features, list):
        backend_features = []

    max_request = _number(manifest.get("max_request_content_bytes"))
    if max_request is None or max_request > MAX_COMBINED_MESSAGE_BYTES:
        findings.append(CompatFinding("request_content_too_large"))

    max_output_bytes = _number(workload.get("max_output_bytes"))
    required_min_output = _number(manifest.get("required_min_output_bytes"))
    if max_output_bytes is None or max_output_bytes <= 0:
        findings.append(CompatFinding("explicit_output_bytes_required"))
    elif (
        required_min_output is not None
        and required_min_output > 0
        and max_output_bytes < required_min_output
    ):
        findings.append(CompatFinding("output_bytes_insufficient"))

    workload_timeout = _number(workload.get("workload_timeout_seconds"))
    min_timeout = _number(manifest.get("min_workload_timeout_seconds"))
    if workload_timeout is not None and min_timeout is not None and workload_timeout < min_timeout:
        findings.append(CompatFinding("workload_timeout_insufficient"))

    max_attempts = _number(workload.get("max_attempts"))
    acceptable = _number(manifest.get("max_acceptable_attempts"))
    if max_attempts is not None and acceptable is not None and max_attempts > acceptable:
        findings.append(CompatFinding("max_attempts_exceeded"))

    deadline = _number(manifest.get("consumer_overall_deadline_seconds"))
    if workload_timeout is not None and deadline is not None and deadline <= workload_timeout:
        findings.append(CompatFinding("consumer_deadline_not_greater"))

    generation = manifest.get("generation")
    if generation is not None:
        if not isinstance(generation, dict):
            findings.append(CompatFinding("generation_invalid"))
        else:
            allowed_generation = workload.get("allowed_generation", {})
            if not isinstance(allowed_generation, dict):
                allowed_generation = {}
            max_output_tokens = _number(workload.get("max_output_tokens"))
            for field, value in generation.items():
                numeric = _number(value)
                bounds = allowed_generation.get(field)
                if not isinstance(bounds, dict):
                    findings.append(CompatFinding("generation_field_denied", str(field)))
                    continue
                if numeric is not None:
                    low = _number(bounds.get("min"))
                    high = _number(bounds.get("max"))
                    if (low is not None and numeric < low) or (high is not None and numeric > high):
                        findings.append(CompatFinding("generation_out_of_range", str(field)))
            requested_tokens = (
                _number(generation.get("max_tokens")) if isinstance(generation, dict) else None
            )
            if (
                requested_tokens is not None
                and max_output_tokens is not None
                and requested_tokens > max_output_tokens
            ):
                findings.append(CompatFinding("generation_tokens_exceeded"))

    required_features = workload.get("required_features", [])
    if isinstance(required_features, list):
        for feature in required_features:
            if feature not in backend_features:
                findings.append(CompatFinding("backend_feature_missing", str(feature)))

    response = manifest.get("response", {})
    if (
        isinstance(response, dict)
        and response.get("kind") == "json_schema"
        and backend.get("type") != "fake"
        and "structured_output" not in backend_features
    ):
        findings.append(CompatFinding("structured_output_unsupported"))

    if findings:
        return CompatResult(INCOMPATIBLE, tuple(findings))
    return CompatResult(COMPATIBLE, ())


__all__ = [
    "COMPATIBLE",
    "INCOMPATIBLE",
    "MAX_COMBINED_MESSAGE_BYTES",
    "CompatFinding",
    "CompatResult",
    "check_desired_compat",
    "load_json",
]
