"""Dependency-light loader for the sealed recovered Gate D fixture."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .recovered_gate_d_authorization import EXPECTED_OPERATION_ID
from .recovered_gate_e_preflight_authorization import (
    EXPECTED_APPROVAL_REFERENCE,
    EXPECTED_CANDIDATE_COMMIT_SHA256,
    EXPECTED_GATE_D_MANIFEST_SHA256,
    RecoveredGateEPreflightAuthorization,
    RecoveredGateEPreflightAuthorizationError,
)
from .recovered_gate_e_preflight_filesystem import (
    RecoveredGateEPreflightFilesystemError,
    pinned_input_roots,
    read_gate_d_artifacts,
)


class RecoveredGateEPreflightLoadError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_PUBLIC_ERROR_CODES = frozenset(
    {
        "gate_e_preflight_action_invalid",
        "gate_e_preflight_anchor_invalid",
        "gate_e_preflight_anchor_mismatch",
        "gate_e_preflight_artifact_invalid",
        "gate_e_preflight_approval_invalid",
        "gate_e_preflight_authorization_invalid",
        "gate_e_preflight_clock_invalid",
        "gate_e_preflight_commit_invalid",
        "gate_e_preflight_expired",
        "gate_e_preflight_filesystem_invalid",
        "gate_e_preflight_invalid",
        "gate_e_preflight_manifest_hash_invalid",
        "gate_e_preflight_root_invalid",
        "gate_e_preflight_roots_overlap",
        "gate_e_preflight_schema_invalid",
        "gate_e_preflight_sources_invalid",
        "gate_e_preflight_window_invalid",
    }
)


@dataclass(frozen=True, slots=True)
class RecoveredGateEProvenance:
    operation_id: str
    source_keys: tuple[str, ...]
    source_count: int
    parent_pool_count: int
    parent_pool_sha256: str
    manifest_sha256: str
    synthetic_mode: str

    def as_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "source_keys": self.source_keys,
            "source_count": self.source_count,
            "parent_pool_count": self.parent_pool_count,
            "parent_pool_sha256": self.parent_pool_sha256,
            "manifest_sha256": self.manifest_sha256,
            "synthetic_mode": self.synthetic_mode,
        }


def _fail(code: str) -> RecoveredGateEPreflightLoadError:
    return RecoveredGateEPreflightLoadError(code)


def _public_error_code(code: object) -> str:
    return (
        code
        if isinstance(code, str) and code in _PUBLIC_ERROR_CODES
        else "gate_e_preflight_invalid"
    )


def _require_exact(value: object, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise _fail("gate_e_preflight_schema_invalid")
    return value


def _authorization_identity(auth: RecoveredGateEPreflightAuthorization) -> dict[str, object]:
    return {
        "action": "offline_recovered_bounded_synthetic_acquisition",
        "approval_reference": "r2-gate-d-20260912-001",
        "budget_units": 10,
        "candidate_commit_sha256": EXPECTED_CANDIDATE_COMMIT_SHA256,
        "expires_at_utc": "2026-09-13T00:00:00Z",
        "historical_root": auth.historical_root,
        "max_journal_entries": 32,
        "max_parent_pool": 6,
        "namespace": "profile-relevant-acquisition",
        "operation_id": auth.operation_id,
        "operator_id": "jmse",
        "output_root": "/home/jmse/r2-evidence/r2-gate-d-20260912-001",
        "partition_seed": "partition-seed",
        "post_c_authorization_sha256": auth.post_c_authorization_sha256,
        "post_c_root": auth.post_c_root,
        "recovery_root": auth.recovery_root,
        "report_sha256": auth.report_sha256,
        "seal_sha256": auth.seal_sha256,
        "selection_seed": "selection-seed",
        "source_keys": list(auth.source_keys),
        "source_plan_sha256": auth.source_plan_sha256,
        "window_start_utc": "2026-09-12T00:00:00Z",
    }


def _load_pinned(
    auth: RecoveredGateEPreflightAuthorization,
    gate_d_fd: int,
) -> RecoveredGateEProvenance:
    artifacts = read_gate_d_artifacts(gate_d_fd, Path(auth.gate_d_root))
    journal, journal_raw = artifacts["journal.json"]
    checkpoint, checkpoint_raw = artifacts["checkpoint.json"]
    evidence, evidence_raw = artifacts["evidence.json"]
    parent_pool, parent_pool_raw = artifacts["parent-pool.json"]
    manifest, manifest_raw = artifacts["manifest.json"]
    if hashlib.sha256(manifest_raw).hexdigest() != EXPECTED_GATE_D_MANIFEST_SHA256:
        raise _fail("gate_e_preflight_manifest_hash_invalid")
    manifest = _require_exact(
        manifest,
        {
            "artifact_sha256",
            "authorization",
            "authorization_sha256",
            "budget_status",
            "budget_units",
            "budget_units_consumed",
            "candidate_commit_sha256",
            "max_journal_entries",
            "max_parent_pool",
            "namespace",
            "operation_id",
            "partition_seed",
            "report_sha256",
            "result",
            "schema_version",
            "selection_seed",
            "source_keys",
            "source_plan_sha256",
        },
    )
    checkpoint = _require_exact(
        checkpoint,
        {
            "budget_status",
            "budget_units",
            "budget_units_consumed",
            "journal_entry_count",
            "namespace",
            "operation_id",
            "parent_pool_count",
            "partition_seed",
            "selection_seed",
        },
    )
    evidence = _require_exact(evidence, {"authorization", "fixture", "source_count"})
    if not isinstance(journal, list) or not isinstance(parent_pool, list):
        raise _fail("gate_e_preflight_schema_invalid")
    expected_identity = _authorization_identity(auth)
    expected_hashes = {
        name: hashlib.sha256(raw).hexdigest()
        for name, (_, raw) in artifacts.items()
        if name != "manifest.json"
    }
    checks = (
        auth.approval_reference == EXPECTED_APPROVAL_REFERENCE,
        manifest["schema_version"] == "f10.1f-gate-d-recovered-synthetic-manifest-v1",
        manifest["operation_id"] == EXPECTED_OPERATION_ID == auth.operation_id,
        manifest["authorization"] == expected_identity,
        manifest["authorization_sha256"]
        == hashlib.sha256(_canonical(expected_identity)).hexdigest(),
        manifest["candidate_commit_sha256"] == EXPECTED_CANDIDATE_COMMIT_SHA256,
        manifest["source_plan_sha256"] == auth.source_plan_sha256,
        manifest["report_sha256"] == auth.report_sha256,
        manifest["source_keys"] == list(auth.source_keys),
        manifest["artifact_sha256"] == expected_hashes,
        manifest["result"] == "sealed",
        manifest["budget_units"] == checkpoint["budget_units"] == 10,
        manifest["budget_units_consumed"] == checkpoint["budget_units_consumed"] == 1,
        manifest["budget_status"] == checkpoint["budget_status"] == "completed",
        manifest["max_parent_pool"] == 6,
        manifest["max_journal_entries"] == 32,
        manifest["namespace"] == checkpoint["namespace"] == "profile-relevant-acquisition",
        manifest["selection_seed"] == checkpoint["selection_seed"] == "selection-seed",
        manifest["partition_seed"] == checkpoint["partition_seed"] == "partition-seed",
        checkpoint["journal_entry_count"] == len(journal) == 1,
        checkpoint["parent_pool_count"] == len(parent_pool) == 0,
        checkpoint["budget_units_consumed"] == len(journal) + len(parent_pool),
        evidence["authorization"] == expected_identity,
        evidence["fixture"] == {"fixture": "bounded"},
        evidence["source_count"] == len(auth.source_keys) == 6,
        journal == [{"event": "synthetic_complete"}],
        parent_pool == [],
        journal_raw == _canonical(journal),
        checkpoint_raw == _canonical(checkpoint),
        evidence_raw == _canonical(evidence),
        parent_pool_raw == _canonical(parent_pool),
    )
    if not all(checks):
        raise _fail("gate_e_preflight_binding_mismatch")
    return RecoveredGateEProvenance(
        operation_id=auth.operation_id,
        source_keys=auth.source_keys,
        source_count=6,
        parent_pool_count=0,
        parent_pool_sha256=hashlib.sha256(parent_pool_raw).hexdigest(),
        manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        synthetic_mode="bounded",
    )


def load_recovered_gate_e_preflight(
    authorization: RecoveredGateEPreflightAuthorization,
    *,
    clock: Callable[[], datetime] | None = None,
) -> RecoveredGateEProvenance:
    if type(authorization) is not RecoveredGateEPreflightAuthorization:
        raise _fail("gate_e_preflight_authorization_invalid")
    trusted_clock = authorization.clock if clock is None else clock
    try:
        authorization.validate_current(trusted_clock())
        with pinned_input_roots(
            tuple(
                Path(root)
                for root in (
                    authorization.historical_root,
                    authorization.recovery_root,
                    authorization.post_c_root,
                    authorization.gate_d_root,
                )
            )
        ) as (_, _, _, gate_d_fd):
            result = _load_pinned(authorization, gate_d_fd)
        authorization.validate_current(trusted_clock())
        return result
    except RecoveredGateEPreflightLoadError as exc:
        raise _fail(_public_error_code(exc.code)) from exc
    except RecoveredGateEPreflightFilesystemError as exc:
        raise _fail("gate_e_preflight_artifact_invalid") from exc
    except (RecoveredGateEPreflightAuthorizationError, TypeError, ValueError, OSError) as exc:
        raise _fail(_public_error_code(getattr(exc, "code", None))) from exc


def _canonical(value: object) -> bytes:
    import json

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


__all__ = [
    "RecoveredGateEPreflightLoadError",
    "RecoveredGateEProvenance",
    "load_recovered_gate_e_preflight",
]
